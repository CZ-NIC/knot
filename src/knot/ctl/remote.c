/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <assert.h>
#include <urcu.h>

#include "dnssec/random.h"
#include "knot/common/log.h"
#include "knot/conf/conf.h"
#include "knot/ctl/commands.h"
#include "knot/ctl/remote.h"
#include "knot/server/tcp-handler.h"
#include "libknot/libknot.h"
#include "contrib/net.h"
#include "contrib/sockaddr.h"
#include "contrib/string.h"
#include "contrib/openbsd/strlcpy.h"
#include "contrib/wire.h"

#define KNOT_CTL_REALM "knot."
#define KNOT_CTL_REALM_EXT ("." KNOT_CTL_REALM)
#define CMDARGS_BUFLEN_LOG 256

/*! \brief Initialize cmdargs_t structure. */
static int cmdargs_init(remote_cmdargs_t *args)
{
	assert(args);

	char *response = malloc(CMDARGS_ALLOC_BLOCK);
	if (!response) {
		return KNOT_ENOMEM;
	}

	memset(args, 0, sizeof(*args));
	args->response = response;
	args->response_max = CMDARGS_ALLOC_BLOCK;

	return KNOT_EOK;
}

/*! \brief Deinitialize cmdargs_t structure. */
static void cmdargs_deinit(remote_cmdargs_t *args)
{
	assert(args);

	free(args->response);
	memset(args, 0, sizeof(*args));
}

int remote_bind(const char *path)
{
	if (path == NULL) {
		return KNOT_EINVAL;
	}

	log_info("remote control, binding to '%s'", path);

	/* Prepare socket address. */
	struct sockaddr_storage addr;
	int ret = sockaddr_set(&addr, AF_UNIX, path, 0);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Create new socket. */
	int sock = net_bound_socket(SOCK_STREAM, &addr, 0);
	if (sock < 0) {
		log_error("remote control, failed to bind to '%s' (%s)",
		          path, knot_strerror(sock));
		return sock;
	}

	/* Start listening. */
	if (listen(sock, TCP_BACKLOG_SIZE) != 0) {
		log_error("remote control, failed to listen on '%s'", path);
		close(sock);
		return knot_map_errno();
	}

	return sock;
}

void remote_unbind(int sock)
{
	if (sock < 0) {
		return;
	}

	/* Remove the control socket file.  */
	struct sockaddr_storage addr;
	socklen_t addr_len = sizeof(addr);
	if (getsockname(sock, (struct sockaddr *)&addr, &addr_len) == 0) {
		char addr_str[SOCKADDR_STRLEN] = { 0 };
		if (sockaddr_tostr(addr_str, sizeof(addr_str), &addr) > 0) {
			(void)unlink(addr_str);
		}
	}

	/* Close the socket.  */
	(void)close(sock);
}

int remote_poll(int sock, const sigset_t *sigmask)
{
	/* Wait for events. */
	fd_set rfds;
	FD_ZERO(&rfds);
	if (sock > -1) {
		FD_SET(sock, &rfds);
	} else {
		sock = -1; /* Make sure n == r + 1 == 0 */
	}

	return pselect(sock + 1, &rfds, NULL, NULL, NULL, sigmask);
}

int remote_recv(int sock, uint8_t *buf, size_t *buflen)
{
	int c = tcp_accept(sock);
	if (c < 0) {
		return c;
	}

	/* Receive data. */
	int n = net_dns_tcp_recv(c, buf, *buflen, NULL);
	*buflen = n;
	if (n <= 0) {
		close(c);
		return KNOT_ECONNREFUSED;
	}

	return c;
}

int remote_parse(knot_pkt_t *pkt)
{
	return knot_pkt_parse(pkt, 0);
}

static int remote_send_chunk(int c, knot_pkt_t *query, const char *d, uint16_t len,
                             int index)
{
	knot_pkt_t *resp = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, &query->mm);
	if (!resp) {
		return KNOT_ENOMEM;
	}

	/* Initialize response. */
	int ret = knot_pkt_init_response(resp, query);
	if (ret != KNOT_EOK) {
		goto failed;
	}

	/* Write to NS section. */
	ret = knot_pkt_begin(resp, KNOT_AUTHORITY);
	assert(ret == KNOT_EOK);

	/* Create TXT RR with result. */
	knot_rrset_t rr;
	ret = remote_build_rr(&rr, "result.", KNOT_RRTYPE_TXT);
	if (ret != KNOT_EOK) {
		goto failed;
	}

	ret = remote_create_txt(&rr, d, len, index);
	assert(ret == KNOT_EOK);

	ret = knot_pkt_put(resp, 0, &rr, KNOT_PF_FREE);
	if (ret != KNOT_EOK) {
		knot_rrset_clear(&rr, NULL);
		goto failed;
	}

	rcu_read_lock();
	conf_val_t *val = &conf()->cache.srv_tcp_reply_timeout;
	struct timeval timeout = { conf_int(val), 0 };
	rcu_read_unlock();

	ret = net_dns_tcp_send(c, resp->wire, resp->size, &timeout);

failed:

	/* Free packet. */
	knot_pkt_free(&resp);

	return ret;
}

static void log_command(const char *cmd, const remote_cmdargs_t *args)
{
	char params[CMDARGS_BUFLEN_LOG] = { 0 };
	size_t rest = CMDARGS_BUFLEN_LOG;
	size_t pos = 0;

	for (unsigned i = 0; i < args->argc; i++) {
		const knot_rrset_t *rr = &args->arg[i];
		if (rr->type != KNOT_RRTYPE_NS) {
			continue;
		}

		uint16_t rr_count = rr->rrs.rr_count;
		for (uint16_t j = 0; j < rr_count; j++) {
			const knot_dname_t *dn = knot_ns_name(&rr->rrs, j);
			char *name = knot_dname_to_str_alloc(dn);

			int ret = snprintf(params + pos, rest, " %s", name);
			free(name);

			if (ret <= 0 || ret >= rest) {
				break;
			}
			pos += ret;
			rest -= ret;
		}
	}

	log_info("remote control, received command '%s%s'", cmd, params);
}

int remote_answer(int sock, server_t *s, knot_pkt_t *pkt)
{
	if (sock < 0 || s == NULL || pkt == NULL) {
		return KNOT_EINVAL;
	}

	/* Prerequisites:
	 * QCLASS: CH
	 * QNAME: <CMD>.KNOT_CTL_REALM.
	 */
	const knot_dname_t *qname = knot_pkt_qname(pkt);
	if (knot_pkt_qclass(pkt) != KNOT_CLASS_CH) {
		return KNOT_EMALF;
	}

	knot_dname_t *realm = knot_dname_from_str_alloc(KNOT_CTL_REALM);
	if (!knot_dname_is_sub(qname, realm) != 0) {
		knot_dname_free(&realm, NULL);
		return KNOT_EMALF;
	}
	knot_dname_free(&realm, NULL);

	/* Command:
	 * QNAME: leftmost label of QNAME
	 */
	size_t cmd_len = *qname;
	char *cmd = strndup((char*)qname + 1, cmd_len);

	/* Data:
	 * NS: TSIG
	 * AR: data
	 */
	remote_cmdargs_t args = { 0 };
	int ret = cmdargs_init(&args);
	if (ret != KNOT_EOK) {
		free(cmd);
		return ret;
	}

	const knot_pktsection_t *authority = knot_pkt_section(pkt, KNOT_AUTHORITY);
	args.arg = knot_pkt_rr(authority, 0);
	args.argc = authority->count;
	args.rc = KNOT_RCODE_NOERROR;

	log_command(cmd, &args);

	const remote_cmd_t *c = remote_cmd_tbl;
	while (c->name != NULL) {
		if (strcmp(cmd, c->name) == 0) {
			ret = c->f(s, &args);
			break;
		}
		++c;
	}

	/* Prepare response. */
	if (args.response_size == 0) {
		args.response_size = strlen(knot_strerror(ret));
		strlcpy(args.response, knot_strerror(ret), args.response_max);
	}

	int index = 0;
	unsigned p = 0;
	size_t chunk = 16384;
	for (; p + chunk < args.response_size; p += chunk) {
		remote_send_chunk(sock, pkt, args.response + p, chunk, index);
		index++;
	}

	unsigned r = args.response_size - p;
	if (r > 0) {
		remote_send_chunk(sock, pkt, args.response + p, r, index);
	}

	cmdargs_deinit(&args);
	free(cmd);
	return ret;
}

int remote_process(server_t *server, int sock, uint8_t *buf, size_t buflen)
{
	knot_pkt_t *pkt =  knot_pkt_new(buf, buflen, NULL);
	if (pkt == NULL) {
		return KNOT_ENOMEM;
	}

	/* Accept incoming connection and read packet. */
	int client = remote_recv(sock, pkt->wire, &buflen);
	if (client < 0) {
		knot_pkt_free(&pkt);
		return client;
	} else {
		pkt->size = buflen;
	}

	/* Parse packet and answer if OK. */
	int ret = remote_parse(pkt);
	if (ret == KNOT_EOK) {
		ret = remote_answer(client, server, pkt);
	}

	knot_pkt_free(&pkt);
	close(client);
	return ret;
}

knot_pkt_t* remote_query(const char *query)
{
	if (!query) {
		return NULL;
	}

	knot_pkt_t *pkt = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, NULL);
	if (!pkt) {
		return NULL;
	}

	knot_wire_set_id(pkt->wire, dnssec_random_uint16_t());

	/* Question section. */
	char *qname = strcdup(query, KNOT_CTL_REALM_EXT);
	knot_dname_t *dname = knot_dname_from_str_alloc(qname);
	free(qname);
	if (!dname) {
		knot_pkt_free(&pkt);
		return NULL;
	}

	/* Cannot return != KNOT_EOK, but still. */
	if (knot_pkt_put_question(pkt, dname, KNOT_CLASS_CH, KNOT_RRTYPE_ANY) != KNOT_EOK) {
		knot_pkt_free(&pkt);
		knot_dname_free(&dname, NULL);
		return NULL;
	}

	knot_dname_free(&dname, NULL);
	return pkt;
}

int remote_build_rr(knot_rrset_t *rr, const char *owner, uint16_t type)
{
	if (!rr || !owner) {
		return KNOT_EINVAL;
	}

	/* Assert K is FQDN. */
	knot_dname_t *name = knot_dname_from_str_alloc(owner);
	if (name == NULL) {
		return KNOT_ENOMEM;
	}

	/* Init RRSet. */
	knot_rrset_init(rr, name, type, KNOT_CLASS_CH);

	return KNOT_EOK;
}

int remote_create_txt(knot_rrset_t *rr, const char *str, size_t str_len,
                      uint16_t index)
{
	if (!rr || !str) {
		return KNOT_EINVAL;
	}

	/* Maximal chunk size. */
	const size_t K = 255;
	/* Number of chunks (ceiling operation). */
	const size_t chunks = (str_len + K - 1)/ K;
	/* Total raw chunk length. */
	const size_t raw_len = sizeof(uint8_t) + sizeof(index) + str_len + chunks;

	uint8_t raw[raw_len];
	memset(raw, 0, raw_len);

	uint8_t *out = raw;
	const char *in = str;

	/* Write index chunk. */
	*out++ = sizeof(index);
	wire_write_u16(out, index);
	out += sizeof(index);

	if (chunks > 0) {
		/* Write leading full chunks. */
		for (size_t i = 0; i < chunks - 1; i++) {
			/* Maximal chunk length. */
			*out++ = (uint8_t)K;
			/* Data chunk. */
			memcpy(out, in, K);
			out += K;
			in += K;
		}

		/* Write last chunk. */
		const size_t rest = str + str_len - in;
		assert(rest <= K);
		/* Last chunk length. */
		*out++ = (uint8_t)rest;
		/* Last data chunk. */
		memcpy(out, in, rest);
	}

	return knot_rrset_add_rdata(rr, raw, raw_len, 0, NULL);
}

int remote_create_ns(knot_rrset_t *rr, const char *name)
{
	if (!rr || !name) {
		return KNOT_EINVAL;
	}

	/* Create dname. */
	knot_dname_t *dn = knot_dname_from_str_alloc(name);
	if (!dn) {
		return KNOT_ERROR;
	}

	/* Build RDATA. */
	int dn_size = knot_dname_size(dn);
	int result = knot_rrset_add_rdata(rr, dn, dn_size, 0, NULL);
	knot_dname_free(&dn, NULL);

	return result;
}

int remote_print_txt(const knot_rrset_t *rr, uint16_t pos)
{
	if (!rr) {
		return KNOT_EINVAL;
	}

	size_t count = knot_txt_count(&rr->rrs, pos);
	for (size_t i = 0; i < count; i++) {
		const uint8_t *rdata = knot_txt_data(&rr->rrs, pos, i);
		printf("%.*s", (int)rdata[0], rdata + 1);
	}

	return KNOT_EOK;
}

uint8_t *remote_get_txt(const knot_rrset_t *rr, uint16_t pos, size_t *out_len)
{
	if (!rr) {
		return NULL;
	}

	// The buffer will be slightly bigger (including string lengths).
	size_t buf_len = knot_rdata_rdlen(knot_rdataset_at(&rr->rrs, pos));
	uint8_t *buf = malloc(buf_len);
	if (buf == NULL) {
		return NULL;
	}

	size_t len = 0;

	size_t count = knot_txt_count(&rr->rrs, pos);
	for (size_t i = 1; i < count; i++) {
		const uint8_t *rdata = knot_txt_data(&rr->rrs, pos, i);
		memcpy(buf + len, rdata + 1, rdata[0]);
		len += rdata[0];
	}

	// There is always at least one free byte.
	buf[len] = '\0';

	if (out_len != NULL) {
		*out_len = len;
	}

	return buf;
}
