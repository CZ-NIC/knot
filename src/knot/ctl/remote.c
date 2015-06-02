/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <sys/stat.h>
#include "knot/ctl/remote.h"
#include "common/log.h"
#include "common/mem.h"
#include "common-knot/fdset.h"
#include "knot/knot.h"
#include "knot/conf/conf.h"
#include "knot/server/net.h"
#include "knot/server/tcp-handler.h"
#include "libknot/packet/wire.h"
#include "libknot/descriptor.h"
#include "common-knot/strlcpy.h"
#include "libknot/tsig-op.h"
#include "libknot/rrtype/rdname.h"
#include "libknot/rrtype/soa.h"
#include "libknot/dnssec/random.h"
#include "libknot/packet/wire.h"
#include "knot/zone/timers.h"
#include "knot/dnssec/zone-sign.h"
#include "knot/dnssec/zone-nsec.h"

#define KNOT_CTL_REALM "knot."
#define KNOT_CTL_REALM_EXT ("." KNOT_CTL_REALM)
#define CMDARGS_ALLOC_BLOCK KNOT_WIRE_MAX_PKTSIZE
#define CMDARGS_BUFLEN_LOG 256
#define KNOT_CTL_SOCKET_UMASK 0007

/*! \brief Remote command structure. */
typedef struct remote_cmdargs_t {
	const knot_rrset_t *arg;
	unsigned argc;
	knot_rcode_t rc;
	char *response;
	size_t response_size;
	size_t response_max;
} remote_cmdargs_t;

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

/*! \brief Resize output buffer if the new data won't fit. */
static int cmdargs_assure_avail(remote_cmdargs_t *args, size_t add_size)
{
	assert(args);
	assert(add_size <= CMDARGS_ALLOC_BLOCK);

	if (args->response_size + add_size > args->response_max) {
		size_t new_max = args->response_max + CMDARGS_ALLOC_BLOCK;
		char *new_response = realloc(args->response, new_max);
		if (!new_response) {
			return KNOT_ENOMEM;
		}

		args->response = new_response;
		args->response_max = new_max;
	}

	return KNOT_EOK;
}

/*! \brief Deinitialize cmdargs_t structure. */
static void cmdargs_deinit(remote_cmdargs_t *args)
{
	assert(args);

	free(args->response);
	memset(args, 0, sizeof(*args));
}

/*! \brief Callback prototype for remote commands. */
typedef int (*remote_cmdf_t)(server_t*, remote_cmdargs_t*);

/*! \brief Callback prototype for per-zone operations. */
typedef int (remote_zonef_t)(zone_t *);

/*! \brief Remote command table item. */
typedef struct remote_cmd_t {
	const char *name;
	remote_cmdf_t f;
} remote_cmd_t;

/* Forward decls. */
static int remote_c_stop(server_t *s, remote_cmdargs_t* a);
static int remote_c_reload(server_t *s, remote_cmdargs_t* a);
static int remote_c_refresh(server_t *s, remote_cmdargs_t* a);
static int remote_c_retransfer(server_t *s, remote_cmdargs_t* a);
static int remote_c_status(server_t *s, remote_cmdargs_t* a);
static int remote_c_zonestatus(server_t *s, remote_cmdargs_t* a);
static int remote_c_flush(server_t *s, remote_cmdargs_t* a);
static int remote_c_signzone(server_t *s, remote_cmdargs_t* a);

/*! \brief Table of remote commands. */
struct remote_cmd_t remote_cmd_tbl[] = {
	{ "stop",      &remote_c_stop },
	{ "reload",    &remote_c_reload },
	{ "refresh",   &remote_c_refresh },
	{ "retransfer",&remote_c_retransfer },
	{ "status",    &remote_c_status },
	{ "zonestatus",&remote_c_zonestatus },
	{ "flush",     &remote_c_flush },
	{ "signzone",  &remote_c_signzone },
	{ NULL,        NULL }
};

/* Private APIs. */

/*! \brief Apply callback to all zones specified by RDATA of CNAME RRs. */
static int remote_rdata_apply(server_t *s, remote_cmdargs_t* a, remote_zonef_t *cb)
{
	if (!s || !a || !cb) {
		return KNOT_EINVAL;
	}

	zone_t *zone = NULL;
	int ret = KNOT_EOK;

	for (unsigned i = 0; i < a->argc; ++i) {
		/* Process all zones in data section. */
		const knot_rrset_t *rr = &a->arg[i];
		if (rr->type != KNOT_RRTYPE_NS) {
			continue;
		}

		uint16_t rr_count = rr->rrs.rr_count;
		for (uint16_t i = 0; i < rr_count; i++) {
			const knot_dname_t *dn = knot_ns_name(&rr->rrs, i);
			rcu_read_lock();
			zone = knot_zonedb_find(s->zone_db, dn);
			if (cb(zone) != KNOT_EOK) {
				a->rc = KNOT_RCODE_SERVFAIL;
			}
			rcu_read_unlock();
		}
	}

	return ret;
}

/*! \brief Zone refresh callback. */
static int remote_zone_refresh(zone_t *zone)
{
	if (!zone_is_slave(zone)) {
		return KNOT_EINVAL;
	}

	zone_events_schedule(zone, ZONE_EVENT_REFRESH, ZONE_EVENT_NOW);
	return KNOT_EOK;
}

/*! \brief Zone refresh callback. */
static int remote_zone_retransfer(zone_t *zone)
{
	if (!zone_is_slave(zone)) {
		return KNOT_EINVAL;
	}

	zone->flags |= ZONE_FORCE_AXFR;
	zone_events_schedule(zone, ZONE_EVENT_XFER, ZONE_EVENT_NOW);
	return KNOT_EOK;
}

/*! \brief Zone flush callback. */
static int remote_zone_flush(zone_t *zone)
{
	if (zone == NULL) {
		return KNOT_EINVAL;
	}

	zone_events_schedule(zone, ZONE_EVENT_FLUSH, ZONE_EVENT_NOW);
	return KNOT_EOK;
}

/*! \brief Sign zone callback. */
static int remote_zone_sign(zone_t *zone)
{
	if (zone == NULL || !zone->conf->dnssec_enable) {
		return KNOT_EINVAL;
	}


	zone->flags |= ZONE_FORCE_RESIGN;
	zone_events_schedule(zone, ZONE_EVENT_DNSSEC, ZONE_EVENT_NOW);
	return KNOT_EOK;
}

/*!
 * \brief Remote command 'stop' handler.
 *
 * QNAME: stop
 * DATA: NULL
 */
static int remote_c_stop(server_t *s, remote_cmdargs_t* a)
{
	UNUSED(a);
	UNUSED(s);
	return KNOT_CTL_STOP;
}

/*!
 * \brief Remote command 'reload' handler.
 *
 * QNAME: reload
 * DATA: NULL
 */
static int remote_c_reload(server_t *s, remote_cmdargs_t* a)
{
	UNUSED(a);
	return server_reload(s, conf()->filename);
}

/*!
 * \brief Remote command 'status' handler.
 *
 * QNAME: status
 * DATA: NONE
 */
static int remote_c_status(server_t *s, remote_cmdargs_t* a)
{
	UNUSED(s);
	UNUSED(a);
	dbg_server("remote: %s\n", __func__);
	return KNOT_EOK;
}

static char *dnssec_info(const zone_t *zone, char *buf, size_t buf_size)
{
	assert(zone);
	assert(buf);

	time_t refresh_at = zone_events_get_time(zone, ZONE_EVENT_DNSSEC);
	struct tm time_gm = { 0 };

	gmtime_r(&refresh_at, &time_gm);
	size_t written = strftime(buf, buf_size, KNOT_LOG_TIME_FORMAT, &time_gm);
	if (written == 0) {
		return NULL;
	}

	return buf;
}

/*!
 * \brief Remote command 'zonestatus' handler.
 *
 * QNAME: zonestatus
 * DATA: NONE
 */
static int remote_c_zonestatus(server_t *s, remote_cmdargs_t* a)
{
	dbg_server("remote: %s\n", __func__);

	int ret = KNOT_EOK;
	rcu_read_lock();

	knot_zonedb_iter_t it;
	knot_zonedb_iter_begin(s->zone_db, &it);
	while(!knot_zonedb_iter_finished(&it)) {
		const zone_t *zone = knot_zonedb_iter_val(&it);

		/* Fetch latest serial. */
		const knot_rdataset_t *soa_rrs = NULL;
		uint32_t serial = 0;
		if (zone->contents) {
			soa_rrs = node_rdataset(zone->contents->apex,
			                        KNOT_RRTYPE_SOA);
			assert(soa_rrs != NULL);
			serial = knot_soa_serial(soa_rrs);
		}

		/* Fetch next zone event. */
		char when[128] = { '\0' };
		zone_event_type_t next_type = ZONE_EVENT_INVALID;
		const char *next_name = "";
		time_t next_time = zone_events_get_next(zone, &next_type);
		if (next_type != ZONE_EVENT_INVALID) {
			next_name = zone_events_get_name(next_type);
			next_time = next_time - time(NULL);
			if (next_time < 0) {
				memcpy(when, "pending", strlen("pending"));
			} else if (snprintf(when, sizeof(when),
			                    "in %lldh%lldm%llds",
			                    (long long)(next_time / 3600),
			                    (long long)(next_time % 3600) / 60,
			                    (long long)(next_time % 60)) < 0) {
				ret = KNOT_ESPACE;
				break;
			}
		} else {
			memcpy(when, "idle", strlen("idle"));
		}

		/* Prepare zone info. */
		char buf[512] = { '\0' };
		char dnssec_buf[128] = { '\0' };
		int n = snprintf(buf, sizeof(buf),
		                 "%s\ttype=%s | serial=%u | %s %s | %s %s\n",
		                 zone->conf->name,
		                 zone_is_slave(zone) ? "slave" : "master",
		                 serial,
		                 next_name,
		                 when,
		                 zone->conf->dnssec_enable ? "automatic DNSSEC, resigning at:" : "DNSSEC signing disabled",
		                 zone->conf->dnssec_enable ? dnssec_info(zone, dnssec_buf, sizeof(dnssec_buf)) : "");
		if (n < 0 || n >= sizeof(buf)) {
			ret = KNOT_ESPACE;
			break;
		}

		ret = cmdargs_assure_avail(a, n);
		if (ret != KNOT_EOK) {
			break;
		}

		memcpy(a->response + a->response_size, buf, n);
		a->response_size += n;

		knot_zonedb_iter_next(&it);
	}
	rcu_read_unlock();

	return ret;
}

/*!
 * \brief Remote command 'refresh' handler.
 *
 * QNAME: refresh
 * DATA: NONE for all zones
 *       CNAME RRs with zones in RDATA
 */
static int remote_c_refresh(server_t *s, remote_cmdargs_t* a)
{
	dbg_server("remote: %s\n", __func__);
	if (a->argc == 0) {
		/* Refresh all. */
		dbg_server_verb("remote: refreshing all zones\n");
		knot_zonedb_foreach(s->zone_db, remote_zone_refresh);
	} else {
		/* Refresh specific zones. */
		remote_rdata_apply(s, a, &remote_zone_refresh);
	}

	return KNOT_CTL_ACCEPTED;
}

/*!
 * \brief Remote command 'retransfer' handler.
 *
 * QNAME: retransfer
 * DATA: CNAME RRs with zones in RDATA
 */
static int remote_c_retransfer(server_t *s, remote_cmdargs_t* a)
{
	dbg_server("remote: %s\n", __func__);
	if (a->argc == 0) {
		/* Refresh all. */
		return KNOT_ENOTSUP;
	} else {
		/* Refresh specific zones. */
		remote_rdata_apply(s, a, &remote_zone_retransfer);
	}

	return KNOT_CTL_ACCEPTED;

}

/*!
 * \brief Remote command 'flush' handler.
 *
 * QNAME: flush
 * DATA: NONE for all zones
 *       CNAME RRs with zones in RDATA
 */
static int remote_c_flush(server_t *s, remote_cmdargs_t* a)
{
	dbg_server("remote: %s\n", __func__);
	if (a->argc == 0) {
		/* Flush all. */
		dbg_server_verb("remote: flushing all zones\n");
		rcu_read_lock();
		knot_zonedb_iter_t it;
		knot_zonedb_iter_begin(s->zone_db, &it);
		while(!knot_zonedb_iter_finished(&it)) {
			remote_zone_flush(knot_zonedb_iter_val(&it));
			knot_zonedb_iter_next(&it);
		}
		rcu_read_unlock();
	} else {
		/* Flush specific zones. */
		remote_rdata_apply(s, a, &remote_zone_flush);
	}

	return KNOT_CTL_ACCEPTED;
}

/*!
 * \brief Remote command 'signzone' handler.
 *
 */
static int remote_c_signzone(server_t *server, remote_cmdargs_t* arguments)
{
	dbg_server("remote: %s\n", __func__);

	if (arguments->argc == 0) {
		/* Resign all. */
		return KNOT_ENOTSUP;
	} else {
		/* Resign specific zones. */
		remote_rdata_apply(server, arguments, remote_zone_sign);
	}

	return KNOT_CTL_ACCEPTED;
}

/*!
 * \brief Prepare and send error response.
 * \param c Client fd.
 * \param buf Query buffer.
 * \param buflen Query size.
 * \return number of bytes sent
 */
static int remote_senderr(int c, uint8_t *qbuf, size_t buflen)
{
	knot_wire_set_qr(qbuf);
	knot_wire_set_rcode(qbuf, KNOT_RCODE_REFUSED);
	struct timeval timeout = { conf()->max_conn_reply, 0 };
	return tcp_send_msg(c, qbuf, buflen, &timeout);
}

/* Public APIs. */

int remote_bind(conf_iface_t *desc)
{
	if (desc == NULL) {
		return KNOT_EINVAL;
	}

	char addr_str[SOCKADDR_STRLEN] = {0};
	sockaddr_tostr(&desc->addr, addr_str, sizeof(addr_str));
	log_info("binding remote control interface to '%s'", addr_str);

	/* Create new socket. */
	mode_t old_umask = umask(KNOT_CTL_SOCKET_UMASK);
	int sock = net_bound_socket(SOCK_STREAM, &desc->addr);
	umask(old_umask);
	if (sock < 0) {
		return sock;
	}

	/* Start listening. */
	int ret = listen(sock, TCP_BACKLOG_SIZE);
	if (ret < 0) {
		log_error("failed to bind to '%s'", addr_str);
		close(sock);
		return ret;
	}

	return sock;
}

int remote_unbind(conf_iface_t *desc, int sock)
{
	if (desc == NULL || sock < 0) {
		return KNOT_EINVAL;
	}

	/* Remove control socket file.  */
	if (desc->addr.ss_family == AF_UNIX) {
		char addr_str[SOCKADDR_STRLEN] = {0};
		sockaddr_tostr(&desc->addr, addr_str, sizeof(addr_str));
		unlink(addr_str);
	}

	return close(sock);
}

int remote_poll(int sock)
{
	/* Wait for events. */
	fd_set rfds;
	FD_ZERO(&rfds);
	if (sock > -1) {
		FD_SET(sock, &rfds);
	} else {
		sock = -1; /* Make sure n == r + 1 == 0 */
	}

	return fdset_pselect(sock + 1, &rfds, NULL, NULL, NULL, NULL);
}

int remote_recv(int sock, struct sockaddr_storage *addr, uint8_t *buf,
                size_t *buflen)
{
	int c = tcp_accept(sock);
	if (c < 0) {
		dbg_server("remote: failed to accept incoming connection\n");
		return c;
	}

	socklen_t addrlen = sizeof(*addr);
	if (getpeername(c, (struct sockaddr *)addr, &addrlen) != 0) {
		dbg_server("remote: failed to get remote address\n");
		close(c);
		return KNOT_ECONNREFUSED;
	}

	/* Receive data. */
	int n = tcp_recv_msg(c, buf, *buflen, NULL);
	*buflen = n;
	if (n <= 0) {
		dbg_server("remote: failed to receive data\n");
		close(c);
		return KNOT_ECONNREFUSED;
	}

	return c;
}

int remote_parse(knot_pkt_t* pkt)
{
	return knot_pkt_parse(pkt, 0);
}

static int remote_send_chunk(int c, knot_pkt_t *query, const char* d, uint16_t len)
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

	ret = remote_create_txt(&rr, d, len);
	assert(ret == KNOT_EOK);

	ret = knot_pkt_put(resp, 0, &rr, KNOT_PF_FREE);
	if (ret != KNOT_EOK) {
		knot_rrset_clear(&rr, NULL);
		goto failed;
	}

	struct timeval timeout = { conf()->max_conn_reply, 0 };
	ret = tcp_send_msg(c, resp->wire, resp->size, &timeout);

failed:

	/* Free packet. */
	knot_pkt_free(&resp);

	return ret;
}

static void log_command(const char *cmd, const remote_cmdargs_t* args)
{
	char params[CMDARGS_BUFLEN_LOG] = { 0 };
	size_t rest = CMDARGS_BUFLEN_LOG;

	for (unsigned i = 0; i < args->argc; i++) {
		const knot_rrset_t *rr = &args->arg[i];
		if (rr->type != KNOT_RRTYPE_NS) {
			continue;
		}

		uint16_t rr_count = rr->rrs.rr_count;
		for (uint16_t j = 0; j < rr_count; j++) {
			const knot_dname_t *dn = knot_ns_name(&rr->rrs, j);
			char *name = knot_dname_to_str_alloc(dn);

			int ret = snprintf(params, rest, " %s", name);
			free(name);
			if (ret <= 0 || ret >= rest) {
				break;
			}
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
		dbg_server("remote: qclass != CH\n");
		return KNOT_EMALF;
	}

	knot_dname_t *realm = knot_dname_from_str_alloc(KNOT_CTL_REALM);
	if (!knot_dname_is_sub(qname, realm) != 0) {
		dbg_server("remote: qname != *%s\n", KNOT_CTL_REALM_EXT);
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
		return ret;
	}

	const knot_pktsection_t *authority = knot_pkt_section(pkt, KNOT_AUTHORITY);
	args.arg = authority->rr;
	args.argc = authority->count;
	args.rc = KNOT_RCODE_NOERROR;

	log_command(cmd, &args);

	remote_cmd_t *c = remote_cmd_tbl;
	while (c->name != NULL) {
		if (strcmp(cmd, c->name) == 0) {
			ret = c->f(s, &args);
			break;
		}
		++c;
	}

	/* Prepare response. */
	if (ret != KNOT_EOK || args.response_size == 0) {
		args.response_size = strlen(knot_strerror(ret));
		strlcpy(args.response, knot_strerror(ret), args.response_max);
	}

	unsigned p = 0;
	size_t chunk = 16384;
	for (; p + chunk < args.response_size; p += chunk) {
		remote_send_chunk(sock, pkt, args.response + p, chunk);
	}

	unsigned r = args.response_size - p;
	if (r > 0) {
		remote_send_chunk(sock, pkt, args.response + p, r);
	}

	cmdargs_deinit(&args);
	free(cmd);
	return ret;
}

static int zones_verify_tsig_query(const knot_pkt_t *query,
                                   const knot_tsig_key_t *key,
                                   uint16_t *rcode, uint16_t *tsig_rcode,
                                   uint64_t *tsig_prev_time_signed)
{
	assert(query != NULL);
	assert(key != NULL);
	assert(rcode != NULL);
	assert(tsig_rcode != NULL);

	if (query->tsig_rr == NULL) {
		log_info("TSIG, key required, query REFUSED");
		*rcode = KNOT_RCODE_REFUSED;
		return KNOT_TSIG_EBADKEY;
	}

	/*
	 * 1) Check if we support the requested algorithm.
	 */
	knot_tsig_algorithm_t alg = tsig_rdata_alg(query->tsig_rr);
	if (knot_tsig_digest_length(alg) == 0) {
		log_info("TSIG, unsupported algorithm, query NOTAUTH");
		/*! \todo [TSIG] It is unclear from RFC if I
		 *               should treat is as a bad key
		 *               or some other error.
		 */
		*rcode = KNOT_RCODE_NOTAUTH;
		*tsig_rcode = KNOT_TSIG_ERR_BADKEY;
		return KNOT_TSIG_EBADKEY;
	}

	const knot_dname_t *kname = query->tsig_rr->owner;
	assert(kname != NULL);

	/*
	 * 2) Find the particular key used by the TSIG.
	 *    Check not only name, but also the algorithm.
	 */
	if (!(key && kname && knot_dname_cmp(key->name, kname) == 0 &&
	      key->algorithm == alg)) {
		*rcode = KNOT_RCODE_NOTAUTH;
		*tsig_rcode = KNOT_TSIG_ERR_BADKEY;
		return KNOT_TSIG_EBADKEY;
	}

	/*
	 * 3) Validate the query with TSIG.
	 */
	/* Prepare variables for TSIG */
	/*! \todo These need to be saved to the response somehow. */
	//size_t tsig_size = tsig_wire_maxsize(key);
	size_t digest_max_size = knot_tsig_digest_length(key->algorithm);
	//size_t digest_size = 0;
	//uint64_t tsig_prev_time_signed = 0;
	//uint8_t *digest = (uint8_t *)malloc(digest_max_size);
	//memset(digest, 0 , digest_max_size);

	//const uint8_t* mac = tsig_rdata_mac(tsig_rr);
	size_t mac_len = tsig_rdata_mac_length(query->tsig_rr);

	int ret = KNOT_EOK;

	if (mac_len > digest_max_size) {
		*rcode = KNOT_RCODE_FORMERR;
		log_info("TSIG, MAC length %zu exceeds maximum size %zu",
		         mac_len, digest_max_size);
		return KNOT_EMALF;
	} else {
		//memcpy(digest, mac, mac_len);
		//digest_size = mac_len;

		/* Check query TSIG. */
		ret = knot_tsig_server_check(query->tsig_rr,
		                             query->wire,
		                             query->size, key);
		switch(ret) {
		case KNOT_EOK:
			*rcode = KNOT_RCODE_NOERROR;
			break;
		case KNOT_TSIG_EBADKEY:
			*tsig_rcode = KNOT_TSIG_ERR_BADKEY;
			*rcode = KNOT_RCODE_NOTAUTH;
			break;
		case KNOT_TSIG_EBADSIG:
			*tsig_rcode = KNOT_TSIG_ERR_BADSIG;
			*rcode = KNOT_RCODE_NOTAUTH;
			break;
		case KNOT_TSIG_EBADTIME:
			*tsig_rcode = KNOT_TSIG_ERR_BADTIME;
			// store the time signed from the query
			*tsig_prev_time_signed = tsig_rdata_time_signed(query->tsig_rr);
			*rcode = KNOT_RCODE_NOTAUTH;
			break;
		case KNOT_EMALF:
			*rcode = KNOT_RCODE_FORMERR;
			break;
		default:
			*rcode = KNOT_RCODE_SERVFAIL;
		}
	}

	return ret;
}

int remote_process(server_t *s, conf_iface_t *ctl_if, int sock,
                   uint8_t* buf, size_t buflen)
{
	knot_pkt_t *pkt =  knot_pkt_new(buf, buflen, NULL);
	if (pkt == NULL) {
		return KNOT_ENOMEM;
	}

	/* Initialize remote party address. */
	struct sockaddr_storage ss;
	memset(&ss, 0, sizeof(struct sockaddr_storage));

	/* Accept incoming connection and read packet. */
	int client = remote_recv(sock, &ss, pkt->wire, &buflen);
	if (client < 0) {
		dbg_server("remote: failed to receive query = %d\n", client);
		knot_pkt_free(&pkt);
		return client;
	} else {
		pkt->size = buflen;
	}

	/* Parse packet and answer if OK. */
	int ret = remote_parse(pkt);
	if (ret == KNOT_EOK && ctl_if->addr.ss_family != AF_UNIX) {

		/* Check ACL list. */
		char addr_str[SOCKADDR_STRLEN] = {0};
		sockaddr_tostr(&ss, addr_str, sizeof(addr_str));
		knot_tsig_key_t *tsig_key = NULL;
		const knot_dname_t *tsig_name = NULL;
		if (pkt->tsig_rr) {
			tsig_name = pkt->tsig_rr->owner;
		}
		conf_iface_t *match = acl_find(&conf()->ctl.allow, &ss, tsig_name);
		uint16_t ts_rc = 0;
		uint16_t ts_trc = 0;
		uint64_t ts_tmsigned = 0;
		if (match == NULL) {
			log_warning("remote control, denied '%s', "
			            "no matching ACL", addr_str);
			remote_senderr(client, pkt->wire, pkt->size);
			ret = KNOT_EACCES;
			goto finish;
		} else {
			tsig_key = match->key;
		}

		/* Check TSIG. */
		if (tsig_key) {
			if (pkt->tsig_rr == NULL) {
				log_warning("remote control, denied '%s', "
				            "key required", addr_str);
				remote_senderr(client, pkt->wire, pkt->size);
				ret = KNOT_EACCES;
				goto finish;
			}
			ret = zones_verify_tsig_query(pkt, tsig_key, &ts_rc,
			                              &ts_trc, &ts_tmsigned);
			if (ret != KNOT_EOK) {
				log_warning("remote control, denied '%s', "
				            "key verification failed", addr_str);
				remote_senderr(client, pkt->wire, pkt->size);
				ret = KNOT_EACCES;
				goto finish;
			}
		}
	}

	/* Answer packet. */
	if (ret == KNOT_EOK) {
		ret = remote_answer(client, s, pkt);
	}

finish:
	knot_pkt_free(&pkt);
	close(client);
	return ret;
}

knot_pkt_t* remote_query(const char *query, const knot_tsig_key_t *key)
{
	if (!query) {
		return NULL;
	}

	knot_pkt_t *pkt = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, NULL);
	if (!pkt) {
		return NULL;
	}

	knot_wire_set_id(pkt->wire, knot_random_uint16_t());
	knot_pkt_reserve(pkt, tsig_wire_maxsize(key));

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

int remote_query_sign(uint8_t *wire, size_t *size, size_t maxlen,
                      const knot_tsig_key_t *key)
{
	if (!wire || !size || !key) {
		return KNOT_EINVAL;
	}

	size_t dlen = knot_tsig_digest_length(key->algorithm);
	uint8_t *digest = malloc(dlen);
	if (!digest) {
		return KNOT_ENOMEM;
	}

	int ret = knot_tsig_sign(wire, size, maxlen, NULL, 0, digest, &dlen,
	                         key, 0, 0);
	free(digest);

	return ret;
}

int remote_build_rr(knot_rrset_t *rr, const char *k, uint16_t t)
{
	if (!k) {
		return KNOT_EINVAL;
	}

	/* Assert K is FQDN. */
	knot_dname_t *key = knot_dname_from_str_alloc(k);
	if (key == NULL) {
		return KNOT_ENOMEM;
	}

	/* Init RRSet. */
	knot_rrset_init(rr, key, t, KNOT_CLASS_CH);

	return KNOT_EOK;
}

int remote_create_txt(knot_rrset_t *rr, const char *v, size_t v_len)
{
	if (!rr || !v) {
		return KNOT_EINVAL;
	}

	/* Number of chunks. */
	const size_t K = 255;
	unsigned chunks = v_len / K + 1;
	uint8_t raw[v_len + chunks];
	memset(raw, 0, v_len + chunks);

	/* Write TXT item. */
	unsigned p = 0;
	size_t off = 0;
	if (v_len > K) {
		for (; p + K < v_len; p += K) {
			raw[off++] = (uint8_t)K;
			memcpy(raw + off, v + p, K);
			off += K;
		}
	}
	unsigned r = v_len - p;
	if (r > 0) {
		raw[off++] = (uint8_t)r;
		memcpy(raw + off, v + p, r);
	}

	return knot_rrset_add_rdata(rr, raw, v_len + chunks, 0, NULL);
}

int remote_create_ns(knot_rrset_t *rr, const char *d)
{
	if (!rr || !d) {
		return KNOT_EINVAL;
	}

	/* Create dname. */
	knot_dname_t *dn = knot_dname_from_str_alloc(d);
	if (!dn) {
		return KNOT_ERROR;
	}

	/* Build RDATA. */
	int dn_size = knot_dname_size(dn);
	int result = knot_rrset_add_rdata(rr, dn, dn_size, 0, NULL);
	knot_dname_free(&dn, NULL);

	return result;
}

int remote_print_txt(const knot_rrset_t *rr, uint16_t i)
{
	if (!rr || rr->rrs.rr_count < 1) {
		return -1;
	}

	/* Packet parser should have already checked the packet validity. */
	char buf[256];
	uint16_t parsed = 0;
	const knot_rdata_t *rdata = knot_rdataset_at(&rr->rrs, i);
	uint8_t *p = knot_rdata_data(rdata);
	uint16_t rlen = knot_rdata_rdlen(rdata);
	while (parsed < rlen) {
		memcpy(buf, (const char*)(p+1), *p);
		buf[*p] = '\0';
		printf("%s", buf);
		parsed += *p + 1;
		p += *p + 1;
	}
	return KNOT_EOK;
}
