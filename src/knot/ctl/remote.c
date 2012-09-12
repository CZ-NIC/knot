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

#include "remote.h"
#include "common/log.h"
#include "common/fdset.h"
#include "knot/common.h"
#include "knot/conf/conf.h"
#include "knot/server/socket.h"
#include "knot/server/tcp-handler.h"
#include "libknot/packet/query.h"

int remote_bind(conf_iface_t *desc)
{
	if (desc == NULL) {
		return -1;
	}
	
	/* Create new socket. */
	int s = socket_create(desc->family, SOCK_STREAM);
	if (s < 0) {
		log_server_error("Couldn't create socket for remote "
				 "control interface - %s",
				 knot_strerror(s));
		return -1;
	}
	
	/* Bind to interface and start listening. */
	int r = socket_bind(s, desc->family, desc->address, desc->port);
	if (r == KNOT_EOK) {
		r = socket_listen(s, TCP_BACKLOG_SIZE);
	}
	
	if (r != KNOT_EOK) {
		socket_close(s);
		log_server_error("Could not bind to "
				 "remote control interface %s port %d.\n",
				 desc->address, desc->port);
		return -1;
	}
	
	return s;
}

int remote_unbind(int r)
{
	if (r < 0) {
		return KNOT_EINVAL;
	}
	
	return socket_close(r);
}

int remote_poll(int r)
{
	if (r < 0) {
		return -1;
	}
	
	/* Wait for events. */
	fd_set rfds;
	FD_ZERO(&rfds);
	FD_SET(r, &rfds);
	return fdset_pselect(r + 1, &rfds, NULL, NULL, NULL, NULL);
}

int remote_recv(knot_nameserver_t *ns, int r)
{
	fprintf(stderr, "remote: accepting..\n");
	int c = tcp_accept(r);
	if (c < 0) {
		return c;
	}
	
	/*! \todo Temporary */
	uint8_t buf[1024] = {0};
	size_t buflen = sizeof(buf);
	sockaddr_t addr;
	sockaddr_init(&addr, AF_INET);

	/* Receive data. */
	int n = tcp_recv(c, buf, buflen, &addr);
	if (n <= 0) {
		fprintf(stderr, "remote: failed to receive data\n");
		socket_close(c);
		return KNOT_ECONNREFUSED;
	}

	/* Parse query. */
	knot_packet_type_t qtype = KNOT_QUERY_NORMAL;
	knot_packet_t *packet = knot_packet_new(KNOT_PACKET_PREALLOC_QUERY);
	if (packet == NULL) {
		fprintf(stderr, "remote: no mem to form packet\n");
		socket_close(c);
		return KNOT_ENOMEM;
	}
	int res = knot_ns_parse_packet(buf, n, packet, &qtype);
	if (res != KNOT_EOK || qtype != KNOT_QUERY_NORMAL) {
		fprintf(stderr, "remote: failed to parse packet\n");
		knot_packet_free(&packet);
		socket_close(c);
		return KNOT_EINVAL;
	}
	res = knot_packet_parse_rest(packet);
	if (res != KNOT_EOK) {
		fprintf(stderr, "remote: failed to parse packet data\n");
		return KNOT_EINVAL;
	}
	
	/* Answer query. */
	int ret = remote_answer(packet);
	fprintf(stderr, "remote: answering result=%d\n", ret);
	if (ret == 0) {
		res = knot_ns_error_response_from_query(ns, packet, KNOT_RCODE_NOERROR, buf, &buflen);
		if (res == KNOT_EOK) {
			tcp_send(c, buf, buflen);
		}
	}
	
	knot_packet_free(&packet);
	
	socket_close(c);
	fprintf(stderr, "remote: i'm so done with this\n");
	return ret;
}

int remote_answer(knot_packet_t *pkt)
{
	/* Prerequisites:
	 * QCLASS: CH
	 * QNAME: config.
	 */
	const knot_dname_t *qname = knot_packet_qname(pkt);
	if (knot_packet_qclass(pkt) != KNOT_CLASS_CH) {
		fprintf(stderr, "remote: qclass != CH\n");
		return -1;
	}
	
	knot_dname_t *domain = knot_dname_new_from_str("config.", 7, NULL);
	if (knot_dname_compare(qname, domain) != 0) {
		fprintf(stderr, "remote: qname != config\n");
		knot_dname_free(&domain);
		return -3;
	}
	
//	knot_dname_free(&domain);
	
	/* Data:
	 * NS: cmd_name TXT cmd_data
	 * AR: TSIG
	 */
	
	if (knot_packet_additional_rrset_count(pkt) != 1) {
		fprintf(stderr, "remote: no command\n");
		return 0; /* OK */
	}
	
	char *data = "NULL";
	const knot_rrset_t *cmd_rr = knot_packet_additional_rrset(pkt, 0);
	if (knot_rrset_type(cmd_rr) == KNOT_RRTYPE_TXT) {
		const knot_rdata_t *rdata = knot_rrset_rdata(cmd_rr);
		if (rdata->count > 0) {
			uint8_t *rd = (uint8_t*)rdata->items[0].raw_data;
			uint16_t len = *((uint16_t*)rd) - 1;
			data = malloc(len + 1);
			memcpy(data, rd + 2 + 1, len);
			data[len] = '\0';
		}
	}
	fprintf(stderr, "CMD: '%s' DATA: '%s'\n",
		knot_dname_to_str(knot_rrset_owner(cmd_rr)), data);
	return 0;
}

int remote_query(knot_packet_t **dst, const char *query)
{
	if (dst == NULL || query == NULL) {
		return KNOT_EINVAL;
	}
	
	*dst = knot_packet_new(KNOT_PACKET_PREALLOC_QUERY);
	if (*dst == NULL) {
		return KNOT_ENOMEM;
	}
	
	knot_packet_set_max_size(*dst, 512);
	knot_query_init(*dst);
	knot_packet_set_random_id(*dst);
	
	/* Question section. */
	knot_question_t q;
	char *qname = strcdup(query, ".config.");
	if (qname == NULL) {
		knot_packet_free(dst);
		return KNOT_ENOMEM;
	}
	/*! \todo what if query has more dots ? */
	q.qname = knot_dname_new_from_str(qname, strlen(qname), 0);
	q.qtype = KNOT_RRTYPE_ANY;
	q.qclass = KNOT_CLASS_CH;
	knot_query_set_question(*dst, &q); /* Cannot return != KNOT_EOK */
	knot_dname_release(q.qname);
	free(qname);
	
	return KNOT_EOK;
}

int remote_query_append(knot_packet_t *qry, knot_rrset_t *data)
{
	if (!qry || !data) {
		return KNOT_EINVAL;
	}
	
	uint8_t *sp = qry->wireformat + qry->size;
	uint8_t *np   = qry->wireformat + qry->max_size;
	uint8_t *p = sp;
	int ret = knot_query_rr_to_wire(data, knot_rrset_rdata(data), &p, np);
	if (ret == KNOT_EOK) {
		qry->header.arcount = 1;
		qry->size += (p - sp);
	}
	
	return ret;
}

int remote_query_sign(knot_packet_t *qry, knot_key_t *key)
{
	if (!qry || !key) {
		return KNOT_EINVAL;
	}
	
	return KNOT_ENOTSUP;
}

