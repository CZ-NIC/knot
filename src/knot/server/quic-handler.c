/*  Copyright (C) 2024 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifdef __APPLE__
#define __APPLE_USE_RFC_3542 // IPV6_PKTINFO
#endif

#include <netinet/in.h>
#include <string.h>

#include "contrib/macros.h"
#include "contrib/net.h"
#include "knot/common/log.h"
#include "knot/nameserver/process_query.h"
#include "knot/server/handler.h"
#include "knot/server/quic-handler.h"
#include "knot/server/server.h"
#include "libknot/quic/quic.h"
#include "libknot/xdp/tcp_iobuf.h"

#define SWEEP_BUF_SIZE 4096

typedef union {
	struct cmsghdr cmsg;
	uint8_t buf[CMSG_SPACE(sizeof(struct in6_pktinfo))];
} cmsg_pktinfo_t;

static void quic_log_cb(const char *line)
{
	log_fmt(LOG_DEBUG, LOG_SOURCE_QUIC, "QUIC, %s", line);
}

static int uq_alloc_reply(knot_quic_reply_t *r)
{
	r->out_payload->iov_len = KNOT_WIRE_MAX_PKTSIZE;

	return KNOT_EOK;
}

static int uq_send_reply(knot_quic_reply_t *r)
{
	int fd = *(int *)r->sock;

	if (r->in_ctx != NULL) {
		*(int *)r->in_ctx = r->ecn; // set ECN for outgoing CMSG
	}
	int ret = sendmsg(fd, r->out_ctx, 0);
	if (ret < 0) {
		return knot_map_errno();
	} else if (ret == r->out_payload->iov_len) {
		return KNOT_EOK;
	} else {
		return KNOT_EAGAIN;
	}
}

static void uq_free_reply(knot_quic_reply_t *r)
{
	// This prevents udp send handler from sending.
	r->out_payload->iov_len = 0;
}

void quic_handler(knotd_qdata_params_t *params, knot_layer_t *layer,
                  uint64_t idle_close, knot_quic_table_t *table,
                  struct iovec *rx, struct msghdr *mh_out, int *p_ecn)
{
	knot_quic_reply_t rpl = {
		.ip_rem = params->remote,
		.ip_loc = params->local,
		.in_payload = rx,
		.out_payload = mh_out->msg_iov,
		.sock = &params->socket,
		.in_ctx = p_ecn,
		.out_ctx = mh_out,
		.ecn = (p_ecn == NULL ? 0 : (*p_ecn & 0x3)),
		.alloc_reply = uq_alloc_reply,
		.send_reply = uq_send_reply,
		.free_reply = uq_free_reply
	};

	rpl.out_payload->iov_len = 0; // prevent send attempt if uq_alloc_reply is not called at all

	if (process_query_proto(params, KNOTD_STAGE_PROTO_BEGIN) == KNOTD_PROTO_STATE_BLOCK) {
		return;
	}

	knot_quic_conn_t *conn = NULL;
	(void)knot_quic_handle(table, &rpl, idle_close, &conn);

	if (conn != NULL) {
		handle_quic_streams(conn, params, layer);

		(void)knot_quic_send(table, conn, &rpl, QUIC_MAX_SEND_PER_RECV, 0);

		knot_quic_cleanup(&conn, 1);
	}

	(void)process_query_proto(params, KNOTD_STAGE_PROTO_END);
}

knot_quic_table_t *quic_make_table(struct server *server)
{
	conf_t *pconf = conf();
	size_t udp_pl = MIN(pconf->cache.srv_udp_max_payload_ipv4,
	                    pconf->cache.srv_udp_max_payload_ipv6);
	size_t quic_max_conns = pconf->cache.srv_quic_max_clients /
	                        pconf->cache.srv_udp_threads;
	size_t quic_max_inbufs= quic_max_conns * QUIC_IBUFS_PER_CONN;
	size_t quic_max_obufs = pconf->cache.srv_quic_obuf_max_size;

	knot_quic_table_t *table =
		knot_quic_table_new(quic_max_conns, quic_max_inbufs, quic_max_obufs,
		                     udp_pl, server->quic_creds);
	if (table != NULL && log_enabled_quic_debug()) {
		table->log_cb = quic_log_cb;
	}

	return table;
}

void quic_reconfigure_table(knot_quic_table_t *table)
{
	if (table != NULL) {
		conf_t *pconf = conf();
		size_t udp_pl = MIN(pconf->cache.srv_udp_max_payload_ipv4,
				    pconf->cache.srv_udp_max_payload_ipv6);
		table->udp_payload_limit = udp_pl;

		// it's also easy to re-configure inbuf and outbuf limits, but no need to yet
		// but it's more difficult to re-configure table size (realloc...)

		table->log_cb = log_enabled_quic_debug() ? quic_log_cb : NULL;
	}
}

int uq_alloc_sweep(struct knot_quic_reply *r)
{
	r->out_payload->iov_len = SWEEP_BUF_SIZE;
	return KNOT_EOK;
}

int uq_send_sweep(struct knot_quic_reply *r)
{
	int fd = (int)(size_t)r->sock;

	cmsg_pktinfo_t cmsg = { 0 };
	if (r->ip_loc->ss_family == AF_INET6) {
		cmsg.cmsg.cmsg_level = IPPROTO_IPV6;
		cmsg.cmsg.cmsg_type = IPV6_PKTINFO;
		cmsg.cmsg.cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
		memcpy(&((struct in6_pktinfo *)CMSG_DATA(&cmsg.cmsg))->ipi6_addr,
		       &((const struct sockaddr_in6 *)r->ip_loc)->sin6_addr,
		       sizeof(struct in6_addr));
	} else {
		cmsg.cmsg.cmsg_level = IPPROTO_IP;
#if defined(IP_PKTINFO)
		cmsg.cmsg.cmsg_type = IP_PKTINFO;
		cmsg.cmsg.cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
		memcpy(&((struct in_pktinfo *)CMSG_DATA(&cmsg.cmsg))->ipi_addr,
		       &((const struct sockaddr_in *)r->ip_loc)->sin_addr,
		       sizeof(struct in_addr));
#elif defined(IP_SENDSRCADDR)
		cmsg.cmsg.cmsg_type = IP_SENDSRCADDR;
		cmsg.cmsg.cmsg_len = CMSG_LEN(sizeof(struct in_addr));
		memcpy((struct in_addr *)CMSG_DATA(&cmsg.cmsg),
		       &((const struct sockaddr_in *)r->ip_loc)->sin_addr,
		       sizeof(struct in_addr));
#endif
	} // this only says "send it with given outgoing IP address"

	assert(r->ip_rem != NULL);
	struct msghdr msg = {
		.msg_iov = r->out_payload,
		.msg_iovlen = 1,
		.msg_name = (void *)r->ip_rem,
		.msg_namelen = r->ip_rem->ss_family == AF_INET6 ? sizeof(struct sockaddr_in6) :
		                                                  sizeof(struct sockaddr_in),
		.msg_control = &cmsg,
		.msg_controllen = sizeof(cmsg),
	};

	int ret = net_msg_send(fd, &msg, 0);
	if (ret < 0) {
		return ret;
	} else if (ret == r->out_payload->iov_len) {
		return KNOT_EOK;
	} else {
		return KNOT_EAGAIN;
	}
}

void uq_free_sweep(struct knot_quic_reply *r)
{
	(void)r;
}

void quic_sweep_table(knot_quic_table_t *table, knot_sweep_stats_t *stats, int fd)
{
	if (table == NULL) {
		return;
	}

	uint8_t sendbuf[SWEEP_BUF_SIZE];
	struct iovec r_iov = { .iov_base = sendbuf };
	knot_quic_reply_t r = {
		.sock = (void *)(size_t)fd,
		.out_payload = &r_iov,
		.alloc_reply = uq_alloc_sweep,
		.send_reply = uq_send_sweep,
		.free_reply = uq_free_sweep,
	};

	knot_quic_table_sweep(table, &r, stats);
	log_swept(stats, false);
}

void quic_unmake_table(knot_quic_table_t *table)
{
	knot_quic_table_free(table);
}
