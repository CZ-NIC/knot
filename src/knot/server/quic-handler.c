/*  Copyright (C) 2023 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <netinet/in.h>
#include <string.h>

#include "contrib/macros.h"
#include "knot/server/handler.h"
#include "knot/server/quic-handler.h"
#include "knot/server/server.h"
#include "libknot/quic/quic.h"
#include "libknot/xdp/tcp_iobuf.h"

static int uq_alloc_reply(knot_quic_reply_t *r)
{
	r->out_payload->iov_len = KNOT_WIRE_MAX_PKTSIZE;

	return KNOT_EOK;
}

static int uq_send_reply(knot_quic_reply_t *r)
{
	int ret = sendmsg(*(int *)r->sock, r->out_ctx, 0);
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
                  uint64_t idle_close, knot_xquic_table_t *table,
                  struct iovec *rx, struct msghdr *mh_out)
{
	knot_quic_reply_t rpl = {
		.ip_rem = params->remote,
		.ip_loc = params->local,
		.in_payload = rx,
		.out_payload = mh_out->msg_iov,
		.sock = &params->socket,
		.out_ctx = mh_out,
		.alloc_reply = uq_alloc_reply,
		.send_reply = uq_send_reply,
		.free_reply = uq_free_reply
	};

	knot_xquic_conn_t *conn = NULL;
	(void)knot_quic_handle(table, &rpl, idle_close, &conn);

	handle_quic_streams(conn, params, layer, NULL);

	(void)knot_quic_send(table, conn, &rpl, QUIC_MAX_SEND_PER_RECV, false);

	knot_xquic_cleanup(&conn, 1);
}

void quic_sweep(knot_xquic_table_t *table, knot_sweep_stats_t *stats)
{
	(void)knot_xquic_table_sweep(table, stats);
	log_swept(stats, false);
}

void *quic_make_table(struct server *server)
{
	conf_t *pconf = conf();
	size_t udp_pl = MIN(pconf->cache.srv_udp_max_payload_ipv4,
	                    pconf->cache.srv_udp_max_payload_ipv6);

	size_t quic_max_conns = pconf->cache.srv_quic_max_clients /
	                        pconf->cache.srv_udp_threads;
	size_t quic_max_inbufs= quic_max_conns * QUIC_IBUFS_PER_CONN;
	size_t quic_max_obufs = pconf->cache.srv_quic_obuf_max_size;

	return knot_xquic_table_new(quic_max_conns, quic_max_inbufs, quic_max_obufs,
	                            udp_pl, server->quic_creds);
}

void quic_unmake_table(knot_xquic_table_t *table)
{
	knot_xquic_table_free(table);
}
