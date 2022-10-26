/*  Copyright (C) 2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <time.h>
#include "contrib/macros.h"
#include "contrib/ucw/mempool.h"
#include "knot/common/log.h"
#include "knot/server/quic-handler.h"
#include "knot/server/server.h"
#include "libknot/xdp/eth.h"
#include "libknot/xdp/quic.h"
#include "libknot/xdp/tcp_iobuf.h"

#define QUIC_MAX_SEND_PER_RECV	4 // NOTE: also in xdp-handler.c
#define QUIC_IBUFS_PER_CONN	512 /* Heuristic value: this means that e.g. for 100k allowed
				       QUIC conns, we will limit total size of input buffers to 50 MiB. */

static bool quic_active_state(int state)
{
	return (state == KNOT_STATE_PRODUCE || state == KNOT_STATE_FAIL);
}

static bool quic_send_state(int state)
{
	return (state != KNOT_STATE_FAIL && state != KNOT_STATE_NOOP);
}

static void log_closed(knot_sweep_stats_t *stats)
{
	struct timespec now = time_now();
	uint64_t sec = now.tv_sec + now.tv_nsec / 1000000000;
	if (sec - stats->last_log <= 9 || (stats->total == 0)) {
		return;
	}

	const char *proto = "QUIC";

	uint32_t timedout = stats->counters[KNOT_SWEEP_CTR_TIMEOUT];
	uint32_t limit_conn = stats->counters[KNOT_SWEEP_CTR_LIMIT_CONN];
	uint32_t limit_ibuf = stats->counters[KNOT_SWEEP_CTR_LIMIT_IBUF];
	uint32_t limit_obuf = stats->counters[KNOT_SWEEP_CTR_LIMIT_OBUF];

	if (stats->total != timedout) {
		log_notice("%s, connection sweep, closed %u, count limit %u, inbuf limit %u, outbuf limit %u",
		           proto, timedout, limit_conn, limit_ibuf, limit_obuf);
	} else {
		log_debug("%s, timed out connections %u", proto, timedout);
	}

	knot_sweep_stats_reset(stats);
	stats->last_log = sec;
}

static void handle_quic_init(knotd_qdata_params_t *params, knot_layer_t *layer,
                             const struct sockaddr_storage *ss,
                             const struct iovec *payload, struct sockaddr_storage *proxied_remote)
{
	params->remote = ss;
	params->xdp_msg = NULL;

	knot_layer_begin(layer, params);

	knot_pkt_t *query = knot_pkt_new(payload->iov_base, payload->iov_len, layer->mm);
	int ret = knot_pkt_parse(query, 0);
	if (ret != KNOT_EOK && query->parsed > 0) { // parsing failed (e.g. 2x OPT)
		query->parsed--; // artificially decreasing "parsed" leads to FORMERR
	}
	knot_layer_consume(layer, query);
}

static void handle_quic_finish(knot_layer_t *layer)
{
	knot_layer_finish(layer);

	// Flush per-query memory (including query and answer packets).
	mp_flush(layer->mm->ctx);
}

static void handle_quic_stream(knot_xquic_conn_t *conn, int64_t stream_id, struct iovec *inbuf,
                               knot_layer_t *layer, knotd_qdata_params_t *params, uint8_t *ans_buf,
                               size_t ans_buf_size, const struct sockaddr_storage *ss)
{
	// Consume the query.
	handle_quic_init(params, layer, ss, inbuf, NULL);
	params->measured_rtt = knot_xquic_conn_rtt(conn);

	// Process the reply.
	knot_pkt_t *ans = knot_pkt_new(ans_buf, ans_buf_size, layer->mm);
	while (quic_active_state(layer->state)) {
		knot_layer_produce(layer, ans);
		if (!quic_send_state(layer->state)) {
			continue;
		}
		if (knot_xquic_stream_add_data(conn, stream_id, ans->wire, ans->size) == NULL) {
			break;
		}
	}

	handle_quic_finish(layer);
}

static int uq_alloc_reply(struct knot_quic_reply *r)
{
	if (r->out_payload->iov_len == 0) {
		r->out_payload->iov_len = KNOT_WIRE_MAX_PKTSIZE;
	} else if (r->out_payload->iov_len != KNOT_WIRE_MAX_PKTSIZE) {
		assert(r->out_ctx == NULL);
		r->out_ctx = r->out_payload->iov_base;
		size_t curr = r->out_payload->iov_len;

		r->out_payload->iov_base += curr;
		r->out_payload->iov_len = KNOT_WIRE_MAX_PKTSIZE - curr;
	}
	return KNOT_EOK;
}

static int uq_send_reply(struct knot_quic_reply *r)
{
	if (r->out_ctx != NULL) {
		struct iovec second_msg = { r->out_payload->iov_base, r->out_payload->iov_len };
		r->out_payload->iov_len = second_msg.iov_base - r->out_ctx;
		r->out_payload->iov_base = r->out_ctx;

		// a packet for the same conn is already awaiting send
		(void)sendmsg(*(int *)r->ctx, r->in_ctx, 0);

		r->out_payload->iov_len = second_msg.iov_len;
		memmove(r->out_payload->iov_base, second_msg.iov_base, second_msg.iov_len);

		r->out_ctx = NULL;
	}
	return KNOT_EOK;
}

static void uq_free_reply(struct knot_quic_reply *r)
{
	if (r->out_ctx != NULL) {
		void *second_msg = r->out_payload->iov_base;
		r->out_payload->iov_len = second_msg - r->out_ctx;
		r->out_payload->iov_base = r->out_ctx;
		r->out_ctx = NULL;
	}
}

void udp_quic_handle(knotd_qdata_params_t *params, knot_layer_t *layer, uint64_t idle_close,
                     void *quic_table, struct msghdr *mh_in, struct msghdr *mh_out,
                     struct iovec *rx, struct iovec *tx)
{
	struct sockaddr_storage local_ip = { 0 };
	if (knot_eth_addr_from_fd(params->socket, mh_in, &local_ip) != KNOT_EOK) {
		// doomed :(
		tx->iov_len = 0;
		return;
	}

	knot_quic_reply_t rpl = { .ip_rem = params->remote, .ip_loc = &local_ip, .in_payload = rx, .out_payload = tx,
	                          .ctx = &params->socket, .in_ctx = mh_out,
	                          .alloc_reply = uq_alloc_reply, .send_reply = uq_send_reply, .free_reply = uq_free_reply };
	knot_xquic_conn_t *conn = NULL;

	rpl.in_ret = knot_quic_handle(quic_table, &rpl, idle_close, &conn);

	int64_t stream_id;
	knot_xquic_stream_t *stream;

	while (conn != NULL && (stream = knot_xquic_stream_get_process(conn, &stream_id)) != NULL) {
		assert(stream->inbuf_fin != NULL);
		assert(stream->inbuf_fin->iov_len > 0);
		handle_quic_stream(conn, stream_id, stream->inbuf_fin, layer, params,
		                   tx->iov_base, tx->iov_len, params->remote); // NOTE: tx is used here just as temporary buffer
		free(stream->inbuf_fin);
		stream->inbuf_fin = NULL;
	}

	(void)knot_quic_send(quic_table, conn, &rpl, QUIC_MAX_SEND_PER_RECV, false);

	knot_xquic_cleanup(&conn, 1);

	if (tx->iov_len == KNOT_WIRE_MAX_PKTSIZE) {
		tx->iov_len = 0;
	}
}

void udp_quic_handle_sweep(void *quic_ctx, struct knot_sweep_stats *quic_closed)
{
	(void)knot_xquic_table_sweep(quic_ctx, quic_closed);
	log_closed(quic_closed);
}

void *udp_quic_make_table(struct server *server)
{
	conf_t *pconf = conf();
	size_t udp_pl = MIN(pconf->cache.srv_udp_max_payload_ipv4, pconf->cache.srv_udp_max_payload_ipv6);

	size_t quic_max_conns = pconf->cache.srv_quic_max_clients / pconf->cache.srv_udp_threads;
	size_t quic_max_inbufs= quic_max_conns * QUIC_IBUFS_PER_CONN;
	size_t quic_max_obufs = pconf->cache.srv_quic_obuf_max_size;


	return knot_xquic_table_new(quic_max_conns, quic_max_inbufs, quic_max_obufs, udp_pl, server->quic_creds);
}

void udp_quic_unmake_table(void *table)
{
	knot_xquic_table_free(table);
}
