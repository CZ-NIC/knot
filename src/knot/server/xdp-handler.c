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

#ifdef ENABLE_XDP

#include <assert.h>
#include <stdlib.h>
#include <urcu.h>

#include "knot/server/xdp-handler.h"
#include "knot/common/log.h"
#include "knot/server/proxyv2.h"
#include "knot/server/server.h"
#include "contrib/sockaddr.h"
#include "contrib/time.h"
#include "contrib/ucw/mempool.h"
#include "libknot/endian.h"
#include "libknot/error.h"
#ifdef ENABLE_QUIC
#include "libknot/xdp/quic.h"
#endif // ENABLE_QUIC
#include "libknot/xdp/tcp.h"
#include "libknot/xdp/tcp_iobuf.h"

#define QUIC_MAX_SEND_PER_RECV	4
#define QUIC_IBUFS_PER_CONN	512 /* Heuristic value: this means that e.g. for 100k allowed
				       QUIC conns, we will limit total size of input buffers to 50 MiB. */

typedef struct xdp_handle_ctx {
	knot_xdp_socket_t *sock;
	knot_xdp_msg_t msg_recv[XDP_BATCHLEN];
	knot_xdp_msg_t msg_send_udp[XDP_BATCHLEN];
	knot_tcp_relay_t relays[XDP_BATCHLEN];
	uint32_t msg_recv_count;
	uint32_t msg_udp_count;
	knot_tcp_table_t *tcp_table;
	knot_tcp_table_t *syn_table;

#ifdef ENABLE_QUIC
	knot_xquic_conn_t *quic_relays[XDP_BATCHLEN];
	knot_quic_reply_t quic_rpls[XDP_BATCHLEN];
	knot_xquic_table_t *quic_table;
	knot_sweep_stats_t quic_closed;
#endif // ENABLE_QUIC

	bool tcp;
	size_t tcp_max_conns;
	size_t tcp_syn_conns;
	size_t tcp_max_inbufs;
	size_t tcp_max_obufs;
	uint32_t tcp_idle_close;  // In microseconds.
	uint32_t tcp_idle_reset;  // In microseconds.
	uint32_t tcp_idle_resend; // In microseconds.

	uint16_t quic_port;       // Network-byte order!
	size_t quic_max_conns;
	uint64_t quic_idle_close; // In nanoseconds.
	size_t quic_max_inbufs;
	size_t quic_max_obufs;

	knot_sweep_stats_t tcp_closed;
} xdp_handle_ctx_t;

static bool udp_state_active(int state)
{
	return (state == KNOT_STATE_PRODUCE || state == KNOT_STATE_FAIL);
}

static bool tcp_active_state(int state)
{
	return (state == KNOT_STATE_PRODUCE || state == KNOT_STATE_FAIL);
}

static bool tcp_send_state(int state)
{
	return (state != KNOT_STATE_FAIL && state != KNOT_STATE_NOOP);
}

static void log_closed(knot_sweep_stats_t *stats, bool tcp)
{
	struct timespec now = time_now();
	uint64_t sec = now.tv_sec + now.tv_nsec / 1000000000;
	if (sec - stats->last_log <= 9 || (stats->total == 0)) {
		return;
	}

	const char *proto = tcp ? "TCP" : "QUIC";

	uint32_t timedout = stats->counters[KNOT_SWEEP_CTR_TIMEOUT];
	uint32_t limit_conn = stats->counters[KNOT_SWEEP_CTR_LIMIT_CONN];
	uint32_t limit_ibuf = stats->counters[KNOT_SWEEP_CTR_LIMIT_IBUF];
	uint32_t limit_obuf = stats->counters[KNOT_SWEEP_CTR_LIMIT_OBUF];

	if (tcp || stats->total != timedout) {
		log_notice("%s, connection sweep, closed %u, count limit %u, inbuf limit %u, outbuf limit %u",
		           proto, timedout, limit_conn, limit_ibuf, limit_obuf);
	} else {
		log_debug("%s, timed out connections %u", proto, timedout);
	}

	knot_sweep_stats_reset(stats);
	stats->last_log = sec;
}

void xdp_handle_reconfigure(xdp_handle_ctx_t *ctx)
{
	rcu_read_lock();
	conf_t *pconf = conf();
	ctx->tcp            = pconf->cache.xdp_tcp;
	ctx->quic_port      = htobe16(pconf->cache.xdp_quic);
	ctx->tcp_max_conns  = pconf->cache.xdp_tcp_max_clients / pconf->cache.srv_xdp_threads;
	ctx->tcp_syn_conns  = 2 * ctx->tcp_max_conns;
	ctx->tcp_max_inbufs = pconf->cache.xdp_tcp_inbuf_max_size / pconf->cache.srv_xdp_threads;
	ctx->tcp_max_obufs  = pconf->cache.xdp_tcp_outbuf_max_size / pconf->cache.srv_xdp_threads;
	ctx->tcp_idle_close = pconf->cache.xdp_tcp_idle_close * 1000000;
	ctx->tcp_idle_reset = pconf->cache.xdp_tcp_idle_reset * 1000000;
	ctx->tcp_idle_resend= pconf->cache.xdp_tcp_idle_resend * 1000000;
	ctx->quic_max_conns = pconf->cache.srv_quic_max_clients / pconf->cache.srv_xdp_threads;
	ctx->quic_idle_close= pconf->cache.srv_quic_idle_close * 1000000000LU;
	ctx->quic_max_inbufs= ctx->quic_max_conns * QUIC_IBUFS_PER_CONN;
	ctx->quic_max_obufs = pconf->cache.srv_quic_obuf_max_size;
	rcu_read_unlock();
}

void xdp_handle_free(xdp_handle_ctx_t *ctx)
{
	knot_tcp_table_free(ctx->tcp_table);
	knot_tcp_table_free(ctx->syn_table);
#ifdef ENABLE_QUIC
	knot_xquic_table_free(ctx->quic_table);
#endif // ENABLE_QUIC
	free(ctx);
}

#ifdef ENABLE_QUIC
static void quic_log_cb(const char *line)
{
	log_debug("QUIC: %s", line);
}
#endif // ENABLE_QUIC

xdp_handle_ctx_t *xdp_handle_init(struct server *server, knot_xdp_socket_t *xdp_sock)
{
	xdp_handle_ctx_t *ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		return NULL;
	}
	ctx->sock = xdp_sock;

	xdp_handle_reconfigure(ctx);

	if (ctx->tcp) {
		// NOTE: the table size don't have to equal its max usage!
		ctx->tcp_table = knot_tcp_table_new(ctx->tcp_max_conns, NULL);
		if (ctx->tcp_table == NULL) {
			xdp_handle_free(ctx);
			return NULL;
		}
		ctx->syn_table = knot_tcp_table_new(ctx->tcp_syn_conns, ctx->tcp_table);
		if (ctx->syn_table == NULL) {
			xdp_handle_free(ctx);
			return NULL;
		}
	}

	if (ctx->quic_port > 0) {
#ifdef ENABLE_QUIC
		conf_t *pconf = conf();
		size_t udp_pl = MIN(pconf->cache.srv_udp_max_payload_ipv4, pconf->cache.srv_udp_max_payload_ipv6);
		ctx->quic_table = knot_xquic_table_new(ctx->quic_max_conns, ctx->quic_max_inbufs,
		                                       ctx->quic_max_obufs, udp_pl, server->quic_creds);
		if (ctx->quic_table == NULL) {
			xdp_handle_free(ctx);
			return NULL;
		}
		if (conf_get_bool(pconf, C_XDP, C_QUIC_LOG)) {
			ctx->quic_table->log_cb = quic_log_cb;
		}
#else
		assert(0); // verified in configuration checks
#endif // ENABLE_QUIC
	}

	return ctx;
}

int xdp_handle_recv(xdp_handle_ctx_t *ctx)
{
	int ret = knot_xdp_recv(ctx->sock, ctx->msg_recv, XDP_BATCHLEN,
	                        &ctx->msg_recv_count, NULL);
	return ret == KNOT_EOK ? ctx->msg_recv_count : ret;
}

static void handle_init(knotd_qdata_params_t *params, knot_layer_t *layer,
                        knotd_query_proto_t proto, const knot_xdp_msg_t *msg,
                        const struct iovec *payload, struct sockaddr_storage *proxied_remote)
{
	params->proto = proto;
	params->remote = (struct sockaddr_storage *)&msg->ip_from;
	params->xdp_msg = msg;

	knot_layer_begin(layer, params);

	knot_pkt_t *query = knot_pkt_new(payload->iov_base, payload->iov_len, layer->mm);
	int ret = knot_pkt_parse(query, 0);
	if (ret != KNOT_EOK && query->parsed > 0) { // parsing failed (e.g. 2x OPT)
		if (params->proto == KNOTD_QUERY_PROTO_UDP &&
		    proxyv2_header_strip(&query, params->remote, proxied_remote) == KNOT_EOK) {
			assert(proxied_remote);
			params->remote = proxied_remote;
		} else {
			query->parsed--; // artificially decreasing "parsed" leads to FORMERR
		}
	}
	knot_layer_consume(layer, query);
}

static void handle_finish(knot_layer_t *layer)
{
	knot_layer_finish(layer);

	// Flush per-query memory (including query and answer packets).
	mp_flush(layer->mm->ctx);
}

static void handle_udp(xdp_handle_ctx_t *ctx, knot_layer_t *layer,
                       knotd_qdata_params_t *params)
{
	struct sockaddr_storage proxied_remote;

	ctx->msg_udp_count = 0;

	for (uint32_t i = 0; i < ctx->msg_recv_count; i++) {
		knot_xdp_msg_t *msg_recv = &ctx->msg_recv[i];
		knot_xdp_msg_t *msg_send = &ctx->msg_send_udp[ctx->msg_udp_count];

		// Skip TCP or QUIC or marked (zero length) message.
		if ((msg_recv->flags & KNOT_XDP_MSG_TCP) ||
		    msg_recv->ip_to.sin6_port == ctx->quic_port ||
		    msg_recv->payload.iov_len == 0) {
			continue;
		}

		// Try to allocate a buffer for a reply.
		if (knot_xdp_reply_alloc(ctx->sock, msg_recv, msg_send) != KNOT_EOK) {
			log_notice("UDP, failed to send some packets");
			break; // Drop the rest of the messages.
		}
		ctx->msg_udp_count++;

		// Consume the query.
		handle_init(params, layer, KNOTD_QUERY_PROTO_UDP, msg_recv, &msg_recv->payload,
		            &proxied_remote);

		// Process the reply.
		knot_pkt_t *ans = knot_pkt_new(msg_send->payload.iov_base,
		                               msg_send->payload.iov_len, layer->mm);
		while (udp_state_active(layer->state)) {
			knot_layer_produce(layer, ans);
		}
		if (layer->state == KNOT_STATE_DONE) {
			msg_send->payload.iov_len = ans->size;
		} else {
			// If not success, don't send any reply.
			msg_send->payload.iov_len = 0;
		}

		// Reset the processing.
		handle_finish(layer);
	}
}

static void handle_tcp(xdp_handle_ctx_t *ctx, knot_layer_t *layer,
                       knotd_qdata_params_t *params)
{
	int ret = knot_tcp_recv(ctx->relays, ctx->msg_recv, ctx->msg_recv_count,
	                        ctx->tcp_table, ctx->syn_table, XDP_TCP_IGNORE_NONE);
	if (ret != KNOT_EOK) {
		log_notice("TCP, failed to process some packets (%s)", knot_strerror(ret));
		return;
	} else if (knot_tcp_relay_empty(&ctx->relays[0])) { // no TCP traffic
		return;
	}

	uint8_t ans_buf[KNOT_WIRE_MAX_PKTSIZE];

	for (uint32_t i = 0; i < ctx->msg_recv_count; i++) {
		knot_tcp_relay_t *rl = &ctx->relays[i];

		// Process all complete DNS queries in one TCP stream.
		for (size_t j = 0; j < rl->inbufs_count; j++) {
			// Consume the query.
			handle_init(params, layer, KNOTD_QUERY_PROTO_TCP, rl->msg, &rl->inbufs[j], NULL);
			params->measured_rtt = rl->conn->establish_rtt;

			// Process the reply.
			knot_pkt_t *ans = knot_pkt_new(ans_buf, sizeof(ans_buf), layer->mm);
			while (tcp_active_state(layer->state)) {
				knot_layer_produce(layer, ans);
				if (!tcp_send_state(layer->state)) {
					continue;
				}

				(void)knot_tcp_reply_data(rl, ctx->tcp_table, false,
				                          ans->wire, ans->size);
			}

			handle_finish(layer);
		}
	}
}

#ifdef ENABLE_QUIC
static void handle_quic_stream(knot_xquic_conn_t *conn, int64_t stream_id, struct iovec *inbuf,
                               knot_layer_t *layer, knotd_qdata_params_t *params, uint8_t *ans_buf,
                               size_t ans_buf_size, const knot_xdp_msg_t *xdp_msg)
{
	// Consume the query.
	handle_init(params, layer, KNOTD_QUERY_PROTO_QUIC, xdp_msg, inbuf, NULL);
	params->measured_rtt = knot_xquic_conn_rtt(conn);

	// Process the reply.
	knot_pkt_t *ans = knot_pkt_new(ans_buf, ans_buf_size, layer->mm);
	while (tcp_active_state(layer->state)) {
		knot_layer_produce(layer, ans);
		if (!tcp_send_state(layer->state)) {
			continue;
		}
		if (knot_xquic_stream_add_data(conn, stream_id, ans->wire, ans->size) == NULL) {
			break;
		}
	}

	handle_finish(layer);
}
#endif // ENABLE_QUIC

static void handle_quic(xdp_handle_ctx_t *ctx, knot_layer_t *layer,
                        knotd_qdata_params_t *params)
{
#ifdef ENABLE_QUIC
	if (ctx->quic_table == NULL) {
		return;
	}

	uint8_t ans_buf[KNOT_WIRE_MAX_PKTSIZE];

	for (uint32_t i = 0; i < ctx->msg_recv_count; i++) {
		knot_xdp_msg_t *msg_recv = &ctx->msg_recv[i];
		ctx->quic_relays[i] = NULL;

		if ((msg_recv->flags & KNOT_XDP_MSG_TCP) ||
		    msg_recv->ip_to.sin6_port != ctx->quic_port ||
		    msg_recv->payload.iov_len == 0) {
			continue;
		}

		(void)knot_xquic_handle(ctx->quic_table, &ctx->quic_rpls[i],
		                        ctx->sock, msg_recv, ctx->quic_idle_close,
		                        &ctx->quic_relays[i]);
		knot_xquic_conn_t *rl = ctx->quic_relays[i];

		int64_t stream_id;
		knot_xquic_stream_t *stream;

		while (rl != NULL && (stream = knot_xquic_stream_get_process(rl, &stream_id)) != NULL) {
			assert(stream->inbuf_fin != NULL);
			assert(stream->inbuf_fin->iov_len > 0);
			handle_quic_stream(rl, stream_id, stream->inbuf_fin, layer, params,
			                   ans_buf, sizeof(ans_buf), &ctx->msg_recv[i]);
			free(stream->inbuf_fin);
			stream->inbuf_fin = NULL;
		}
	}
#else
	(void)(ctx);
	(void)(layer);
	(void)(params);
#endif // ENABLE_QUIC
}

void xdp_handle_msgs(xdp_handle_ctx_t *ctx, knot_layer_t *layer,
                     server_t *server, unsigned thread_id)
{
	assert(ctx->msg_recv_count > 0);

	knotd_qdata_params_t params = {
		.socket = knot_xdp_socket_fd(ctx->sock),
		.server = server,
		.thread_id = thread_id,
	};

	knot_xdp_send_prepare(ctx->sock);

	handle_udp(ctx, layer, &params);
	if (ctx->tcp) {
		handle_tcp(ctx, layer, &params);
	}
	handle_quic(ctx, layer, &params);

	knot_xdp_recv_finish(ctx->sock, ctx->msg_recv, ctx->msg_recv_count);
}

void xdp_handle_send(xdp_handle_ctx_t *ctx)
{
	uint32_t unused;
	int ret = knot_xdp_send(ctx->sock, ctx->msg_send_udp, ctx->msg_udp_count, &unused);
	if (ret != KNOT_EOK) {
		log_notice("UDP, failed to send some packets");
	}
	if (ctx->tcp) {
		ret = knot_tcp_send(ctx->sock, ctx->relays, ctx->msg_recv_count,
		                    XDP_BATCHLEN);
		if (ret != KNOT_EOK) {
			log_notice("TCP, failed to send some packets");
		}
	}
#ifdef ENABLE_QUIC
	for (uint32_t i = 0; i < ctx->msg_recv_count; i++) {
		if (ctx->quic_relays[i] == NULL) {
			continue;
		}

		ret = knot_quic_send(ctx->quic_table, ctx->quic_relays[i], &ctx->quic_rpls[i],
		                     QUIC_MAX_SEND_PER_RECV, false);
		if (ret != KNOT_EOK) {
			log_notice("QUIC, failed to send some packets");
		}
	}
	knot_xquic_cleanup(ctx->quic_relays, ctx->msg_recv_count);
#endif // ENABLE_QUIC

	(void)knot_xdp_send_finish(ctx->sock);

	if (ctx->tcp) {
		knot_tcp_cleanup(ctx->tcp_table, ctx->relays, ctx->msg_recv_count);
	}
}

void xdp_handle_sweep(xdp_handle_ctx_t *ctx)
{
#ifdef ENABLE_QUIC
	if (ctx->quic_table != NULL) {
		knot_xquic_table_sweep(ctx->quic_table, &ctx->quic_closed);
		log_closed(&ctx->quic_closed, false);
	}
#endif // ENABLE_QUIC

	if (!ctx->tcp) {
		return;
	}

	int ret = KNOT_EOK;
	uint32_t prev_total;
	knot_tcp_relay_t sweep_relays[XDP_BATCHLEN];
	do {
		knot_xdp_send_prepare(ctx->sock);

		prev_total = ctx->tcp_closed.total;

		ret = knot_tcp_sweep(ctx->tcp_table, ctx->tcp_idle_close, ctx->tcp_idle_reset,
		                     ctx->tcp_idle_resend,
		                     ctx->tcp_max_conns, ctx->tcp_max_inbufs, ctx->tcp_max_obufs,
		                     sweep_relays, XDP_BATCHLEN, &ctx->tcp_closed);
		if (ret == KNOT_EOK) {
			ret = knot_tcp_send(ctx->sock, sweep_relays, XDP_BATCHLEN, XDP_BATCHLEN);
		}
		knot_tcp_cleanup(ctx->tcp_table, sweep_relays, XDP_BATCHLEN);
		if (ret != KNOT_EOK) {
			break;
		}

		ret = knot_tcp_sweep(ctx->syn_table, UINT32_MAX, ctx->tcp_idle_reset,
		                     UINT32_MAX, ctx->tcp_syn_conns, SIZE_MAX, SIZE_MAX,
		                     sweep_relays, XDP_BATCHLEN, &ctx->tcp_closed);
		if (ret == KNOT_EOK) {
			ret = knot_tcp_send(ctx->sock, sweep_relays, XDP_BATCHLEN, XDP_BATCHLEN);
		}
		knot_tcp_cleanup(ctx->syn_table, sweep_relays, XDP_BATCHLEN);

		(void)knot_xdp_send_finish(ctx->sock);
	} while (ret == KNOT_EOK && prev_total < ctx->tcp_closed.total);

	log_closed(&ctx->tcp_closed, true);
}

#endif // ENABLE_XDP
