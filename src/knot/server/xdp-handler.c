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

#ifdef ENABLE_XDP

#include <assert.h>
#include <stdlib.h>
#include <urcu.h>

#include "knot/server/handler.h"
#include "knot/server/quic-handler.h"
#include "knot/server/xdp-handler.h"
#include "knot/common/log.h"
#include "knot/server/server.h"
#include "libknot/error.h"
#ifdef ENABLE_QUIC
#include "libknot/quic/quic.h"
#endif // ENABLE_QUIC
#include "libknot/xdp/tcp.h"
#include "libknot/xdp/tcp_iobuf.h"

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
	knot_quic_conn_t *quic_relays[XDP_BATCHLEN];
	knot_quic_reply_t quic_replies[XDP_BATCHLEN];
	knot_quic_table_t *quic_table;
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
	uint64_t quic_idle_close; // In nanoseconds.

	knot_sweep_stats_t tcp_closed;
} xdp_handle_ctx_t;

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
	ctx->quic_idle_close= pconf->cache.srv_quic_idle_close * 1000000000LU;
	rcu_read_unlock();
}

void xdp_handle_free(xdp_handle_ctx_t *ctx)
{
	// send RST on all existing conns
	knot_tcp_relay_t sweep_relays[XDP_BATCHLEN] = { 0 };
	int ret = KNOT_EOK;
	while (ret == KNOT_EOK && ctx->tcp_table != NULL && ctx->tcp_table->usage > 0) {
		knot_xdp_send_prepare(ctx->sock);
		ret = knot_tcp_sweep(ctx->tcp_table, UINT32_MAX, 1, UINT32_MAX, UINT32_MAX, SIZE_MAX,
		                     SIZE_MAX, sweep_relays, XDP_BATCHLEN, &ctx->tcp_closed);
		if (ret == KNOT_EOK) {
			ret = knot_tcp_send(ctx->sock, sweep_relays, XDP_BATCHLEN, XDP_BATCHLEN);
		}
		knot_tcp_cleanup(ctx->tcp_table, sweep_relays, XDP_BATCHLEN);
		(void)knot_xdp_send_finish(ctx->sock);
	}

	knot_tcp_table_free(ctx->tcp_table);
	knot_tcp_table_free(ctx->syn_table);
#ifdef ENABLE_QUIC
	quic_unmake_table(ctx->quic_table);
#endif // ENABLE_QUIC
	free(ctx);
}

#ifdef ENABLE_QUIC
static int quic_alloc_cb(knot_quic_reply_t *rpl)
{
	return knot_xdp_reply_alloc(rpl->sock, rpl->in_ctx, rpl->out_ctx);
}

static int quic_send_cb(knot_quic_reply_t *rpl)
{
	uint32_t sent = 0;
	knot_xdp_msg_t *msg = rpl->out_ctx;
	msg->ecn = rpl->ecn;
	return knot_xdp_send(rpl->sock, msg, 1, &sent);
}

static void quic_free_cb(knot_quic_reply_t *rpl)
{
	knot_xdp_send_free(rpl->sock, rpl->out_ctx, 1);
}
#endif // ENABLE_QUIC

xdp_handle_ctx_t *xdp_handle_init(server_t *server, knot_xdp_socket_t *xdp_sock)
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
		ctx->quic_table = quic_make_table(server);
		if (ctx->quic_table == NULL) {
			xdp_handle_free(ctx);
			return NULL;
		}
		for (int i = 0; i < XDP_BATCHLEN; i++) {
			knot_quic_reply_t *reply = &ctx->quic_replies[i];
			reply->sock = xdp_sock;
			reply->alloc_reply = quic_alloc_cb;
			reply->send_reply = quic_send_cb;
			reply->free_reply = quic_free_cb;
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
			if (log_enabled_debug()) {
				log_debug("UDP/XDP, failed to allocate a buffer");
			}
			break; // Drop the rest of the messages.
		}
		ctx->msg_udp_count++;

		// Prepare a reply.
		params_xdp_update(params, KNOTD_QUERY_PROTO_UDP, msg_recv, 0, NULL);
		handle_udp_reply(params, layer, &msg_recv->payload, &msg_send->payload,
		                 &proxied_remote);
	}
}

static void handle_tcp(xdp_handle_ctx_t *ctx, knot_layer_t *layer,
                       knotd_qdata_params_t *params)
{
	int ret = knot_tcp_recv(ctx->relays, ctx->msg_recv, ctx->msg_recv_count,
	                        ctx->tcp_table, ctx->syn_table, XDP_TCP_IGNORE_NONE);
	if (ret != KNOT_EOK) {
		if (log_enabled_debug()) {
			log_debug("TCP/XDP, failed to process some packets (%s)", knot_strerror(ret));
		}
		return;
	} else if (knot_tcp_relay_empty(&ctx->relays[0])) { // no TCP traffic
		return;
	}

	uint8_t ans_buf[KNOT_WIRE_MAX_PKTSIZE];

	for (uint32_t i = 0; i < ctx->msg_recv_count; i++) {
		knot_tcp_relay_t *rl = &ctx->relays[i];

		// Process all complete DNS queries in one TCP stream.
		for (size_t j = 0; rl->inbf != NULL && j < rl->inbf->n_inbufs; j++) {
			// Consume the query.
			params_xdp_update(params, KNOTD_QUERY_PROTO_TCP, ctx->msg_recv,
			                  rl->conn->establish_rtt, NULL);
			struct iovec *inbufs = rl->inbf->inbufs;
			handle_query(params, layer, &inbufs[j], NULL);

			// Process the reply.
			knot_pkt_t *ans = knot_pkt_new(ans_buf, sizeof(ans_buf), layer->mm);
			while (active_state(layer->state)) {
				knot_layer_produce(layer, ans);
				if (!send_state(layer->state)) {
					continue;
				}

				(void)knot_tcp_reply_data(rl, ctx->tcp_table, false,
				                          ans->wire, ans->size);
			}

			handle_finish(layer);
		}
	}
}

static void handle_quic(xdp_handle_ctx_t *ctx, knot_layer_t *layer,
                        knotd_qdata_params_t *params)
{
#ifdef ENABLE_QUIC
	if (ctx->quic_table == NULL) {
		return;
	}

	for (uint32_t i = 0; i < ctx->msg_recv_count; i++) {
		knot_xdp_msg_t *msg_recv = &ctx->msg_recv[i];
		ctx->quic_relays[i] = NULL;

		if ((msg_recv->flags & KNOT_XDP_MSG_TCP) ||
		    msg_recv->ip_to.sin6_port != ctx->quic_port ||
		    msg_recv->payload.iov_len == 0) {
			continue;
		}

		knot_quic_reply_t *reply = &ctx->quic_replies[i];
		knot_xdp_msg_t *msg_out = &ctx->msg_send_udp[i];

		reply->ip_rem = (struct sockaddr_storage *)&msg_recv->ip_from;
		reply->ip_loc = (struct sockaddr_storage *)&msg_recv->ip_to;
		reply->in_payload = &msg_recv->payload;
		reply->out_payload = &msg_out->payload;
		reply->in_ctx = msg_recv;
		reply->out_ctx = msg_out;
		reply->ecn = msg_recv->ecn;

		(void)knot_quic_handle(ctx->quic_table, reply, ctx->quic_idle_close,
		                       &ctx->quic_relays[i]);
		knot_quic_conn_t *conn = ctx->quic_relays[i];

		handle_quic_streams(conn, params, layer, &ctx->msg_recv[i]);
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

	knotd_qdata_params_t params = params_xdp_init(
		knot_xdp_socket_fd(ctx->sock), server, thread_id);

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
	if (ret != KNOT_EOK && log_enabled_debug()) {
		log_debug("UDP/XDP, failed to send some packets");
	}
	if (ctx->tcp) {
		ret = knot_tcp_send(ctx->sock, ctx->relays, ctx->msg_recv_count,
		                    XDP_BATCHLEN);
		if (ret != KNOT_EOK && log_enabled_debug()) {
			log_debug("TCP/XDP, failed to send some packets");
		}
	}
#ifdef ENABLE_QUIC
	for (uint32_t i = 0; i < ctx->msg_recv_count; i++) {
		if (ctx->quic_relays[i] == NULL) {
			continue;
		}

		ret = knot_quic_send(ctx->quic_table, ctx->quic_relays[i],
		                     &ctx->quic_replies[i], QUIC_MAX_SEND_PER_RECV, 0);
		if (ret != KNOT_EOK && log_enabled_debug()) {
			log_debug("QUIC/XDP, failed to send some packets");
		}
	}
	knot_quic_cleanup(ctx->quic_relays, ctx->msg_recv_count);
#endif // ENABLE_QUIC

	(void)knot_xdp_send_finish(ctx->sock);

	if (ctx->tcp) {
		knot_tcp_cleanup(ctx->tcp_table, ctx->relays, ctx->msg_recv_count);
	}
}

void xdp_handle_sweep(xdp_handle_ctx_t *ctx)
{
#ifdef ENABLE_QUIC
	knot_quic_table_sweep(ctx->quic_table, NULL, &ctx->quic_closed);
	log_swept(&ctx->quic_closed, false);
	quic_reconfigure_table(ctx->quic_table);
#endif // ENABLE_QUIC

	if (!ctx->tcp) {
		return;
	}

	int ret = KNOT_EOK;
	uint32_t prev_total;
	knot_tcp_relay_t sweep_relays[XDP_BATCHLEN] = { 0 };
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

	log_swept(&ctx->tcp_closed, true);
}

#endif // ENABLE_XDP
