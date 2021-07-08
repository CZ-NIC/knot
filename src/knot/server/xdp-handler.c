/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include "knot/server/server.h"
#include "contrib/sockaddr.h"
#include "contrib/ucw/mempool.h"
#include "libknot/error.h"
#include "libknot/xdp/tcp.h"

typedef struct xdp_handle_ctx {
	knot_xdp_socket_t *sock;
	knot_xdp_msg_t msg_recv[XDP_BATCHLEN];
	knot_xdp_msg_t msg_send_udp[XDP_BATCHLEN];
	knot_tcp_relay_dynarray_t tcp_relays;
	uint32_t msg_recv_count;
	uint32_t msg_udp_count;
	knot_tcp_table_t *tcp_table;

	bool tcp;
	size_t tcp_max_conns;
	size_t tcp_max_inbufs;
	uint32_t tcp_idle_close; // In microseconds.
	uint32_t tcp_idle_reset; // In microseconds.
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

void xdp_handle_reconfigure(xdp_handle_ctx_t *ctx)
{
	rcu_read_lock();
	conf_t *pconf = conf();
	ctx->tcp            = pconf->cache.xdp_tcp;
	ctx->tcp_max_conns  = pconf->cache.xdp_tcp_max_clients    / pconf->cache.srv_xdp_threads;
	ctx->tcp_max_inbufs = pconf->cache.xdp_tcp_inbuf_max_size / pconf->cache.srv_xdp_threads;
	ctx->tcp_idle_close = pconf->cache.xdp_tcp_idle_close * 1000000;
	ctx->tcp_idle_reset = pconf->cache.xdp_tcp_idle_reset * 1000000;
	rcu_read_unlock();
}

void xdp_handle_free(xdp_handle_ctx_t *ctx)
{
	knot_tcp_table_free(ctx->tcp_table);
	free(ctx);
}

xdp_handle_ctx_t *xdp_handle_init(knot_xdp_socket_t *xdp_sock)
{
	xdp_handle_ctx_t *ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		return NULL;
	}
	ctx->sock = xdp_sock;

	xdp_handle_reconfigure(ctx);

	if (ctx->tcp) {
		// NOTE: the table size don't have to equal its max usage!
		ctx->tcp_table = knot_tcp_table_new(ctx->tcp_max_conns);
		if (ctx->tcp_table == NULL) {
			xdp_handle_free(ctx);
			return NULL;
		}
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
                        const knot_xdp_msg_t *msg, const struct iovec *payload)
{
	params->remote = (struct sockaddr_storage *)&msg->ip_from;
	params->xdp_msg = msg;
	if (!(msg->flags & KNOT_XDP_MSG_TCP)) {
		params->flags = KNOTD_QUERY_FLAG_NO_AXFR |
		                KNOTD_QUERY_FLAG_NO_IXFR |
		                KNOTD_QUERY_FLAG_LIMIT_SIZE;
	}

	knot_layer_begin(layer, params);

	knot_pkt_t *query = knot_pkt_new(payload->iov_base, payload->iov_len, layer->mm);
	int ret = knot_pkt_parse(query, 0);
	if (ret != KNOT_EOK && query->parsed > 0) { // parsing failed (e.g. 2x OPT)
		query->parsed--; // artificially decreasing "parsed" leads to FORMERR
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
	ctx->msg_udp_count = 0;

	for (uint32_t i = 0; i < ctx->msg_recv_count; i++) {
		knot_xdp_msg_t *msg_recv = &ctx->msg_recv[i];
		knot_xdp_msg_t *msg_send = &ctx->msg_send_udp[ctx->msg_udp_count];

		// Skip TCP or marked (zero length) message.
		if ((msg_recv->flags & KNOT_XDP_MSG_TCP) ||
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
		handle_init(params, layer, msg_recv, &msg_recv->payload);

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
	uint32_t ack_errors = 0;
	int ret = knot_tcp_relay(ctx->sock, ctx->msg_recv, ctx->msg_recv_count,
	                         ctx->tcp_table, NULL, &ctx->tcp_relays, &ack_errors);
	if (ret != KNOT_EOK) {
		log_notice("TCP, failed to process some packets (%s)", knot_strerror(ret));
		return;
	} else if (ctx->tcp_relays.size == 0) {
		return;
	} else if (ack_errors > 0) {
		log_notice("TCP, failed to send some ACK packets");
	}

	uint8_t ans_buf[KNOT_WIRE_MAX_PKTSIZE];

	// Note dynaray_foreach can't be used as we insert into the dynarray inside the loop.
	for (int n_tcp_relays = ctx->tcp_relays.size, rli = 0; rli < n_tcp_relays; rli++) {
		knot_tcp_relay_t *rl = knot_tcp_relay_dynarray_arr(&ctx->tcp_relays) + rli;
		if ((rl->action & XDP_TCP_DATA) == 0 || rl->answer != XDP_TCP_NOOP) {
			continue;
		}

		// Consume the query.
		handle_init(params, layer, rl->msg, &rl->data);

		// Process the reply.
		knot_pkt_t *ans = knot_pkt_new(ans_buf, sizeof(ans_buf), layer->mm);
		while (tcp_active_state(layer->state)) {
			knot_layer_produce(layer, ans);
			if (!tcp_send_state(layer->state)) {
				continue;
			}

			ret = knot_tcp_relay_answer(&ctx->tcp_relays, rl,
			                            ans->wire, ans->size);
			if (ret != KNOT_EOK) {
				char addr[SOCKADDR_STRLEN];
				sockaddr_tostr(addr, sizeof(addr), params->remote);
				log_notice("TCP, failed to reply, address %s (%s)",
				           addr, knot_strerror(ret));
				layer->state = KNOT_STATE_FAIL;
			}
		}

		handle_finish(layer);
	}
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

	knot_xdp_recv_finish(ctx->sock, ctx->msg_recv, ctx->msg_recv_count);
}

void xdp_handle_send(xdp_handle_ctx_t *ctx)
{
	uint32_t unused;
	(void)knot_xdp_send(ctx->sock, ctx->msg_send_udp, ctx->msg_udp_count, &unused);
	if (ctx->tcp) {
		int ret = knot_tcp_send(ctx->sock, knot_tcp_relay_dynarray_arr(&ctx->tcp_relays),
		                        ctx->tcp_relays.size);
		if (ret != KNOT_EOK) {
			log_notice("TCP, failed to send some packets");
		}
	}
	(void)knot_xdp_send_finish(ctx->sock);

	if (ctx->tcp) {
		knot_tcp_relay_free(&ctx->tcp_relays);
	}
}

static size_t overweight(size_t weight, size_t max_weight)
{
	int64_t w = weight;
	w -= max_weight;
	w = MAX(w, 0);
	return w;
}

void xdp_handle_sweep(xdp_handle_ctx_t *ctx)
{
	if (!ctx->tcp) {
		return;
	}

	uint32_t prev_reset;
	uint32_t total_reset = 0, total_close = 0;
	int ret = KNOT_EOK;
	do {
		prev_reset = total_reset;
		ret = knot_tcp_sweep(ctx->tcp_table, ctx->sock, 20,
		                     ctx->tcp_idle_close, ctx->tcp_idle_reset,
		                     overweight(ctx->tcp_table->usage, ctx->tcp_max_conns),
		                     overweight(ctx->tcp_table->inbufs_total, ctx->tcp_max_inbufs),
		                     &total_close, &total_reset);
	} while (ret == KNOT_EOK && prev_reset < total_reset);

	if (total_close > 0 || total_reset > 0) {
		log_notice("TCP, connection timeout, %u closed, %u reset",
		           total_close, total_reset);
	}
}

#endif // ENABLE_XDP
