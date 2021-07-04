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

#include "knot/server/xdp-handler.h"

#include "contrib/ucw/mempool.h"
#include "knot/common/log.h"
#include "knot/server/server.h"
#include "libknot/error.h"
#include "libknot/xdp/tcp.h"

#include <stdlib.h>
#include <urcu.h>

#define XDP_BATCHLEN      32 // TODO move/dedup

#ifdef ENABLE_XDP

typedef struct xdp_handle_ctx {
	knot_xdp_msg_t msg_recv[XDP_BATCHLEN];
	knot_xdp_msg_t msg_send_udp[XDP_BATCHLEN];
	knot_tcp_relay_dynarray_t tcp_relays;
	uint32_t msg_recv_count;
	uint32_t msg_udp_count;
	knot_tcp_table_t *tcp_table;

	uint32_t tcp_max_conns;
	size_t tcp_inbufs_size;
	uint32_t tcp_idle_close;
	uint32_t tcp_idle_reset;
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
	ctx->tcp_max_conns   = pconf->cache.xdp_tcp_max_conns / pconf->cache.srv_xdp_threads;
	ctx->tcp_inbufs_size = pconf->cache.xdp_tcp_inbufs_size / pconf->cache.srv_xdp_threads;
	ctx->tcp_idle_close  = pconf->cache.xdp_tcp_idle_close * 1000000; // conf:secs -> tcp:usecs
	ctx->tcp_idle_reset  = pconf->cache.xdp_tcp_idle_reset * 1000000;
	rcu_read_unlock();
}

void xdp_handle_cleanup(xdp_handle_ctx_t *ctx)
{
	ctx->msg_recv_count = 0;
	ctx->msg_udp_count = 0;
}

void xdp_handle_free(xdp_handle_ctx_t *ctx)
{
	xdp_handle_cleanup(ctx);
	knot_tcp_table_free(ctx->tcp_table);
	free(ctx);
}

xdp_handle_ctx_t *xdp_handle_init(void)
{
	xdp_handle_ctx_t *ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		return NULL;
	}

	xdp_handle_cleanup(ctx);
	xdp_handle_reconfigure(ctx);

	ctx->tcp_table = knot_tcp_table_new(ctx->tcp_max_conns); // NOTE: it's not necessary that the table size is equal to its max usage!
	if (ctx->tcp_table == NULL) {
		xdp_handle_free(ctx);
		return NULL;
	}

	return ctx;
}

int xdp_handle_recv(xdp_handle_ctx_t *ctx, knot_xdp_socket_t *xdp_sock)
{
	xdp_handle_cleanup(ctx);
	int ret = knot_xdp_recv(xdp_sock, ctx->msg_recv, sizeof(ctx->msg_recv) / sizeof(ctx->msg_recv[0]),
	                        &ctx->msg_recv_count, NULL);
	return ret == KNOT_EOK ? ctx->msg_recv_count : ret;
}

static void handle_init(knotd_qdata_params_t *params, knot_layer_t *layer, const knot_xdp_msg_t *msg, const struct iovec *payload)
{
	params->remote = (struct sockaddr_storage *)&msg->ip_from;
	params->xdp_msg = msg;
	if (!(msg->flags & KNOT_XDP_MSG_TCP)) {
		params->flags = KNOTD_QUERY_FLAG_NO_AXFR | KNOTD_QUERY_FLAG_NO_IXFR | KNOTD_QUERY_FLAG_LIMIT_SIZE;
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
	mp_flush(layer->mm->ctx);
}

int xdp_handle_msgs(xdp_handle_ctx_t *ctx, knot_xdp_socket_t *sock,
                    knot_layer_t *layer, server_t *server, unsigned thread_id)
{
	knotd_qdata_params_t params = {
		.socket = knot_xdp_socket_fd(sock),
		.server = server,
		.thread_id = thread_id,
	};

	if (ctx->msg_recv_count > 0) {
		knot_xdp_send_prepare(sock);
	}

	// handle UDP messages
	for (uint32_t i = 0; i < ctx->msg_recv_count; i++) {
		knot_xdp_msg_t *msg_recv = &ctx->msg_recv[i];
		knot_xdp_msg_t *msg_send = &ctx->msg_send_udp[ctx->msg_udp_count];

		if ((msg_recv->flags & KNOT_XDP_MSG_TCP) ||
		    msg_recv->payload.iov_len == 0) {
			continue;
		}

		if (knot_xdp_reply_alloc(sock, msg_recv, msg_send) != KNOT_EOK) {
			continue; // no point in returning error, where handled?
		}
		ctx->msg_udp_count++;

		handle_init(&params, layer, msg_recv, &msg_recv->payload);

		knot_pkt_t *ans = knot_pkt_new(msg_send->payload.iov_base, msg_send->payload.iov_len, layer->mm);
		while (udp_state_active(layer->state)) {
			knot_layer_produce(layer, ans);
		}
		if (layer->state == KNOT_STATE_DONE) {
			msg_send->payload.iov_len = ans->size;
		} else {
			msg_send->payload.iov_len = 0;
		}

		handle_finish(layer);
	}

	// handle TCP messages
	int ret = knot_xdp_tcp_relay(sock, ctx->msg_recv, ctx->msg_recv_count, ctx->tcp_table, NULL, &ctx->tcp_relays);
	if (ret == KNOT_EOK && ctx->tcp_relays.size > 0) {
		uint8_t ans_buf[KNOT_WIRE_MAX_PKTSIZE];

		for (size_t n_tcp_relays = ctx->tcp_relays.size, rli = 0; rli < n_tcp_relays; rli++) { // dynaaray_foreach can't be used because we insert into the dynarray inside the loop
			knot_tcp_relay_t *rl = knot_tcp_relay_dynarray_arr(&ctx->tcp_relays) + rli;
			if ((rl->action & XDP_TCP_DATA) && (rl->answer == 0)) {
				knot_pkt_t *ans = knot_pkt_new(ans_buf, sizeof(ans_buf), layer->mm);
				handle_init(&params, layer, rl->msg, &rl->data);

				while (tcp_active_state(layer->state)) {
					knot_layer_produce(layer, ans);
					if (!tcp_send_state(layer->state)) {
						continue;
					}

					ret = knot_xdp_tcp_send_data(&ctx->tcp_relays, rl, ans->wire, ans->size);
					if (ret != KNOT_EOK) {
						layer->state = KNOT_STATE_FAIL;
					}
				}
				handle_finish(layer);
			}
		}
	}
	knot_xdp_recv_finish(sock, ctx->msg_recv, ctx->msg_recv_count);

	return KNOT_EOK;
}

size_t overweight(size_t weight, size_t max_weight)
{
	int64_t w = weight;
	w -= max_weight;
	w = MAX(w, 0);
	return w;
}

int xdp_handle_send(xdp_handle_ctx_t *ctx, knot_xdp_socket_t *xdp_sock)
{
	uint32_t unused = 0;

	int ret = knot_xdp_send(xdp_sock, ctx->msg_send_udp, ctx->msg_udp_count, &unused);
	if (ret == KNOT_EOK) {
		if (ctx->tcp_relays.size > 0) {
			ret = knot_xdp_tcp_send(xdp_sock, knot_tcp_relay_dynarray_arr(&ctx->tcp_relays), ctx->tcp_relays.size);
		} else {
			ret = knot_xdp_send_finish(xdp_sock);
		}
	}

	knot_xdp_tcp_relay_free(&ctx->tcp_relays);

	if (ret == KNOT_EOK) {
		ret = xdp_handle_timeout(ctx, xdp_sock);
	}

	return ret;
}

int xdp_handle_timeout(xdp_handle_ctx_t *ctx, knot_xdp_socket_t *xdp_sock)
{
	uint32_t last_reset = 0, last_close = 0;
	int ret = KNOT_EOK;
	do {
		ret = knot_xdp_tcp_timeout(ctx->tcp_table, xdp_sock, 20, ctx->tcp_idle_close, ctx->tcp_idle_reset,
		                           overweight(ctx->tcp_table->usage, ctx->tcp_max_conns),
		                           overweight(ctx->tcp_table->inbufs_total, ctx->tcp_inbufs_size),
		                           &last_close, &last_reset);
	} while (last_reset > 0 && ret == KNOT_EOK);

	if (last_close > 0 || last_reset > 0) {
		log_debug("timeouted XDP-TCP connections: %u closed, %u reset", last_close, last_reset);
	}
	return ret;
}

#endif // ENABLE_XDP
