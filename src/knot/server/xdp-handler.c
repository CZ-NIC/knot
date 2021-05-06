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
#include "knot/server/server.h"
#include "libknot/error.h"
#include "libknot/xdp/tcp.h"

#include <stdlib.h>

#define XDP_BATCHLEN      32 // TODO move/dedup

#ifdef ENABLE_XDP

typedef struct xdp_handle_ctx {
	knot_xdp_msg_t msg_recv[XDP_BATCHLEN];
	knot_xdp_msg_t msg_send_udp[XDP_BATCHLEN];
	tcp_relay_dynarray_t tcp_relays;
	uint32_t msg_recv_count;
	uint32_t msg_udp_count;
	knot_tcp_table_t *tcp_table;
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

	ctx->tcp_table = knot_tcp_table_new(1000); // TODO better parametrize
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
	int ret = knot_xdp_tcp_relay(sock, ctx->msg_recv, ctx->msg_recv_count, ctx->tcp_table, NULL, &ctx->tcp_relays,
				     NULL); // TODO NULL
	if (ret == KNOT_EOK && ctx->tcp_relays.size > 0) {
		uint8_t ans_buf[1024]; // TODO 1024

		for (size_t n_tcp_relays = ctx->tcp_relays.size, rli = 0; rli < n_tcp_relays; rli++) { // dynaaray_foreach can't be used because we insert into the dynarray inside the loop
			knot_tcp_relay_t *rl = tcp_relay_dynarray_arr(&ctx->tcp_relays) + rli;
			if ((rl->action & XDP_TCP_DATA) && (rl->answer == 0)) {
				knot_pkt_t *ans = knot_pkt_new(ans_buf, sizeof(ans_buf), layer->mm);
				handle_init(&params, layer, rl->msg, &rl->data);

				while (tcp_active_state(layer->state)) {
					knot_layer_produce(layer, ans);

					knot_tcp_relay_t *clone;
					if (ans->size > 0 && tcp_send_state(layer->state) &&
					    (clone = tcp_relay_dynarray_add(&ctx->tcp_relays, rl)) != NULL &&
					    (clone->data.iov_base = malloc(ans->size)) != NULL) {
						clone->data.iov_len = ans->size;
						memcpy(clone->data.iov_base, ans->wire, ans->size);
						clone->answer = XDP_TCP_ANSWER | XDP_TCP_DATA;
						clone->free_data = XDP_TCP_FREE_DATA;
					}
				}
				handle_finish(layer);
			}
		}
	}
	knot_xdp_recv_finish(sock, ctx->msg_recv, ctx->msg_recv_count);

	return KNOT_EOK;
}

uint32_t overweight(uint32_t weight, uint32_t max_weight)
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
			ret = knot_xdp_tcp_send(xdp_sock, tcp_relay_dynarray_arr(&ctx->tcp_relays), ctx->tcp_relays.size);
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
	return knot_xdp_tcp_timeout(ctx->tcp_table, xdp_sock, 20, 2000000, 4000000, overweight(ctx->tcp_table->usage, 1000), 0, NULL); // FIXME configurable parameters
}

#endif // ENABLE_XDP
