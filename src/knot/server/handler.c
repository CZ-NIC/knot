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

#include "knot/server/handler.h"

#include "contrib/string.h"
#include "contrib/openbsd/strlcat.h"
#include "contrib/time.h"
#include "contrib/ucw/mempool.h"
#include "knot/common/log.h"
#include "knot/server/proxyv2.h"

void handle_query(knotd_qdata_params_t *params, knot_layer_t *layer,
                  const struct iovec *payload, struct sockaddr_storage *proxied_remote)
{
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

void handle_finish(knot_layer_t *layer)
{
	knot_layer_finish(layer);

	// Flush per-query memory (including query and answer packets).
	mp_flush(layer->mm->ctx);
}

void handle_udp_reply(knotd_qdata_params_t *params, knot_layer_t *layer,
                      struct iovec *rx, struct iovec *tx,
                      struct sockaddr_storage *proxied_remote)
{
	handle_query(params, layer, rx, proxied_remote);

	knot_pkt_t *ans = knot_pkt_new(tx->iov_base, tx->iov_len, layer->mm);

	while (active_state(layer->state)) {
		knot_layer_produce(layer, ans);
	}

	// Send response only if finished successfully.
	if (layer->state == KNOT_STATE_DONE) {
		tx->iov_len = ans->size;
	} else {
		tx->iov_len = 0;
	}

	handle_finish(layer);
}

#ifdef ENABLE_QUIC
static void handle_quic_stream(knot_quic_conn_t *conn, int64_t stream_id, struct iovec *inbuf,
                               knot_layer_t *layer, knotd_qdata_params_t *params, uint8_t *ans_buf,
                               size_t ans_buf_size)
{
	// Consume the query.
	handle_query(params, layer, inbuf, NULL);

	// Process the reply.
	knot_pkt_t *ans = knot_pkt_new(ans_buf, ans_buf_size, layer->mm);
	while (active_state(layer->state)) {
		knot_layer_produce(layer, ans);
		if (!send_state(layer->state)) {
			continue;
		}
		if (knot_quic_stream_add_data(conn, stream_id, ans->wire, ans->size) == NULL) {
			break;
		}
	}

	handle_finish(layer);

	// Store the qdata params AUTH flag to the connection.
	if (params->flags & KNOTD_QUERY_FLAG_AUTHORIZED) {
		conn->flags |= KNOT_QUIC_CONN_AUTHORIZED;
	} else {
		conn->flags &= ~KNOT_QUIC_CONN_AUTHORIZED;
	}
}

void handle_quic_streams(knot_quic_conn_t *conn, knotd_qdata_params_t *params,
                         knot_layer_t *layer)
{
	uint8_t ans_buf[KNOT_WIRE_MAX_PKTSIZE];

	params_update_quic(params, conn);

	int64_t stream_id;
	knot_quic_stream_t *stream;
	while (conn != NULL && (stream = knot_quic_stream_get_process(conn, &stream_id)) != NULL) {
		assert(stream->inbufs != NULL);
		assert(stream->inbufs->n_inbufs > 0);
		struct iovec *inbufs = stream->inbufs->inbufs;
		params_update_quic_stream(params, stream_id);
		// NOTE: only the first msg in the stream is used, the rest is dropped.
		handle_quic_stream(conn, stream_id, &inbufs[0], layer, params,
		                   ans_buf, sizeof(ans_buf));
		while (stream->inbufs != NULL) {
			knot_tcp_inbufs_upd_res_t *tofree = stream->inbufs;
			stream->inbufs = tofree->next;
			free(tofree);
		}
	}
}
#endif // ENABLE_QUIC

void log_swept(knot_sweep_stats_t *stats, bool tcp)
{
	struct timespec now = time_now();
	uint64_t sec = now.tv_sec + now.tv_nsec / 1000000000;
	if (sec - stats->last_log <= 9 || (stats->total == 0)) {
		return;
	}

	const char *proto = tcp ? "TCP" : "QUIC";

	struct desc {
		knot_sweep_counter_t idx;
		const char *name;
	};
	const struct desc descs[] = {
		{ KNOT_SWEEP_CTR_TIMEOUT, "inactive" },
		{ KNOT_SWEEP_CTR_LIMIT_CONN, "count limit" },
		{ KNOT_SWEEP_CTR_LIMIT_IBUF, "inbuf limit" },
		{ KNOT_SWEEP_CTR_LIMIT_OBUF, "outbuf limit" },
		{ KNOT_SWEEP_CTR_TIMEOUT_RST, "reset timeout" },
		{ 0, NULL },
	};

	uint32_t inactive = stats->counters[KNOT_SWEEP_CTR_TIMEOUT];
	if (tcp || stats->total != inactive) {
		char buf[256] = "terminated connections";
		for (const struct desc *d = descs; d->name != NULL; d++) {
			if (stats->counters[d->idx] == 0) {
				continue;
			}
			char *item = sprintf_alloc(", %s %u", d->name, stats->counters[d->idx]);
			if (item != NULL) {
				strlcat(buf, item, sizeof(buf));
				free(item);
			}
		}
		log_notice("%s, %s", proto, buf);
	} else {
		log_debug("%s, terminated inactive connections %u", proto, inactive);
	}

	knot_sweep_stats_reset(stats);
	stats->last_log = sec;
}
