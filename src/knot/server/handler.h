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

#pragma once

#include "knot/include/module.h"
#include "knot/query/layer.h"
#include "knot/server/server.h"
#include "libknot/xdp/tcp_iobuf.h"
#include "libknot/quic/tls.h"

#ifdef ENABLE_QUIC
#include "libknot/quic/quic.h"
#endif // ENABLE_QUIC

#ifdef ENABLE_XDP
#include "libknot/xdp.h"
#endif // ENABLE_XDP

#define QUIC_MAX_SEND_PER_RECV	4
#define QUIC_IBUFS_PER_CONN	512 /* Heuristic value: this means that e.g. for 100k allowed
				       QUIC conns, we will limit total size of input buffers to 50 MiB. */

inline static knotd_qdata_params_t params_init(knotd_query_proto_t proto,
                                               const void *remote, const void *local,
                                               int sock, server_t *server,
                                               unsigned thread_id)

{
	knotd_qdata_params_t params = {
		.proto = proto,
		.remote = (const struct sockaddr_storage *)remote,
		.local = (const struct sockaddr_storage *)local,
		.socket = sock,
		.thread_id = thread_id,
		.server = server,
		.quic_stream = -1,
	};

	return params;
}

inline static void params_update_tcp(knotd_qdata_params_t *params, uint32_t rtt)
{
	params->measured_rtt = rtt;
}

#ifdef ENABLE_QUIC
inline static void params_update_quic(knotd_qdata_params_t *params, uint32_t rtt,
                                      knot_quic_conn_t *conn, int64_t stream_id)
{
	params->quic_conn = conn;
	params->quic_stream = stream_id;
	params->measured_rtt = rtt;
}
#endif // ENABLE_QUIC

inline static void params_update_tls(knotd_qdata_params_t *params,
                                     knot_tls_conn_t *conn)
{
	params->tls_conn = conn;
}

#ifdef ENABLE_XDP
inline static knotd_qdata_params_t params_xdp_init(int sock, server_t *server,
                                                   unsigned thread_id)
{
	knotd_qdata_params_t params = {
		.socket = sock,
		.thread_id = thread_id,
		.server = server,
		.quic_stream = -1,
	};

	return params;
}

inline static void params_xdp_update(knotd_qdata_params_t *params,
                                     knotd_query_proto_t proto,
                                     struct knot_xdp_msg *msg)
{
	params->proto = proto;
	params->remote = (struct sockaddr_storage *)&msg->ip_from;
	params->local = (struct sockaddr_storage *)&msg->ip_to;
	params->xdp_msg = msg;
}
#endif // ENABLE_XDP

inline static bool active_state(int state)
{
	return (state == KNOT_STATE_PRODUCE || state == KNOT_STATE_FAIL);
}

inline static bool send_state(int state)
{
	return (state != KNOT_STATE_FAIL && state != KNOT_STATE_NOOP);
}

void handle_query(knotd_qdata_params_t *params, knot_layer_t *layer,
                  const struct iovec *payload, struct sockaddr_storage *proxied_remote);

void handle_finish(knot_layer_t *layer);

void handle_udp_reply(knotd_qdata_params_t *params, knot_layer_t *layer,
                      struct iovec *rx, struct iovec *tx,
                      struct sockaddr_storage *proxied_remote);

#ifdef ENABLE_QUIC
void handle_quic_streams(knot_quic_conn_t *conn, knotd_qdata_params_t *params,
                         knot_layer_t *layer);
#endif // ENABLE_QUIC

void log_swept(knot_sweep_stats_t *stats, bool tcp);
