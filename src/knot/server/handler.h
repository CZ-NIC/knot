/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
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

#ifdef ENABLE_QUIC
inline static void params_update_quic(knotd_qdata_params_t *params,
                                      knot_quic_conn_t *conn)
{
	params->quic_conn = conn;
	if (conn->flags & KNOT_QUIC_CONN_AUTHORIZED) {
		params->flags |= KNOTD_QUERY_FLAG_AUTHORIZED;
	}
}

inline static void params_update_quic_stream(knotd_qdata_params_t *params,
                                             int64_t stream_id)
{
	params->quic_stream = stream_id;
	params->measured_rtt = knot_quic_conn_rtt(params->quic_conn);
}
#endif // ENABLE_QUIC

inline static void params_update_tls(knotd_qdata_params_t *params,
                                     knot_tls_conn_t *conn)
{
	params->tls_conn = conn;
	if (params->tls_conn->flags & KNOT_TLS_CONN_AUTHORIZED) {
		params->flags |= KNOTD_QUERY_FLAG_AUTHORIZED;
	}
}

#ifdef ENABLE_XDP
inline static void params_update_tcp(knotd_qdata_params_t *params,
                                     knot_tcp_conn_t *conn)
{
	params->measured_rtt = conn->establish_rtt;
	if (conn->flags & KNOT_TCP_CONN_AUTHORIZED) {
		params->flags |= KNOTD_QUERY_FLAG_AUTHORIZED;
	}
}

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
