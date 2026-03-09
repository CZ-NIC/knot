/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "knot/include/module.h"
#include "knot/query/layer.h"
#include "libknot/quic/quic_conn.h"
#include "libknot/xdp/tcp_iobuf.h"

struct server;

/*!
 * \brief Handle a received QUIC packet.
 *
 * \not It may also send back some additional packets.
 *
 * \param params        Query params.
 * \param layer         Query processing layer.
 * \param idle_close    QUIC policy when to close idel connections, in nanoseconds.
 * \param table         QUIC connection table.
 * \param rx            Incoming packet payload.
 * \param mh_out        Msghdr for outgoing packets.
 * \param p_ecn         Pointer on in/out ECN in cmsg header.
 */
void quic_handler(knotd_qdata_params_t *params, knot_layer_t *layer,
                  uint64_t idle_close, knot_quic_table_t *table,
                  struct iovec *rx, struct msghdr *mh_out, int *p_ecn);

/*!
 * \brief Allocate QUIC connection table.
 *
 * \param server    Server.
 *
 * \return QUIC connection table, or NULL.
 */
knot_quic_table_t *quic_make_table(struct server *server);

/*!
 * \brief Change QUIC configuration while running.
 *
 * \param table   QUIC connection table.
 */
void quic_reconfigure_table(knot_quic_table_t *table);

/*!
 * \brief Sweep idle or excessive QUIC connections.
 *
 * \note This function cannot be used with XDP.
 *
 * \param table    QUIC connection table.
 * \param stats    Statistics to be updated.
 * \param fd       Standard socket descriptor to send sweep replies through.
 */
void quic_sweep_table(knot_quic_table_t *table, knot_sweep_stats_t *stats, int fd);

/*!
 * \brief Deallocate QUIC connecton table.
 *
 * \param table    QUIC connection table.
 */
void quic_unmake_table(knot_quic_table_t *table);
