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
 * \param table    QUIC connection table.
 * \param stats    Statistics to be updated.
 */
void quic_sweep_table(knot_quic_table_t *table, knot_sweep_stats_t *stats);

/*!
 * \brief Deallocate QUIC connecton table.
 *
 * \param table    QUIC connection table.
 */
void quic_unmake_table(knot_quic_table_t *table);
