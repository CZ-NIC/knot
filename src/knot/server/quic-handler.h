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

struct server;
struct knot_sweep_stats;

/*!
 * \brief Handle a received QUIC packet.
 *
 * \not It may also send back some additional packets.
 *
 * \param params        Query params.
 * \param layer         Query processing layer.
 * \param idle_close    QUIC policy when to close idel connections, in nanoseconds.
 * \param quic_table    QUIC connection table.
 * \param mh_out        Msghdr for potential outgoing packets.
 * \param rx            Incoming packet payload.
 * \param tx            Buffer for outgoing packet payload.
 */
void quic_handler(knotd_qdata_params_t *params, knot_layer_t *layer,
                  uint64_t idle_close, void *quic_table, struct msghdr *mh_out,
                  struct iovec *rx, struct iovec *tx);

/*!
 * \brief Sweep idle or excessive QUIC connections.
 *
 * \param quic_ctx       QUIC connection table.
 * \param quic_closed    Statistics to be updated.
 */
void quic_sweep(void *quic_ctx, struct knot_sweep_stats *quic_closed);

/*!
 * \brief Allocate QUIC connection table.
 *
 * \param server    Server.
 *
 * \return QUIC connection table, or NULL.
 */
void *quic_make_table(struct server *server);

/*!
 * \brief Deallocate QUIC connecton table.
 *
 * \param table    QUIC connection table.
 */
void quic_unmake_table(void *table);
