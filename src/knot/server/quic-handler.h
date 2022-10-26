/*  Copyright (C) 2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
 * \brief Handle a QUIC packet received by recv(m)msg.
 *
 * \not It may also send back some addiitonal packets with sendmsg.
 *
 * \param params        Query params.
 * \param layer         Query processing layer.
 * \param idle_close    QUIC policy when to close idel connections, in nanoseconds.
 * \param quic_table    QUIC connection table.
 * \param mh_in         Msghdr of incoming packet.
 * \param mh_out        Msghdr for potential outgoing packets.
 * \param rx            Incoming packet payload.
 * \param tx            Buffer for outgoing packet payload.
 */
void udp_quic_handle(knotd_qdata_params_t *params, knot_layer_t *layer, uint64_t idle_close,
                     void *quic_table, struct msghdr *mh_in, struct msghdr *mh_out,
                     struct iovec *rx, struct iovec *tx);

/*!
 * \brief Sweep idle or excessive QUIC connections.
 *
 * \param quic_ctx       Pointer at QUIC connection table.
 * \param quic_closed    Statistics to be updated.
 */
void udp_quic_handle_sweep(void *quic_ctx, struct knot_sweep_stats *quic_closed);

/*!
 * \brief Allocate QUIC connection table.
 *
 * \param server    Server.
 *
 * \return QUIC connection table, or NULL.
 */
void *udp_quic_make_table(struct server *server);

/*!
 * \brief Deallocate QUIC connecton table.
 */
void udp_quic_unmake_table(void *table);
