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

#pragma once

#include "contrib/dynarray.h"
#include "libknot/xdp/msg.h"
#include "libknot/xdp/xdp.h"

typedef enum {
	XDP_TCP_NOOP      = 0,
	XDP_TCP_ESTABLISH = 1,
	XDP_TCP_DATA      = (1 << 2),
	XDP_TCP_CLOSE     = 2,
	XDP_TCP_RESET     = 3,
	XDP_TCP_ANSWER    = (1 << 3),
} knot_tcp_action_t;

typedef struct {
	const knot_xdp_msg_t *msg;
	knot_tcp_action_t action;
	knot_tcp_action_t answer;
	struct iovec data;
} knot_tcp_relay_t;

dynarray_declare(tcprelay, knot_tcp_relay_t, DYNARRAY_VISIBILITY_PUBLIC, 10)

/*!
 * \brief Process received packets, send ACKs, pick incomming data.
 *
 * \param msgs      Packets received by knot_xdp_recv().
 * \param n_msgs    Their count.
 * \param socket    XDP socket to answer through.
 * \param relays    Output: connection changes and data.
 *
 * \return KNOT_E*
 */
int knot_xdp_tcp_relay(knot_xdp_msg_t *msgs, size_t n_msgs,
                       knot_xdp_socket_t *socket, tcprelay_dynarray_t *relays);

/*!
 * \brief Send TCp packets.
 *
 * \param socket    XDP socket to send through.
 * \param relays    Connection changes and data.
 *
 * \return KNOT_E*
 */
int knot_xdp_tcp_send(knot_xdp_socket_t *socket, tcprelay_dynarray_t *relays);
