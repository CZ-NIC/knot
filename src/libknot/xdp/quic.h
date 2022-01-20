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

#include <stdint.h>

#include "contrib/libngtcp2/ngtcp2/ngtcp2.h"
#include "contrib/libngtcp2/ngtcp2/ngtcp2_crypto.h"
#include "contrib/libngtcp2/ngtcp2/ngtcp2_crypto_gnutls.h"

#include "libknot/xdp/xdp.h"

typedef struct knot_xquic_conn {
	struct {
		struct knot_xquic_conn *list_node_next;
		struct knot_xquic_conn *list_node_prev;
	} list_node_placeholder;
	struct sockaddr_in6 ip_rem;
	struct sockaddr_in6 ip_loc;
	uint8_t last_eth_rem[ETH_ALEN];
	uint8_t last_eth_loc[ETH_ALEN];

	ngtcp2_conn *conn;
	ngtcp2_cid cid;

	struct iovec rx_query; // TODO ?
	struct iovec tx_query; // TODO ?

	struct knot_xquic_conn *next;

	struct knot_xquic_table *xquic_table; // TODO ?
} knot_xquic_conn_t;

typedef struct knot_xquic_table {
	size_t size;
	size_t usage;
	uint64_t hash_secret[4];
	knot_xquic_conn_t *conns[];
} knot_xquic_table_t;

/*!
 * \brief Process received packets, pic incomming DNS data.
 *
 * \param relays        Out: affected QUIC connections.
 * \param msgs          Incomming packets.
 * \param count         Number of incomming packets.
 * \param quic_table    Connection table.
 *
 * \return KNOT_E*
 */
int knot_xquic_recv(knot_xquic_conn_t **relays, knot_xdp_msg_t *msgs,
                    uint32_t count, knot_xquic_table_t *quic_table);


int knot_xquic_send(knot_xdp_socket_t *sock, knot_xquic_conn_t *relay);
