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

/*!
 * \file
 *
 * \brief TCP over XDP IO interface.
 *
 * \addtogroup xdp
 * @{
 */

#pragma once

#include "contrib/dynarray.h"
#include "contrib/ucw/lists.h"
#include "libknot/mm_ctx.h"
#include "libknot/xdp/msg.h"
#include "libknot/xdp/xdp.h"

typedef enum {
	XDP_TCP_NOOP      = 0,
	XDP_TCP_SYN       = 1,
	XDP_TCP_ESTABLISH = 2,
	XDP_TCP_CLOSE     = 3,
	XDP_TCP_RESET     = 4,
	XDP_TCP_DATA      = (1 << 3),
	XDP_TCP_ANSWER    = (1 << 4),
} knot_tcp_action_t;

typedef enum {
	XDP_TCP_NORMAL,
	XDP_TCP_ESTABLISHING,
	XDP_TCP_CLOSING,
} knot_tcp_state_t;

typedef enum {
	XDP_TCP_FREE_NONE,
	XDP_TCP_FREE_DATA,
	XDP_TCP_FREE_PREFIX,
} knot_tcp_relay_free_t;

typedef struct knot_xdp_tcp_conn {
	node_t n;
	struct sockaddr_in6 ip_rem;
	struct sockaddr_in6 ip_loc;
	uint8_t last_eth_rem[ETH_ALEN];
	uint8_t last_eth_loc[ETH_ALEN];
	uint32_t seqno;
	uint32_t ackno;
	uint32_t acked;
	uint32_t last_active;
	knot_tcp_state_t state;
	struct iovec inbuf;
	struct knot_xdp_tcp_conn *next;
} knot_tcp_conn_t;

typedef struct {
	size_t size;
	list_t timeout;
	size_t usage;
	uint32_t hash_secret[4];
	knot_tcp_conn_t *conns[];
} knot_tcp_table_t;

typedef struct {
	const knot_xdp_msg_t *msg;
	knot_tcp_action_t action;
	knot_tcp_action_t answer;
	struct iovec data;
	knot_tcp_relay_free_t free_data;
	knot_tcp_conn_t *conn;
} knot_tcp_relay_t;

#define TCP_RELAY_DEFAULT_COUNT 10

dynarray_declare(tcp_relay, knot_tcp_relay_t, DYNARRAY_VISIBILITY_PUBLIC, TCP_RELAY_DEFAULT_COUNT)

inline static uint32_t knot_tcp_next_seqno(const knot_xdp_msg_t *msg)
{
	uint32_t res = msg->seqno + msg->payload.iov_len;
	if (msg->flags & (KNOT_XDP_MSG_SYN | KNOT_XDP_MSG_FIN)) {
		res++;
	}
	return res;
}

/*!
 * \brief Allocate TCP connection-handling hash table.
 *
 * \param size   Number of records for the hash table.
 *
 * \note Hashing conflicts are solved by single-linked-lists in each record.
 *
 * \return The table, or NULL.
 */
knot_tcp_table_t *knot_tcp_table_new(size_t size);

/*!
 * \brief Free TCP connection hash table including all connection records.
 *
 * \note The freed connections are not closed nor resetted.
 */
void knot_tcp_table_free(knot_tcp_table_t *t);

/*!
 * \brief Process received packets, send ACKs, pick incoming data.
 *
 * \param socket       XDP socket to answer through.
 * \param msgs         Packets received by knot_xdp_recv().
 * \param msg_count    Number of received packets.
 * \param tcp_table    Table of TCP connections.
 * \param syn_table    Optional: extra table for handling partially established connections.
 * \param relays       Out: connection changes and data.
 * \param mm           Memory context.
 *
 * \return KNOT_E*
 */
int knot_xdp_tcp_relay(knot_xdp_socket_t *socket, knot_xdp_msg_t msgs[], uint32_t msg_count,
                       knot_tcp_table_t *tcp_table, knot_tcp_table_t *syn_table,
                       tcp_relay_dynarray_t *relays, knot_mm_t *mm);

/*!
 * \brief Free resources in 'relays'.
 */
void knot_xdp_tcp_relay_free(tcp_relay_dynarray_t *relays);

/*!
 * \brief Send TCP packets.
 *
 * \param socket       XDP socket to send through.
 * \param relays       Connection changes and data.
 * \param relay_count  Number of connection changes and data.
 *
 * \return KNOT_E*
 */
int knot_xdp_tcp_send(knot_xdp_socket_t *socket, knot_tcp_relay_t relays[],
                      uint32_t relay_count);

/*!
 * \brief Cleanup old TCP connections, perform timeout checks.
 *
 * \param tcp_table        TCP connection table to clean up.
 * \param socket           XDP socket for close messages.
 * \param max_at_once      Don't close more connections at once.
 * \param close_timeout    Gracefully close connections older than this (usecs).
 * \param reset_timeout    Reset connections older than this (usecs).
 * \param reset_at_least   Reset at least this number of oldest conecction, even when not yet timeouted.
 * \param reset_inbufs     Reset oldest connection with buffered partial DNS messages to free up this amount of space.
 * \param reset_count      Optional: Out: number of resetted connections.
 *
 * \return  KNOT_E*
 */
int knot_xdp_tcp_timeout(knot_tcp_table_t *tcp_table, knot_xdp_socket_t *socket,
                         uint32_t max_at_once,
                         uint32_t close_timeout, uint32_t reset_timeout,
                         uint32_t reset_at_least, size_t reset_inbufs,
                         uint32_t *reset_count);

/*!
 * \brief Cleanp old TCP connection w/o sending RST or FIN.
 *
 * \param tcp_table     TCP connection table tzo clean up.
 * \param timeout       Remove connections older than this (usecs).
 * \param at_least      Remove at least this number of connections.
 * \param cleaned       Optional: Out: number of removed connections.
 */
void knot_xdp_tcp_cleanup(knot_tcp_table_t *tcp_table, uint32_t timeout,
                          uint32_t at_least, uint32_t *cleaned);

/*! @} */
