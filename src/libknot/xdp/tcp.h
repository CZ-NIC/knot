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

#include "libknot/dynarray.h"
#include "libknot/xdp/msg.h"
#include "libknot/xdp/xdp.h"

typedef enum {
	XDP_TCP_NOOP      = 0,
	XDP_TCP_SYN       = 1,
	XDP_TCP_ESTABLISH = 2,
	XDP_TCP_CLOSE     = 3,
	XDP_TCP_RESET     = 4,
	XDP_TCP_RESEND    = 5,

	XDP_TCP_FREE      = 0x10,
} knot_tcp_action_t;

typedef enum {
	XDP_TCP_NORMAL,
	XDP_TCP_ESTABLISHING,
	XDP_TCP_CLOSING1, // FIN+ACK sent
	XDP_TCP_CLOSING2, // FIND+ACK received and sent
} knot_tcp_state_t;

typedef enum {
	XDP_TCP_FREE_NONE,
	XDP_TCP_FREE_DATA,
	XDP_TCP_FREE_PREFIX,
} knot_tcp_relay_free_t;

typedef struct tcp_outbufs {
	struct tcp_outbuf *bufs;
} tcp_outbufs_t; // this typedef belongs to tcp_iobuf.h, but is here to avoid issues with symbols

typedef struct knot_tcp_conn {
	struct {
		void *list_node_placeholder1;
		void *list_node_placeholder2;
	} list_node_placeholder;
	struct sockaddr_in6 ip_rem;
	struct sockaddr_in6 ip_loc;
	uint8_t last_eth_rem[ETH_ALEN];
	uint8_t last_eth_loc[ETH_ALEN];
	uint16_t mss;
	uint8_t window_scale;
	uint32_t seqno;
	uint32_t ackno;
	uint32_t acked;
	uint32_t window_size;
	uint32_t last_active;
	uint32_t establish_rtt;
	knot_tcp_state_t state;
	struct iovec inbuf;
	tcp_outbufs_t outbufs;
	struct knot_tcp_conn *next;
} knot_tcp_conn_t;

typedef struct {
	size_t size;
	size_t usage;
	size_t inbufs_total;
	size_t outbufs_total;
	uint64_t hash_secret[2];
	knot_tcp_conn_t *conns[];
} knot_tcp_table_t;

typedef struct {
	const knot_xdp_msg_t *msg;
	knot_tcp_action_t action;
	knot_xdp_msg_flag_t auto_answer;
	uint32_t auto_seqno;
	knot_tcp_action_t answer;
	struct iovec *inbufs;
	size_t inbufs_count;
	knot_tcp_conn_t *conn;
} knot_tcp_relay_t;

/*!
 * \brief Return next TCP sequence number.
 */
inline static uint32_t knot_tcp_next_seqno(const knot_xdp_msg_t *msg)
{
	uint32_t res = msg->seqno + msg->payload.iov_len;
	if (msg->flags & (KNOT_XDP_MSG_SYN | KNOT_XDP_MSG_FIN)) {
		res++;
	}
	return res;
}

inline static bool knot_tcp_relay_empty(const knot_tcp_relay_t *r)
{
	return r->action == XDP_TCP_NOOP && r->auto_answer == 0 && r->inbufs_count == 0;
}

/*!
 * \brief Allocate TCP connection-handling hash table.
 *
 * \param size           Number of records for the hash table.
 * \param secret_share   Optional: share the hashing secret with another table.
 *
 * \note Hashing conflicts are solved by single-linked-lists in each record.
 *
 * \return The table, or NULL.
 */
knot_tcp_table_t *knot_tcp_table_new(size_t size, knot_tcp_table_t *secret_share);

/*!
 * \brief Free TCP connection hash table including all connection records.
 *
 * \note The freed connections are not closed nor reset.
 */
void knot_tcp_table_free(knot_tcp_table_t *table);

/*!
 * \brief Process received packets, prepare automatick responses (e.g. ACK), pick incoming data.
 *
 * \param relays      Out: relays to be filled with message/connection details.
 * \param msgs        Packets received by knot_xdp_recv();
 * \param count       Number of received packets.
 * \param tcp_table   Table of TCP connections.
 * \param syn_table   Optional: extra table for handling partially established connections.
 *
 * \return KNOT_E*
 */
int knot_tcp_recv(knot_tcp_relay_t *relays, knot_xdp_msg_t *msgs, uint32_t count,
                  knot_tcp_table_t *tcp_table, knot_tcp_table_t *syn_table);

/*!
 * \brief Prepare data (payload) to be sent as a response on specific relay.
 *
 * \param relay       Relay with active connection.
 * \param tcp_table   TCP table.
 * \param data        Data payload, possibly > MSS and > window.
 * \param len         Payload length, < 64k.
 *
 * \return KNOT_E*
 */
int knot_tcp_reply_data(knot_tcp_relay_t *relay, knot_tcp_table_t *tcp_table,
                        uint8_t *data, size_t len);

/*!
 * \brief Send TCP packets.
 *
 * \param socket       XDP socket to send through.
 * \param relays       Connection changes and data.
 * \param relay_count  Number of connection changes and data.
 * \param max_at_once  Limit of packet batch sent by knot_xdp_send().
 *
 * \return KNOT_E*
 */
int knot_tcp_send(knot_xdp_socket_t *socket, knot_tcp_relay_t relays[], uint32_t relay_count,
                  uint32_t max_at_once);

/*!
 * \brief Cleanup old TCP connections, perform timeout checks.
 *
 * \param tcp_table        TCP connection table to clean up.
 * \param close_timeout    Gracefully close connections older than this (usecs).
 * \param reset_timeout    Reset connections older than this (usecs).
 * \param limit_n_conn     Limit of active connections in TCP table, reset if more.
 * \param limit_ibuf_size  Limit of memory usage by input buffers, reset if exceeded.
 * \param limit_obuf_size  Limit of memory usage by output buffers, reset if exceeded.
 * \param relays           Out: relays to be filled with close/reset instructions for knot_tcp_send().
 * \param max_relays       Maximum relays to be used.
 * \param close_count      Out: number of connection closed.
 * \param reset_count      Out: number of connections reset.
 *
 * \return KNOT_E*
 */
int knot_tcp_sweep(knot_tcp_table_t *tcp_table,
                   uint32_t close_timeout, uint32_t reset_timeout,
                   uint32_t resend_timeout, uint32_t limit_n_conn,
                   size_t limit_ibuf_size, size_t limit_obuf_size,
                   knot_tcp_relay_t *relays, size_t max_relays,
                   uint32_t *close_count, uint32_t *reset_count);

/*!
 * \brief Free resources of closed/reset connections.
 *
 * \param tcp_table    TCP table with connections.
 * \param relays       Relays with closed/resettted (or other, ignored) connections.
 * \param n_relays     Number of relays.
 */
void knot_tcp_cleanup(knot_tcp_table_t *tcp_table, knot_tcp_relay_t *relays, size_t n_relays);

/*! @} */
