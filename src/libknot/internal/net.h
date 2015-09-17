/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
/*!
 * \file net.h
 *
 * \author Marek Vavrusa <marek.vavusa@nic.cz>
 *
 * \brief Generic sockets APIs.
 *
 * This file provides higher-level API for creating connections and listeners.
 *
 * \addtogroup network
 * @{
 */

#pragma once

#include <stdbool.h>

#include "libknot/internal/sockaddr.h"

/*!
 * \brief Network interface flags.
 */
enum net_flags {
	NET_BIND_NONLOCAL = (1 << 0), //!< Allow to bind unavailable address.
	NET_BIND_MULTIPLE = (1 << 1), //!< Allow to bind address multiple times.
};

/*!
 * \brief Create unbound socket of given family and type.
 *
 * \param type  Socket transport type (SOCK_STREAM, SOCK_DGRAM).
 * \param ss    Socket address storage.
 *
 * \return socket or error code
 */
int net_unbound_socket(int type, const struct sockaddr_storage *ss);

/*!
 * \brief Create socket bound to given address.
 *
 * \param type   Socket transport type (SOCK_STREAM, SOCK_DGRAM).
 * \param ss     Socket address storage.
 * \param flags  Allow binding to non-local address with NET_BIND_NONLOCAL.
 *
 * \return socket or error code
 */
int net_bound_socket(int type, const struct sockaddr_storage *ss,
                     enum net_flags flags);

/*!
 * \brief Create socket connected (asynchronously) to destination address.
 *
 * \param type     Socket transport type (SOCK_STREAM, SOCK_DGRAM).
 * \param dst_addr Destination address.
 * \param src_addr Source address (can be NULL).
 *
 * \note The socket will have O_NONBLOCK flag set.
 *
 * \return socket or error code
 */
int net_connected_socket(int type, const struct sockaddr_storage *dst_addr,
                         const struct sockaddr_storage *src_addr);

/*!
 * \brief Return true if the socket is connected.
 *
 * \note This could be used to identify connected TCP from UDP sockets.
 *
 * \param sock  Socket.
 *
 * \return true if connected
 */
bool net_is_connected(int sock);

/*!
 * \brief Send a UDP message over connected socket.
 *
 * \param fd Associated socket.
 * \param msg Buffer for a query wireformat.
 * \param msglen Buffer maximum size.
 * \param addr Destination address (or NULL if connected).
 *
 * \retval Number of sent data on success.
 * \retval KNOT_ERROR on error.
 */
int udp_send_msg(int fd, const uint8_t *msg, size_t msglen, const struct sockaddr *addr);

/*!
 * \brief Receive a UDP message from connected socket.
 *
 * \param fd Associated socket.
 * \param buf Buffer for incoming bytestream.
 * \param len Buffer maximum size.
 * \param timeout Message receive timeout.
 *
 * \retval Number of read bytes on success.
 * \retval KNOT_ERROR on error.
 * \retval KNOT_ENOMEM on potential buffer overflow.
 */
int udp_recv_msg(int fd, uint8_t *buf, size_t len, struct timeval *timeout);

/*!
 * \brief Send a TCP message.
 *
 * \param fd Associated socket.
 * \param msg Buffer for a query wireformat.
 * \param msglen Buffer maximum size.
 * \param timeout Message send timeout.
 *
 * \retval Number of sent data on success.
 * \retval KNOT_ERROR on error.
 */
int tcp_send_msg(int fd, const uint8_t *msg, size_t msglen, struct timeval *timeout);

/*!
 * \brief Receive a TCP message.
 *
 * \param fd Associated socket.
 * \param buf Buffer for incoming bytestream.
 * \param len Buffer maximum size.
 * \param timeout Message receive timeout.
 *
 * \retval Number of read bytes on success.
 * \retval KNOT_ERROR on error.
 * \retval KNOT_ENOMEM on potential buffer overflow.
 */
int tcp_recv_msg(int fd, uint8_t *buf, size_t len, struct timeval *timeout);

/*! @} */
