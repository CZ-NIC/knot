/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>

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
 * \note The socket is set to non-blocking mode.
 *
 * \param type  Socket transport type (SOCK_STREAM, SOCK_DGRAM).
 * \param sa    Socket address.
 *
 * \return socket or error code
 */
int net_unbound_socket(int type, const struct sockaddr *sa);

/*!
 * \brief Create socket bound to given address.
 *
 * The socket is set to non-blocking mode.
 *
 * \param type   Socket transport type (SOCK_STREAM, SOCK_DGRAM).
 * \param sa     Socket address.
 * \param flags  Socket binding options.
 *
 * \return socket or error code
 */
int net_bound_socket(int type, const struct sockaddr *sa, enum net_flags flags);

/*!
 * \brief Create socket connected (asynchronously) to destination address.
 *
 * \note The socket is set to non-blocking mode.
 *
 * \param type      Socket transport type (SOCK_STREAM, SOCK_DGRAM).
 * \param dst_addr  Destination address.
 * \param src_addr  Source address (can be NULL).
 *
 * \return socket or error code
 */
int net_connected_socket(int type, const struct sockaddr *dst_addr,
                         const struct sockaddr *src_addr);

/*!
 * \brief Return true if the socket is fully connected.
 *
 * \param sock  Socket.
 *
 * \return true if connected
 */
bool net_is_connected(int sock);

/*!
 * \brief Get socket type (e.g. \a SOCK_STREAM).
 *
 * \param sock  Socket.
 */
int net_socktype(int sock);

/*!
 * \brief Check if socket is a SOCK_STREAM socket.
 */
bool net_is_stream(int sock);

/*!
 * \brief Accept a connection on a listening socket.
 *
 * \brief The socket is set to non-blocking mode.
 *
 * \param sock  Socket
 * \param addr  Remote address (can be NULL).
 *
 * \return socket or error code
 */
int net_accept(int sock, struct sockaddr_storage *addr);

/*!
 * \brief Send a message on a socket.
 *
 * The socket can be SOCK_STREAM or SOCK_DGRAM.
 *
 * The implementation handles partial-writes automatically.
 *
 * \param[in] sock        Socket.
 * \param[in] buffer      Message buffer.
 * \param[in] size        Size of the message.
 * \param[in] addr        Remote address (ignored for SOCK_STREAM).
 * \param[in] timeout_ms  Write timeout in miliseconds (-1 for infinity,
 *                        not valid for SOCK_DGRAM).
 *
 * \return Number of bytes sent or negative error code.
 */
ssize_t net_base_send(int sock, const uint8_t *buffer, size_t size,
                      const struct sockaddr *addr, int timeout_ms);

/*!
 * \brief Receive a message from a socket.
 *
 * \param[in]  sock        Socket.
 * \param[out] buffer      Receiving buffer.
 * \param[in]  size        Capacity of the receiving buffer.
 * \param[out] addr        Remote address (can be NULL).
 * \param[in]  timeout_ms  Read timeout in miliseconds (-1 for infinity).
 *
 * \return Number of bytes read or negative error code.
 */
ssize_t net_base_recv(int sock, uint8_t *buffer, size_t size,
                      struct sockaddr_storage *addr, int timeout_ms);

/*!
 * \brief Send a message on a SOCK_DGRAM socket.
 *
 * \see net_base_send
 */
ssize_t net_dgram_send(int sock, const uint8_t *buffer, size_t size,
                       const struct sockaddr *addr);

/*!
 * \brief Receive a message from a SOCK_DGRAM socket.
 *
 * \see net_base_recv
 */
ssize_t net_dgram_recv(int sock, uint8_t *buffer, size_t size, int timeout_ms);

/*!
 * \brief Send a message on a SOCK_STREAM socket.
 *
 * \see net_base_send
 */
ssize_t net_stream_send(int sock, const uint8_t *buffer, size_t size, int timeout_ms);

/*!
 * \brief Receive a message from a SOCK_STREAM socket.
 *
 * \see net_base_recv
 */
ssize_t net_stream_recv(int sock, uint8_t *buffer, size_t size, int timeout_ms);

/*!
 * \brief Send a DNS message on a TCP socket.
 *
 * The outgoing message is prefixed with a two-byte value carrying the DNS
 * message size according to the specification. These two bytes are not
 * reflected in the return value.
 *
 * \see net_base_send
 */
ssize_t net_dns_tcp_send(int sock, const uint8_t *buffer, size_t size, int timeout_ms);

/*!
 * \brief Receive a DNS message from a TCP socket.
 *
 * The first two bytes of the incoming message are interpreted as a DNS message
 * size according to the specification. These two bytes are not included in
 * the returned size. Only a complete DNS message is retrieved.
 *
 * \see net_base_recv
 */
ssize_t net_dns_tcp_recv(int sock, uint8_t *buffer, size_t size, int timeout_ms);
