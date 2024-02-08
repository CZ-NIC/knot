/*  Copyright (C) 2024 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <sys/types.h>

typedef struct knot_tls_ctx {
	struct knot_quic_creds *creds;

	unsigned handshake_timeout_ms;
	unsigned io_timeout_ms;

	bool server;
} knot_tls_ctx_t;

typedef struct knot_tls_conn {
	struct gnutls_session_int *session;
	struct knot_tls_ctx *ctx;
	bool handshake_done;
	int fd;
	int timeout;

	// TODO: debug statistics. Remove(?) once well-tuned.
	uint16_t conntag;
	size_t recv_count;
	size_t send_count;
	size_t err_count;
	ssize_t iofun_count;
	int last_err;
} knot_tls_conn_t;

/*!
 * \brief Initialize DoT answering context.
 *
 * \param creds           Certificate credentials.
 * \param server          Server context (otherwise client).
 * \param io_timeout_ms   Connections' IO-timeout.
 *
 * \return Initialized context or NULL.
 */
knot_tls_ctx_t *knot_tls_ctx_new(struct knot_quic_creds *creds,
                                 bool server,
                                 unsigned io_timeout_ms);

/*!
 * \brief Free DoT answering context.
 */
void knot_tls_ctx_free(knot_tls_ctx_t *ctx);

/*!
 * \brief Initialize DoT connection.
 *
 * \param ctx          DoT answering context.
 * \param sock_fd      Opened TCP connection socket.
 *
 * \return Connection struct or NULL.
 */
knot_tls_conn_t *knot_tls_conn_new(knot_tls_ctx_t *ctx, int sock_fd);

/*!
 * \brief Free DoT connection struct.
 *
 * \note Doesn't close the TCP connection socket.
 */
void knot_tls_conn_del(knot_tls_conn_t *conn);

/*!
 * \brief Perform the TLS handshake (via gnutls_handshake()).
 *
 * \note This is also done by the recv/send functions.
 */
int knot_tls_handshake(knot_tls_conn_t *conn);

/*!
 * \brief Receive data from a TLS connection.
 *
 * \param conn       DoT connection.
 * \param data       Destination buffer.
 * \param size       Amount to be received.
 *
 * \return Either exactly 'size' or a negative error code.
 */
ssize_t knot_tls_recv(knot_tls_conn_t *conn, void *data, size_t size);

/*!
 * \brief Send data to a TLS connection.
 *
 * \param conn       DoT connection.
 * \param data       The data.
 * \param size       Amount to be sent.
 *
 * \return Either exactly 'size' or a negative error code.
 */
ssize_t knot_tls_send(knot_tls_conn_t *conn, void *data, size_t size);

/*!
 * \brief Receive a size-word-prefixed DNS message.
 *
 * \param conn       DoT connection.
 * \param data       Destination buffer.
 * \param size       Maximum buffer size.
 *
 * \return Either the DNS message size received or negative error code.
 *
 * \note The two-byte-size-prefix is stripped upon reception, not stored to the buffer.
 */
ssize_t knot_tls_recv_dns(knot_tls_conn_t *conn, void *data, size_t size);

/*!
 * \brief Send a size-word-prefixed DNS message.
 *
 * \param conn      DoT connection.
 * \param data      DNS payload.
 * \param size      Payload size.
 *
 * \return Either exactly 'size' or a negative error code.
 */
ssize_t knot_tls_send_dns(knot_tls_conn_t *conn, void *data, size_t size);
