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

/*!
 * \file
 *
 * \brief Pure TLS functionality.
 *
 * \addtogroup quic
 * @{
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

struct gnutls_priority_st;

typedef enum {
	KNOT_TLS_CONN_HANDSHAKE_DONE = (1 << 0),
	KNOT_TLS_CONN_SESSION_TAKEN  = (1 << 1), // unused, to be implemeted later
	KNOT_TLS_CONN_BLOCKED        = (1 << 2),
} knot_tls_conn_flag_t;

typedef struct knot_tls_ctx {
	struct knot_creds *creds;
	struct gnutls_priority_st *priority;
	unsigned handshake_timeout;
	unsigned io_timeout;
	bool server;
} knot_tls_ctx_t;

typedef struct knot_tls_conn {
	struct gnutls_session_int *session;
	struct knot_tls_ctx *ctx;
	int fd;
	unsigned fd_clones_count;
	knot_tls_conn_flag_t flags;
} knot_tls_conn_t;

/*!
 * \brief Initialize DoT answering context.
 *
 * \param creds       Certificate credentials.
 * \param io_timeout  Connections' IO-timeout (in milliseconds).
 * \param hs_timeout  Handshake timeout (in milliseconds).
 * \param server      Server context (otherwise client).
 *
 * \return Initialized context or NULL.
 */
knot_tls_ctx_t *knot_tls_ctx_new(struct knot_creds *creds, unsigned io_timeout,
                                 unsigned hs_timeout, bool server);

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
 * \brief Check if session ticket can be taken out of this connection.
 */
bool knot_tls_session_available(knot_tls_conn_t *conn);

/*!
 * \brief Gets data needed for session resumption.
 *
 * \param conn   TLS connection.
 *
 * \return TLS session context.
 */
struct knot_tls_session *knot_tls_session_save(knot_tls_conn_t *conn);

/*!
 * \brief Loads data needed for session resumption.
 *
 * \param conn     TLS connection.
 * \param session  TLS session context.
 *
 * \return KNOT_E*
 */
int knot_tls_session_load(knot_tls_conn_t *conn, struct knot_tls_session *session);

/*!
 * \brief Perform the TLS handshake (via gnutls_handshake()).
 *
 * \note This is also done by the recv/send functions.
 *
 * \param conn     DoT connection.
 * \param oneshot  If set, don't wait untill the handshake is finished.
 *
 * \retval KNOT_EOK           Handshake successfully finished.
 * \retval KNOT_EGAIN         Handshake not finished, call me again.
 * \retval KNOT_NET_EHSHAKE   Handshake error.
 * \retval KNOT_NET_ECONNECT  Socket not connected.
 */
int knot_tls_handshake(knot_tls_conn_t *conn, bool oneshot);

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

/*!
 * \brief Set or unset the conection's BLOCKED flag.
 */
void knot_tls_conn_block(knot_tls_conn_t *conn, bool block);

/*! @} */
