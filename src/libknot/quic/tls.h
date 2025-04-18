/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
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

#include <libknot/quic/tls_common.h>

struct gnutls_priority_st;

typedef enum {
	KNOT_TLS_CONN_HANDSHAKE_DONE = (1 << 0),
	KNOT_TLS_CONN_SESSION_TAKEN  = (1 << 1), // unused, to be implemeted later
	KNOT_TLS_CONN_BLOCKED        = (1 << 2),
	KNOT_TLS_CONN_AUTHORIZED     = (1 << 3),
} knot_tls_conn_flag_t;

typedef struct knot_tls_ctx {
	struct knot_creds *creds;
	struct gnutls_priority_st *priority;
	knot_tls_flag_t flags;
	unsigned handshake_timeout;
	unsigned io_timeout;
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
 * \param flags       Specify client/server mode and common/dns format.
 *
 * \return Initialized context or NULL.
 */
knot_tls_ctx_t *knot_tls_ctx_new(struct knot_creds *creds, unsigned io_timeout,
                                 unsigned hs_timeout, knot_tls_flag_t flags);

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
 * \brief Receive a data blob.
 *
 * \note In the DNS mode, the two-byte-size prefix is stripped upon reception,
 *       not stored to the buffer.
 *
 * \param conn      DoT connection.
 * \param data      Destination buffer.
 * \param size      Maximum buffer size.
 *
 * \return Either the DNS message size received or negative error code.
 */
ssize_t knot_tls_recv(knot_tls_conn_t *conn, void *data, size_t size);

/*!
 * \brief Send a data blob.
 *
 * \note In the DNS mode, the two-byte-size prefix is sended before the data
 *       blob itself.
 *
 * \param conn      DoT connection.
 * \param data      DNS payload.
 * \param size      Payload size.
 *
 * \return Either exactly 'size' or a negative error code.
 */
ssize_t knot_tls_send(knot_tls_conn_t *conn, void *data, size_t size);

/*!
 * \brief Set or unset the conection's BLOCKED flag.
 */
void knot_tls_conn_block(knot_tls_conn_t *conn, bool block);

/*! @} */
