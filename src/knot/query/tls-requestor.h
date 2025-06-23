/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include <stdint.h>
#include <sys/socket.h>

#include "knot/conf/conf.h"
#include "libknot/quic/tls_common.h"

struct knot_request;

/*!
 * \brief TLS requestor context envelope, containing TLS general context and TLS connection.
 */
typedef struct knot_tls_req_ctx {
	struct knot_tls_ctx *ctx;
	struct knot_tls_conn *conn;
} knot_tls_req_ctx_t;

/*!
 * \brief Initialize TLS requestor context.
 *
 * \param ctx               Context structure to be initialized.
 * \param fd                Opened TCP connection file descriptor.
 * \param remote            Remote address for purposes of TLS session resumption.
 * \param local             Local address for purposes of TLS session resumption.
 * \param local_creds       Local TLS credentials.
 * \param peer_hostnames    Permittable TLS peer hostnames.
 * \param peer_pins         Permittable TLS peer PINs.
 * \param reused_fd[out]    Indicates successful TLS session resumption.
 * \param io_timeout_ms     Configured io-timeout for TLS connection.
 *
 * \return KNOT_E*
 */
int knot_tls_req_ctx_init(knot_tls_req_ctx_t *ctx,
                          int fd,
                          const struct sockaddr_storage *remote,
                          const struct sockaddr_storage *local,
                          const struct knot_creds *local_creds,
                          const char *const peer_hostnames[RMT_MAX_PINS],
                          const uint8_t *const peer_pins[RMT_MAX_PINS],
                          bool *reused_fd,
                          int io_timeout_ms);

/*!
 * \brief Maintain the TLS requestor context (update session ticket).
 *
 * \param ctx     Context structure to be initialized.
 * \param r       Context of the request.
 */
void knot_tls_req_ctx_maint(knot_tls_req_ctx_t *ctx, struct knot_request *r);

/*!
 * \brief De-initialize TLS requestor context.
 */
void knot_tls_req_ctx_deinit(knot_tls_req_ctx_t *ctx);
