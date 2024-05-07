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

#include <stdint.h>

#include "libknot/quic/tls_common.h"

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
 * \param local_creds       Local TLS credentials.
 * \param peer_pin          TLS peer pin.
 * \param peer_pin_len      TLS peer pin length.
 * \param io_timeout_ms     Configured io-timeout for TLS connection.
 *
 * \return KNOT_E*
 */
int knot_tls_req_ctx_init(knot_tls_req_ctx_t *ctx, int fd,
                          const struct knot_creds *local_creds,
                          const uint8_t *peer_pin, uint8_t peer_pin_len,
                          int io_timeout_ms);

/*!
 * \brief De-initialize TLS requestor context.
 */
void knot_tls_req_ctx_deinit(knot_tls_req_ctx_t *ctx);
