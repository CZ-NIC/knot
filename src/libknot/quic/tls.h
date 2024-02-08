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

typedef struct {
	struct knot_quic_creds *creds;

	unsigned handshake_timeout_ms;
	unsigned io_timeout_ms;
	unsigned idle_timeout_ms;
} knot_tls_ctx_t;

typedef struct {
	struct gnutls_session_int *session;
} knot_tls_conn_t;

knot_tls_ctx_t *knot_tls_ctx_new(struct knot_quic_creds *creds,
                                 unsigned handshake_timeout_ms,
                                 unsigned io_timeout_ms,
                                 unsigned idle_timeout_ms);

void knot_tls_ctx_free();

knot_tls_conn_t *knot_tls_conn_new(knot_tls_ctx_t *ctx, int sock_fd, bool server);

void knot_tls_conn_close();
