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
#include <sys/types.h>

typedef struct knot_tls_ctx {
	const struct knot_quic_creds *creds;

	unsigned handshake_timeout_ms;
	unsigned io_timeout_ms;
	unsigned idle_timeout_ms;

	bool server;
} knot_tls_ctx_t;

typedef struct knot_tls_conn {
	struct gnutls_session_int *session;
	bool handshake_done;
	int fd;
	int timeout;
} knot_tls_conn_t;

knot_tls_ctx_t *knot_tls_ctx_new(const struct knot_quic_creds *creds,
                                 bool server,
                                 unsigned handshake_timeout_ms,
                                 unsigned io_timeout_ms,
                                 unsigned idle_timeout_ms);

void knot_tls_ctx_free(knot_tls_ctx_t *ctx);

knot_tls_conn_t *knot_tls_conn_new(knot_tls_ctx_t *ctx, int sock_fd);

void knot_tls_conn_del(knot_tls_conn_t *conn);

int knot_tls_handshake(knot_tls_conn_t *conn);

ssize_t knot_tls_recv(knot_tls_conn_t *conn, void *data, size_t size);

ssize_t knot_tls_send(knot_tls_conn_t *conn, void *data, size_t size);

ssize_t knot_tls_recv_dns(knot_tls_conn_t *conn, void *data, size_t size);

ssize_t knot_tls_send_dns(knot_tls_conn_t *conn, void *data, size_t size);
