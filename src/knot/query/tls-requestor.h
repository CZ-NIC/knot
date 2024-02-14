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

typedef struct {
	struct knot_tls_ctx *ctx;
	struct knot_tls_conn *conn;
} knot_tls_req_ctx_t;

struct knot_quic_creds;

int knot_tls_req_ctx_init(knot_tls_req_ctx_t *ctx, int fd,
                          const struct knot_quic_creds *local_creds,
                          const uint8_t *peer_pin, uint8_t peer_pin_len,
                          int io_timeout_ms);

void knot_tls_req_ctx_deinit(knot_tls_req_ctx_t *ctx);
