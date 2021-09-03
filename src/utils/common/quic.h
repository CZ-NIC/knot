/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <ngtcp2/ngtcp2.h>

#include "utils/common/tls.h"

/*! \brief QUIC parameters. */
typedef struct {
	/*! Use QUIC indicator. */
	bool enable;
} quic_params_t;

typedef struct {
	tls_ctx_t *tls;
	/*! ngtcp2 (QUIC) setting. */
	ngtcp2_settings settings;
	ngtcp2_path path;
	/*! client secret */
	uint8_t static_secret[32];
	/*! Stream context */
	struct {
		int64_t stream_id;
		uint8_t *data;
		size_t datalen;
		size_t nwrite;
	} stream;
	uint64_t last_error;
	/*! QUIC parameters. */
	const quic_params_t *params;
	/*! QUIC state. */
	ngtcp2_conn *conn;
} quic_ctx_t;

int quic_ctx_init(quic_ctx_t *ctx, tls_ctx_t *tls_ctx, const quic_params_t *params);

int quic_ctx_connect(quic_ctx_t *ctx, int sockfd, const char *remote, struct sockaddr_storage *dst_addr);

int quic_send_dns_query(quic_ctx_t *ctx, int sockfd, struct addrinfo *srv, const uint8_t *buf, const size_t buf_len);