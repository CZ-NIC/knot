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

/*! \brief QUIC parameters. */
typedef struct {
	/*! Use QUIC indicator. */
	bool enable;
} quic_params_t;

uint64_t quic_timestamp(void);

size_t quic_setup_alpn(gnutls_datum_t *dest, size_t maxlen, const char *in);

int quic_params_copy(quic_params_t *dst, const quic_params_t *src);

void quic_params_clean(quic_params_t *params);

#ifdef LIBNGTCP2

#include <ngtcp2/ngtcp2.h>

#include "utils/common/tls.h"

typedef struct {
	// Parameters
	quic_params_t params;

	// Context
	tls_ctx_t *tls;
	/*! ngtcp2 (QUIC) setting. */
	ngtcp2_settings settings;
	/*! Stream context */
	struct {
		int64_t stream_id;
		uint8_t *tx_data;
		size_t tx_datalen;
		size_t nwrite;
		uint8_t *rx_data;
		size_t rx_datalen;
		size_t nread;
		uint16_t resp_size;
	} stream;
	uint64_t last_error;
	ngtcp2_conn *conn;
	uint8_t secret[32];
	bool opened_stream;
} quic_ctx_t;

int quic_ctx_init(quic_ctx_t *ctx, tls_ctx_t *tls_ctx,
        const quic_params_t *params);

int quic_ctx_connect(quic_ctx_t *ctx, int sockfd, const char *remote,
        struct addrinfo *dst_addr);

int quic_send_dns_query(quic_ctx_t *ctx, int sockfd, struct addrinfo *srv,
        const uint8_t *buf, const size_t buf_len);

int quic_recv_dns_response(quic_ctx_t *ctx, uint8_t *buf, const size_t buf_len,
        struct addrinfo *srv, int timeout_ms);

void quic_ctx_close(quic_ctx_t *ctx);

void quic_ctx_deinit(quic_ctx_t *ctx);

#endif
