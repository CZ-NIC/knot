/*  Copyright (C) 2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#define QUIC_DEFAULT_VERSION "-VERS-ALL:+VERS-TLS1.3"
#define QUIC_DEFAULT_CIPHERS "-CIPHER-ALL:+AES-128-GCM:+AES-256-GCM:+CHACHA20-POLY1305:+AES-128-CCM"
#define QUIC_DEFAULT_GROUPS  "-GROUP-ALL:+GROUP-SECP256R1:+GROUP-X25519:+GROUP-SECP384R1:+GROUP-SECP521R1"
#define QUIC_PRIORITY        "%DISABLE_TLS13_COMPAT_MODE:NORMAL:"QUIC_DEFAULT_VERSION":"QUIC_DEFAULT_CIPHERS":"QUIC_DEFAULT_GROUPS

static const gnutls_datum_t quic_alpn[] = {
	{
		.data = (unsigned char *)"doq",
		.size = 3
	},{
		.data = (unsigned char *)"doq-i11",
		.size = 7
	},{
		.data = (unsigned char *)"doq-i03",
		.size = 7
	}
};

/*! \brief QUIC parameters. */
typedef struct {
	/*! Use QUIC indicator. */
	bool enable;
} quic_params_t;

int quic_params_copy(quic_params_t *dst, const quic_params_t *src);

void quic_params_clean(quic_params_t *params);

#ifdef LIBNGTCP2

#include <ngtcp2/ngtcp2.h>
#include <sys/uio.h>

#include "utils/common/tls.h"

typedef enum {
	OPENING,
	CONNECTED,
	CLOSING
} quic_state_t;

typedef struct {
	// Parameters
	quic_params_t params;

	// Context
	tls_ctx_t *tls;
	/*! ngtcp2 (QUIC) setting. */
	ngtcp2_conn *conn;
	ngtcp2_settings settings;
	ngtcp2_pkt_info pi;
	uint8_t secret[32];
	quic_state_t state;
	/*! Stream context */
	struct {
		int64_t id;
		uint64_t sent;
		struct iovec in_storage;
		struct iovec *out_storage;
		size_t out_storage_it;
		size_t out_storage_len;
		size_t out_storage_total;
	} stream;
	uint64_t last_error;
} quic_ctx_t;

uint64_t quic_timestamp(void);

int quic_set_enc(int sockfd, uint32_t ecn, int family);

uint32_t quic_get_ecn(struct msghdr *msg, const int family);

int quic_generate_secret(uint8_t *buf, size_t buflen);

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
