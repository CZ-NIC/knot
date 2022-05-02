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

/*! \brief QUIC parameters. */
typedef struct {
	/*! Use QUIC indicator. */
	bool enable;
} quic_params_t;

int quic_params_copy(quic_params_t *dst, const quic_params_t *src);

void quic_params_clean(quic_params_t *params);

#ifdef LIBNGTCP2

#include <ngtcp2/ngtcp2.h>

#include "utils/common/tls.h"

#define QUIC_DEFAULT_VERSION "-VERS-ALL:+VERS-TLS1.3"
#define QUIC_DEFAULT_CIPHERS "-CIPHER-ALL:+AES-128-GCM:+AES-256-GCM:+CHACHA20-POLY1305:+AES-128-CCM"
#define QUIC_DEFAULT_GROUPS  "-GROUP-ALL:+GROUP-SECP256R1:+GROUP-X25519:+GROUP-SECP384R1:+GROUP-SECP521R1"
#define QUIC_PRIORITY        "%DISABLE_TLS13_COMPAT_MODE:NORMAL:"QUIC_DEFAULT_VERSION":"QUIC_DEFAULT_CIPHERS":"QUIC_DEFAULT_GROUPS


typedef enum {
	OPENING,
	CONNECTED,
	CLOSING
} quic_state_t;

typedef struct {
	// Parameters
	quic_params_t params;

	// Context
	ngtcp2_settings settings;
	struct {
		int64_t id;
		uint64_t out_ack;
		struct iovec in_buffer;
		struct iovec *in_parsed;
		size_t in_parsed_size;
		size_t in_parsed_total;
		size_t in_parsed_it;
	} stream;
	ngtcp2_connection_close_error last_err;
	uint8_t secret[32];
	tls_ctx_t *tls;
	ngtcp2_conn *conn;
	ngtcp2_pkt_info pi;
	quic_state_t state;
	uint64_t idle_ts;
} quic_ctx_t;

extern const gnutls_datum_t quic_alpn[];

uint64_t quic_timestamp(void);

int quic_generate_secret(uint8_t *buf, size_t buflen);

int quic_ctx_init(quic_ctx_t *ctx, tls_ctx_t *tls_ctx, const quic_params_t *params);

#endif //LIBNGTCP2
