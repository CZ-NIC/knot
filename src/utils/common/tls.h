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

#include <stdint.h>
#include <netdb.h>
#include <gnutls/gnutls.h>

#include "contrib/sockaddr.h"
#include "contrib/ucw/lists.h"

/*! \brief TLS parameters. */
typedef struct {
	/*! Use TLS indicator. */
	bool enable;
	/*! Import system certificates indicator. */
	bool system_ca;
	/*! Certificate files to import. */
	list_t ca_files;
	/*! Pinned certificates. */
	list_t pins;
	/*! Required server hostname. */
	char *hostname;
	/*! Optional server name indicator. */
	char *sni;
	/*! Optional client keyfile name. */
	char *keyfile;
	/*! Optional client certfile name. */
	char *certfile;
	/*! Optional validity of stapled OCSP response for the server cert. */
	uint32_t ocsp_stapling;
} tls_params_t;

/*! \brief TLS context. */
typedef struct {
	/*! TLS handshake timeout. */
	int wait;
	/*! Socket descriptor. */
	int sockfd;
	/*! TLS parameters. */
	const tls_params_t *params;
	/*! GnuTLS session handle. */
	gnutls_session_t session;
	/*! GnuTLS credentials handle. */
	gnutls_certificate_credentials_t credentials;
} tls_ctx_t;

extern const gnutls_datum_t dot_alpn;

void tls_params_init(tls_params_t *params);
int tls_params_copy(tls_params_t *dst, const tls_params_t *src);
void tls_params_clean(tls_params_t *params);

int tls_ctx_init(tls_ctx_t *ctx, const tls_params_t *params,
        unsigned int flags, int wait, const gnutls_datum_t *alpn,
        size_t alpn_size, const char *priority);
int tls_ctx_connect(tls_ctx_t *ctx, int sockfd, const char *remote,
        bool fastopen, struct sockaddr_storage *addr);

int tls_ctx_send(tls_ctx_t *ctx, const uint8_t *buf, const size_t buf_len);
int tls_ctx_receive(tls_ctx_t *ctx, uint8_t *buf, const size_t buf_len);
void tls_ctx_close(tls_ctx_t *ctx);
void tls_ctx_deinit(tls_ctx_t *ctx);
void print_tls(const tls_ctx_t *ctx);
