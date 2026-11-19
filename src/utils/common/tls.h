/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <netdb.h>
#include <gnutls/gnutls.h>

#include "contrib/sockaddr.h"
#include "contrib/ucw/lists.h"

#define CERT_PIN_LEN 32

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

int tls_certificate_verification(tls_ctx_t *ctx);

int tls_ctx_init(tls_ctx_t *ctx, const tls_params_t *params,
        unsigned int flags, int wait);
int tls_ctx_setup_remote_endpoint(tls_ctx_t *ctx, const gnutls_datum_t *alpn,
        size_t alpn_size, const char *priority, const char *remote);
int tls_ctx_connect(tls_ctx_t *ctx, int sockfd, struct sockaddr_storage *addr);

int tls_ctx_send(tls_ctx_t *ctx, const uint8_t *buf, const size_t buf_len);
int tls_ctx_receive(tls_ctx_t *ctx, uint8_t *buf, const size_t buf_len);
void tls_ctx_close(tls_ctx_t *ctx);
void tls_ctx_deinit(tls_ctx_t *ctx);
void print_tls(const tls_ctx_t *ctx);

/*!
 * \brief Whether a name is an IPv4 or IPv6 address literal.
 *
 * RFC 6066 section 3: "Literal IPv4 and IPv6 addresses are not permitted in
 * HostName". A name the user did not give, taken from the server address,
 * must not be sent as the server name: GnuTLS servers (Knot DNS) refuse an
 * IPv6 literal there, and others look it up as a name and present a
 * certificate for another one. The certificate is still verified against
 * the address.
 */
static inline bool tls_name_is_address(const char *name)
{
	struct in6_addr addr6;
	struct in_addr addr4;
	return name != NULL && (inet_pton(AF_INET, name, &addr4) == 1 ||
	                        inet_pton(AF_INET6, name, &addr6) == 1);
}
