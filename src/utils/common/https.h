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

/*! \brief HTTP method to transfer query. */
typedef enum {
	POST,
	GET
} https_method_t;

/*! \brief HTTPS parameters. */
typedef struct {
	/*! Use HTTPS indicator. */
	bool enable;
	/*! HTTP method to transfer query. */
	https_method_t method;
	/*! Path */
	char *path;
} https_params_t;

int https_params_copy(https_params_t *dst, const https_params_t *src);
void https_params_clean(https_params_t *params);

#ifdef LIBNGHTTP2

#include <netinet/in.h>
#include <pthread.h>
#include <sys/socket.h>
#include <nghttp2/nghttp2.h>

#include "utils/common/tls.h"

extern const gnutls_datum_t doh_alpn;

/*! \brief Structure that stores data source for DATA frames. */
typedef struct {
	const uint8_t *buf;
	size_t buf_len;
} https_data_provider_t;

/*! \brief HTTPS context. */
typedef struct {
	// Parameters
	https_params_t params;

	// Contexts
	nghttp2_session *session;
	tls_ctx_t *tls;
	char *authority;
	char *path;

	// Send destination
	const uint8_t *send_buf;
	size_t send_buflen;

	// Recv destination
	uint8_t *recv_buf;
	size_t recv_buflen;
	unsigned long status;

	// Recv locks
	pthread_mutex_t recv_mx;
	int32_t stream;
} https_ctx_t;

/*!
 * \brief Initialize HTTPS context.
 *
 * \param ctx      HTTPS context.
 * \param tls_ctx  TLS context.
 * \param params   Parameter table.
 *
 * \retval KNOT_EOK     When initialized.
 * \retval KNOT_EINVAL  When parameters are invalid.
 */
int https_ctx_init(https_ctx_t *ctx, tls_ctx_t *tls_ctx, const https_params_t *params);

/*!
 * \brief Create TLS connection and perform HTTPS handshake.
 *
 * \param ctx       HTTPS context.
 * \param sockfd    Socket descriptor.
 * \param fastopen  Use TCP Fast Open indication.
 * \param addr      Socket address storage with address to server side.
 *
 * \retval KNOT_EOK           When successfully connected.
 * \retval KNOT_EINVAL        When parameters are invalid.
 * \retval KNOT_NET_ESOCKET   When socket is no accessible.
 * \retval KNOT_NET_ETIMEOUT  When server respond takes too long.
 * \retval KNOT_NET_ECONNECT  When unnable to connect to the server.
 */
int https_ctx_connect(https_ctx_t *ctx, int sockfd, bool fastopen,
                      struct sockaddr_storage *addr);

/*!
 * \brief Send buffer as DNS message over HTTPS.
 *
 * \param ctx      HTTPS context.
 * \param buf      Buffer with DNS message in wire format.
 * \param buf_len  Length of buffer.
 *
 * \retval KNOT_EOK        When successfully sent.
 * \retval KNOT_EINVAL     When parameters are invalid.
 * \retval KNOT_NET_ESEND  When error occurs while sending a data.
 */
int https_send_dns_query(https_ctx_t *ctx, const uint8_t *buf, const size_t buf_len);

/*!
 * \brief Receive DATA frame as HTTPS packet, and store it into buffer.
 *
 * \param ctx      HTTPS context.
 * \param buf      Buffer where will be DNS response stored.
 * \param buf_len  Length of buffer.
 *
 * \retval >=0              Number of bytes received in DATA frame.
 * \retval KNOT_NET_ERECV   When error while receive.
 */
int https_recv_dns_response(https_ctx_t *ctx, uint8_t *buf, const size_t buf_len);

/*!
 * \brief Deinitialize HTTPS context.
 *
 * \param ctx  HTTPS context.
 */
void https_ctx_deinit(https_ctx_t *ctx);

/*!
 * \brief Prints information about HTTPS context.
 *
 * \param ctx  HTTPS context.
 */
void print_https(const https_ctx_t *ctx);

#endif //LIBNGHTTP2
