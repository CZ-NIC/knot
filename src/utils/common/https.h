/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

/*! \brief HTTPS parameters. */
typedef struct {
    /*! Use HTTPS indicator. */
    bool enable;
} https_params_t;

#ifdef LIBNGHTTP2

#include <poll.h>
#include <assert.h>
#include <pthread.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <gnutls/gnutls.h>
#include <nghttp2/nghttp2.h>

#include "contrib/base64url.h"
#include "libknot/errcode.h"

#include "utils/common/tls.h"
#include "utils/common/msg.h"

#define MAKE_NV(K, KS, V, VS) \
    { (uint8_t *)K, (uint8_t *)V, KS, VS, NGHTTP2_NV_FLAG_NONE }

#define MAKE_STATIC_NV(K, V) \
    MAKE_NV(K, sizeof(K) - 1, V, sizeof(V) - 1)

#define HTTPS_MAX_STREAMS 16
#define HTTPS_AUTHORITY_LEN (INET6_ADDRSTRLEN + 2)

#define HTTPS_POST_THRESHOLD 1024UL
#define HTTPS_USE_POST(S) (S >= HTTPS_POST_THRESHOLD)

/*! \brief Structure that stores data source for DATA frames. */
typedef struct {
    const uint8_t *buf;
    size_t buf_len;
} https_data_provider_t;

/*! \brief HTTPS context. */
typedef struct {
    //Parameters
    const https_params_t *params;

    //Contexts
    nghttp2_session *session;
    tls_ctx_t *tls;
    char authority[HTTPS_AUTHORITY_LEN];

    //Read locks
    pthread_mutex_t recv_mx;
    bool read;

    //Read destination
    uint8_t *buf;
    size_t buflen;
} https_ctx_t;

/*!
 * \brief   Initialize HTTPS context.
 * 
 * \param ctx		HTTPS context.
 * \param tls_ctx	TLS context.
 * \param params	Parameter table.
 *
 * \retval KNOT_EOK     when initialized.
 * \retval KNOT_EINVAL  when parameters are invalid.
 */
int https_ctx_init(https_ctx_t *ctx, tls_ctx_t *tls_ctx, const https_params_t *params);

/*!
 * \brief   Create TLS connection and perform HTTPS handshake.
 * 
 * \param ctx		HTTPS context.
 * \param sockfd	TLS context.
 * \param address	Socket address storage with address to server side.
 * \param remote	[optional] Remote name.
 *
 * \retval KNOT_EOK             when successfully connected.
 * \retval KNOT_EINVAL          when parameters are invalid.
 * \retval KNOT_NET_ESOCKET     when socket is no accessible.
 * \retval KNOT_NET_ETIMEOUT    when server respond takes too long.
 * \retval KNOT_NET_ECONNECT    when unnable to connect to the server.
 */
int https_ctx_connect(https_ctx_t *ctx, const int sockfd, struct sockaddr_storage *address, const char *remote);

/*!
 * \brief   Send buffer as DNS message over HTTPS.
 * 
 * \param ctx		HTTPS context.
 * \param buf       Buffer with DNS message in wire format.
 * \param buf_len	Length of buffer.
 *
 * \retval KNOT_EOK             when successfully sent.
 * \retval KNOT_EINVAL          when parameters are invalid.
 * \retval KNOT_NET_ESEND       when error occurs while sending a data.
 */
int https_send_dns_query(https_ctx_t *ctx, const uint8_t *buf, const size_t buf_len);

/*!
 * \brief   Receive DATA frame as HTTPS packet, and store it into buffer.
 * 
 * \param ctx		HTTPS context.
 * \param buf       Buffer where will be DNS response stored.
 * \param buf_len	Length of buffer.
 *
 * \retval >=0              number of bytes received in DATA frame.
 * \retval KNOT_NET_ERECV   when error while receive.
 */
int https_recv_dns_response(https_ctx_t *ctx, uint8_t *buf, const size_t buf_len);

/*!
 * \brief   Deinitialize HTTPS context.
 * 
 * \param ctx		HTTPS context.
 */
void https_ctx_deinit(https_ctx_t *ctx);


#endif //LIBNGHTTP2