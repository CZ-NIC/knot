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

#include <arpa/inet.h>
#include <assert.h>
#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>
#include <poll.h>
#include <stdlib.h>

#include "libknot/quic/tls.h"

#include "contrib/macros.h"
#include "contrib/time.h"
#include "contrib/ucw/lists.h"
#include "libknot/attribute.h"
#include "libknot/error.h"
#include "libknot/quic/tls_common.h"

typedef struct knot_tls_session {
	node_t n;
	gnutls_datum_t tls_session;
	size_t quic_params_len;
	// NOTE this differs from definition in quic.c, basically TLS requires the
	// quic_params to be zero and QUIC non-zero.
} knot_tls_session_t;

_public_
knot_tls_ctx_t *knot_tls_ctx_new(struct knot_creds *creds, unsigned io_timeout,
                                 unsigned hs_timeout, bool server)
{
	knot_tls_ctx_t *res = calloc(1, sizeof(*res));
	if (res == NULL) {
		return NULL;
	}

	res->creds = creds;
	res->handshake_timeout = hs_timeout;
	res->io_timeout = io_timeout;
	res->server = server;

	int ret = gnutls_priority_init2(&res->priority, KNOT_TLS_PRIORITIES, NULL,
	                                GNUTLS_PRIORITY_INIT_DEF_APPEND);
	if (ret != GNUTLS_E_SUCCESS) {
		free(res);
		return NULL;
	}

	return res;
}

_public_
void knot_tls_ctx_free(knot_tls_ctx_t *ctx)
{
	if (ctx != NULL) {
		gnutls_priority_deinit(ctx->priority);
		free(ctx);
	}
}

_public_
knot_tls_conn_t *knot_tls_conn_new(knot_tls_ctx_t *ctx, int sock_fd)
{
	knot_tls_conn_t *res = calloc(1, sizeof(*res));
	if (res == NULL) {
		return NULL;
	}
	res->ctx = ctx;
	res->fd = sock_fd;

	int ret = knot_tls_session(&res->session, ctx->creds, ctx->priority,
	                           false, true, ctx->server);
	if (ret != KNOT_EOK) {
		goto fail;
	}

	gnutls_transport_set_int(res->session, sock_fd); // Use internal recv/send/poll.
	gnutls_handshake_set_timeout(res->session, ctx->handshake_timeout);

	return res;
fail:
	gnutls_deinit(res->session);
	free(res);
	return NULL;
}

_public_
void knot_tls_conn_del(knot_tls_conn_t *conn)
{
	if (conn != NULL && conn->fd_clones_count-- < 1) {
		(void)gnutls_bye(conn->session, GNUTLS_SHUT_WR);
		gnutls_deinit(conn->session);
		free(conn);
	}
}

_public_
bool knot_tls_session_available(knot_tls_conn_t *conn)
{
	return conn != NULL && !(conn->flags & KNOT_TLS_CONN_SESSION_TAKEN) &&
	       (gnutls_session_get_flags(conn->session) & GNUTLS_SFLAGS_SESSION_TICKET);
}

_public_
struct knot_tls_session *knot_tls_session_save(knot_tls_conn_t *conn)
{
	if (!knot_tls_session_available(conn)) {
		return NULL;
	}

	knot_tls_session_t *session = calloc(1, sizeof(*session));
	if (session == NULL) {
		return NULL;
	}

	int ret = gnutls_session_get_data2(conn->session, &session->tls_session);
	if (ret != GNUTLS_E_SUCCESS) {
		free(session);
		return NULL;
	}
	conn->flags |= KNOT_TLS_CONN_SESSION_TAKEN;

	return session;
}

_public_
int knot_tls_session_load(knot_tls_conn_t *conn, struct knot_tls_session *session)
{
	if (session == NULL || (conn != NULL && session->quic_params_len > 0)) {
		return KNOT_EINVAL;
	}

	int ret = KNOT_EOK;
	if (conn != NULL) {
		ret = gnutls_session_set_data(conn->session, session->tls_session.data,
		                              session->tls_session.size);
		if (ret != GNUTLS_E_SUCCESS) {
			ret = KNOT_ERROR;
		}
	}

	gnutls_free(session->tls_session.data);
	free(session);
	return ret;
}

_public_
int knot_tls_handshake(knot_tls_conn_t *conn, bool oneshot)
{
	if (conn->flags & (KNOT_TLS_CONN_HANDSHAKE_DONE | KNOT_TLS_CONN_BLOCKED)) {
		return KNOT_EOK;
	}

	struct pollfd pfd = {
		.fd = conn->fd,
		.events = POLLOUT
	};
	int ret = poll(&pfd, 1, conn->ctx->io_timeout);
	if (ret != 1) {
		return ret == 0 ? KNOT_NET_ECONNECT : KNOT_EAGAIN;
	}

	gnutls_record_set_timeout(conn->session, conn->ctx->io_timeout);
	do {
		ret = gnutls_handshake(conn->session);
	} while (!oneshot && ret < 0 && gnutls_error_is_fatal(ret) == 0);

	switch (ret) {
	case GNUTLS_E_SUCCESS:
		conn->flags |= KNOT_TLS_CONN_HANDSHAKE_DONE;
		return knot_tls_pin_check(conn->session, conn->ctx->creds);
	case GNUTLS_E_TIMEDOUT:
		return KNOT_NET_ETIMEOUT;
	default:
		if (gnutls_error_is_fatal(ret) == 0) {
			return KNOT_EAGAIN;
		} else {
			return KNOT_NET_EHSHAKE;
		}
	}
}

#define TIMEOUT_CTX_INIT \
	struct timespec begin, end; \
	if (*timeout_ptr > 0) { \
		clock_gettime(CLOCK_MONOTONIC, &begin); \
	}

#define TIMEOUT_CTX_UPDATE \
	if (*timeout_ptr > 0) { \
		clock_gettime(CLOCK_MONOTONIC, &end); \
		int running_ms = time_diff_ms(&begin, &end); \
		*timeout_ptr = MAX(*timeout_ptr - running_ms, 0); \
	}

static ssize_t recv_data(knot_tls_conn_t *conn, void *data, size_t size, int *timeout_ptr)
{
	gnutls_record_set_timeout(conn->session, *timeout_ptr);

	size_t total = 0;
	ssize_t res;
	while (total < size) {
		TIMEOUT_CTX_INIT
		res = gnutls_record_recv(conn->session, data + total, size - total);
		if (res > 0) {
			total += res;
		} else if (res == 0) {
			return KNOT_ECONNRESET;
		} else if (gnutls_error_is_fatal(res) != 0) {
			return KNOT_NET_ERECV;
		}
		TIMEOUT_CTX_UPDATE
		gnutls_record_set_timeout(conn->session, *timeout_ptr);
	}

	assert(total == size);
	return size;
}

_public_
ssize_t knot_tls_recv_dns(knot_tls_conn_t *conn, void *data, size_t size)
{
	if (conn == NULL || data == NULL) {
		return KNOT_EINVAL;
	}

	if (conn->flags & KNOT_TLS_CONN_BLOCKED) {
		return 0;
	}

	ssize_t ret = knot_tls_handshake(conn, false);
	if (ret != KNOT_EOK) {
		return ret;
	}

	int timeout = conn->ctx->io_timeout;

	uint16_t msg_len;
	ret = recv_data(conn, &msg_len, sizeof(msg_len), &timeout);
	if (ret != sizeof(msg_len)) {
		return ret;
	}

	msg_len = ntohs(msg_len);
	if (size < msg_len) {
		return KNOT_ESPACE;
	}

	ret = recv_data(conn, data, msg_len, &timeout);
	if (ret != size) {
		return ret;
	}

	return msg_len;
}

_public_
ssize_t knot_tls_send_dns(knot_tls_conn_t *conn, void *data, size_t size)
{
	if (conn == NULL || data == NULL || size > UINT16_MAX) {
		return KNOT_EINVAL;
	}

	ssize_t res = knot_tls_handshake(conn, false);
	if (res != KNOT_EOK) {
		return res;
	}

	// Enable data buffering.
	gnutls_record_cork(conn->session);

	uint16_t msg_len = htons(size);
	res = gnutls_record_send(conn->session, &msg_len, sizeof(msg_len));
	if (res != sizeof(msg_len)) {
		return KNOT_NET_ESEND;
	}

	res = gnutls_record_send(conn->session, data, size);
	if (res != size) {
		return KNOT_NET_ESEND;
	}

	int timeout = conn->ctx->io_timeout, *timeout_ptr = &timeout;
	gnutls_record_set_timeout(conn->session, timeout);

	// Send the buffered data.
	while (gnutls_record_check_corked(conn->session) > 0) {
		TIMEOUT_CTX_INIT
		int ret = gnutls_record_uncork(conn->session, 0);
		if (ret < 0 && gnutls_error_is_fatal(ret) != 0) {
			return ret == GNUTLS_E_TIMEDOUT ? KNOT_ETIMEOUT :
			                                  KNOT_NET_ESEND;
		}
		TIMEOUT_CTX_UPDATE
		gnutls_record_set_timeout(conn->session, timeout);
	}

	return size;
}

_public_
void knot_tls_conn_block(knot_tls_conn_t *conn, bool block)
{
	if (block) {
		conn->flags |= KNOT_TLS_CONN_BLOCKED;
	} else {
		conn->flags &= ~KNOT_TLS_CONN_BLOCKED;
	}
}
