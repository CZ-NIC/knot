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
#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>

#include "libknot/quic/tls.h"

#include "contrib/macros.h"
#include "contrib/net.h"
#include "libknot/attribute.h"
#include "libknot/error.h"
#include "libknot/quic/tls_common.h"

// TODO re-consider those detailed
#define TLS_DEFAULT_VERSION "-VERS-ALL:+VERS-TLS1.3"
#define TLS_DEFAULT_GROUPS  "-GROUP-ALL:+GROUP-X25519:+GROUP-SECP256R1:+GROUP-SECP384R1:+GROUP-SECP521R1"
#define TLS_PRIORITIES      "%DISABLE_TLS13_COMPAT_MODE:NORMAL:"TLS_DEFAULT_VERSION":"TLS_DEFAULT_GROUPS

#define EAGAIN_MAX_FOR_GNUTLS 10 // gnutls_record_recv() has been observed to return GNUTLS_E_AGAIN repetitively and excessively, leading to infinite loops. This limits the number of re-tries.

_public_
knot_tls_ctx_t *knot_tls_ctx_new(struct knot_quic_creds *creds, unsigned io_timeout,
                                 bool server)
{
	knot_tls_ctx_t *res = calloc(1, sizeof(*res));
	if (res == NULL) {
		return NULL;
	}

	res->creds = creds;
	res->handshake_timeout = GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT;
	res->io_timeout = io_timeout;
	res->server = server;

	return res;
}

_public_
void knot_tls_ctx_free(knot_tls_ctx_t *ctx)
{
	if (ctx != NULL) {
		free(ctx);
	}
}

static int poll_func(gnutls_transport_ptr_t ptr, unsigned timeout_ms)
{
	knot_tls_conn_t *conn = (knot_tls_conn_t *)ptr;

	struct pollfd pfd = {
		.fd = conn->fd,
		.events = POLLIN
	};

	return poll(&pfd, 1, timeout_ms);
}

static ssize_t pull_func(gnutls_transport_ptr_t ptr, void *buf, size_t size)
{
	knot_tls_conn_t *conn = (knot_tls_conn_t *)ptr;
	conn->recv_count++;
	ssize_t ret = net_stream_recv(conn->fd, buf, size, conn->ctx->io_timeout);
	if (ret < 0) {
		conn->err_count++;
		conn->last_err = ret;
	}
	return ret;
}

static ssize_t push_func(gnutls_transport_ptr_t ptr, const void *buf, size_t size)
{
	knot_tls_conn_t *conn = (knot_tls_conn_t *)ptr;
	conn->send_count++;
	ssize_t ret = net_stream_send(conn->fd, buf, size, conn->ctx->io_timeout);
	if (ret < 0) {
		conn->err_count++;
		conn->last_err = ret;
	}
	return ret;
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

	int ret = knot_quic_conn_session(&res->session, ctx->creds, TLS_PRIORITIES,
	                                 "\x03""dot", false, ctx->server);
	if (ret != KNOT_EOK) {
		goto fail;
	}

	gnutls_transport_set_ptr(res->session, res);
	gnutls_transport_set_pull_timeout_function(res->session, poll_func);
	gnutls_transport_set_pull_function(res->session, pull_func);
	gnutls_transport_set_push_function(res->session, push_func); // TODO employ gnutls_transport_set_vec_push_function for optimization
	gnutls_handshake_set_timeout(res->session, ctx->handshake_timeout);
	gnutls_record_set_timeout(res->session, ctx->io_timeout);

	return res;
fail:
	gnutls_deinit(res->session);
	free(res);
	return NULL;
}

_public_
void knot_tls_conn_del(knot_tls_conn_t *conn)
{
	if (conn != NULL) {
		gnutls_deinit(conn->session);
		free(conn);
	}
}

inline static bool eagain_rcode(ssize_t gnutls_rcode)
{
	return gnutls_rcode == GNUTLS_E_AGAIN || gnutls_rcode == GNUTLS_E_INTERRUPTED;
}

_public_
int knot_tls_handshake(knot_tls_conn_t *conn)
{
	if (conn->handshake_done) {
		_Static_assert(KNOT_EOK == GNUTLS_E_SUCCESS, "EOK differs between libknot and GnuTLS");
		return KNOT_EOK;
	}
	int ret, again = EAGAIN_MAX_FOR_GNUTLS;
	do {
		if (--again < 0) {
			return KNOT_ETIMEOUT;
		}
		ret = gnutls_handshake(conn->session);
	} while (eagain_rcode(ret));
	// TODO filter error codes?

	if (ret == KNOT_EOK) {
		conn->handshake_done = true;
		ret = knot_quic_conn_pin_check(conn->session, conn->ctx->creds);
	}
	return ret;
}

static ssize_t tls_io_fun(knot_tls_conn_t *conn, void *data, size_t size,
                          ssize_t (*io_cb)(gnutls_session_t, void *, size_t))
{
	ssize_t res = knot_tls_handshake(conn), orig_size = size, again = EAGAIN_MAX_FOR_GNUTLS;
	if (res != KNOT_EOK) {
		return res;
	}

	do {
		if (--again < 0) {
			return KNOT_ETIMEOUT;
		}
		res = io_cb(conn->session, data, size);
		if (res > 0) {
			data += res;
			size -= res;
		}
	} while (eagain_rcode(res) || (res > 0 && size > 0));

	conn->iofun_count++;

	// TODO filter error codes?
	return res > 0 ? orig_size : res;
}

static ssize_t gnutls_record_send_noconst(gnutls_session_t session,
                                          void *data, size_t data_size)
{
	// just a wrapper, parameter 'data' is not (const void *) here
	return gnutls_record_send(session, data, data_size);
}

_public_
ssize_t knot_tls_recv(knot_tls_conn_t *conn, void *data, size_t size)
{
	return tls_io_fun(conn, data, size, gnutls_record_recv);
}

_public_
ssize_t knot_tls_send(knot_tls_conn_t *conn, void *data, size_t size)
{
	return tls_io_fun(conn, data, size, gnutls_record_send_noconst);
}

_public_
ssize_t knot_tls_recv_dns(knot_tls_conn_t *conn, void *data, size_t size)
{
	uint16_t dns_len;
	ssize_t ret = knot_tls_recv(conn, &dns_len, sizeof(dns_len));
	if (ret > 0 && ret < sizeof(dns_len)) {
		ret = KNOT_EMALF;
	} else if (ret == sizeof(dns_len)) {
		dns_len = ntohs(dns_len);
		if (dns_len > size) {
			return KNOT_ESPACE;
		}
		ret = knot_tls_recv(conn, data, dns_len);
	}

	return ret;
}

_public_
ssize_t knot_tls_send_dns(knot_tls_conn_t *conn, void *data, size_t size)
{
	if (size > UINT16_MAX) {
		return KNOT_EINVAL;
	}

	uint16_t dns_len = htons(size);
	ssize_t ret = knot_tls_send(conn, &dns_len, sizeof(dns_len)); // TODO invent a way how to send length and data at once
	if (ret > 0 && ret < sizeof(dns_len)) {
		ret = KNOT_EMALF;
	} else if (ret == sizeof(dns_len)) {
		ret = knot_tls_send(conn, data, size);
	}

	return ret;
}
