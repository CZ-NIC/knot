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

#include <gnutls/gnutls.h>
#include <poll.h>
#include <stdlib.h>

#include "libknot/quic/tls.h"

#include "contrib/macros.h"
#include "contrib/net.h"
#include "libknot/attribute.h"
#include "libknot/error.h"
#include "libknot/quic/quic.h"

knot_tls_ctx_t *knot_tls_ctx_new(struct knot_quic_creds *creds,
                                 bool server,
                                 unsigned handshake_timeout_ms,
                                 unsigned io_timeout_ms,
                                 unsigned idle_timeout_ms)
{
	knot_tls_ctx_t *res = calloc(1, sizeof(*res));
	if (res == NULL) {
		return NULL;
	}
	res->server = server;
	res->creds = creds;
	res->handshake_timeout_ms = handshake_timeout_ms;
	res->io_timeout_ms = io_timeout_ms;
	res->idle_timeout_ms = idle_timeout_ms;
	return res;
}

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
	return net_stream_recv(conn->fd, buf, size, conn->timeout);
}

static ssize_t push_func(gnutls_transport_ptr_t ptr, const void *buf, size_t size)
{
	knot_tls_conn_t *conn = (knot_tls_conn_t *)ptr;
	return net_stream_send(conn->fd, buf, size, conn->timeout);
}

_public_
knot_tls_conn_t *knot_tls_conn_new(knot_tls_ctx_t *ctx, int sock_fd)
{
	knot_tls_conn_t *res = calloc(1, sizeof(*res));
	if (res == NULL) {
		return NULL;
	}
	res->fd = sock_fd;
	res->timeout = ctx->io_timeout_ms;

	int ret = knot_quic_conn_session(&res->session, ctx->creds, "NORMAL" /* FIXME */, "dot", false, ctx->server);
	if (ret != GNUTLS_E_SUCCESS) {
		goto fail;
	}

	gnutls_transport_set_ptr(res->session, res);
	gnutls_transport_set_pull_timeout_function(res->session, poll_func);
	gnutls_transport_set_pull_function(res->session, pull_func);
	gnutls_transport_set_push_function(res->session, push_func); // TODO employ gnutls_transport_set_vec_push_function for optimization
	gnutls_handshake_set_timeout(res->session, ctx->handshake_timeout_ms);
	gnutls_record_set_timeout(res->session, ctx->io_timeout_ms);

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
	int ret;
	do {
		ret = gnutls_handshake(conn->session);
	} while (eagain_rcode(ret));
	// TODO filter error codes?
	return ret;
}

static ssize_t io_call(knot_tls_conn_t *conn, void *data, size_t size,
                       ssize_t (*io_func)(struct gnutls_session_int *, void *, size_t))
{
	ssize_t res = knot_tls_handshake(conn);
	if (res != KNOT_EOK) {
		return res;
	}

	do {
		res = io_func(conn->session, data, size);
	} while (eagain_rcode(res));
	// TODO filter error codes?
	return res;
}

_public_
ssize_t knot_tls_recv(knot_tls_conn_t *conn, void *data, size_t size)
{
	return io_call(conn, data, size, gnutls_record_recv);
}

_public_
ssize_t knot_tls_send(knot_tls_conn_t *conn, void *data, size_t size)
{
	return io_call(conn, data, size, (ssize_t (*)(struct gnutls_session_int *, void *, size_t)) // workaround for const
	                                 gnutls_record_send);
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
