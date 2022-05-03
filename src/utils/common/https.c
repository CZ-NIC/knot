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

#include <assert.h>
#include <arpa/inet.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>

#include "contrib/base64url.h"
#include "contrib/macros.h"
#include "contrib/openbsd/strlcat.h"
#include "contrib/openbsd/strlcpy.h"
#include "contrib/url-parser/url_parser.h"
#include "libknot/errcode.h"
#include "libknot/dname.h"
#include "utils/common/https.h"
#include "utils/common/msg.h"

#define is_read(ctx) (ctx->stream == -1)

int https_params_copy(https_params_t *dst, const https_params_t *src)
{
	if (dst == NULL || src == NULL) {
		return KNOT_EINVAL;
	}

	dst->enable = src->enable;
	dst->method = src->method;
	if (src->path != NULL) {
		dst->path = strdup(src->path);
		if (dst->path == NULL) {
			return KNOT_ENOMEM;
		}
	}

	return KNOT_EOK;
}

void https_params_clean(https_params_t *params)
{
	if (params == NULL) {
		return;
	}

	params->enable = false;
	params->method = GET;
	free(params->path);
	params->path = NULL;
}

#ifdef LIBNGHTTP2

#define HTTP_STATUS_SUCCESS	200
#define HTTPS_MAX_STREAMS	16
#define HTTPS_AUTHORITY_LEN	(INET6_ADDRSTRLEN + 2)

#define MAKE_NV(K, KS, V, VS) \
	{ (uint8_t *)K, (uint8_t *)V, KS, VS, NGHTTP2_NV_FLAG_NONE }

#define MAKE_STATIC_NV(K, V) \
	MAKE_NV(K, sizeof(K) - 1, V, sizeof(V) - 1)

static const char default_path[] = "/dns-query";
static const char default_query[] = "?dns=";

static const nghttp2_settings_entry settings[] = {
	{ NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, HTTPS_MAX_STREAMS }
};

const gnutls_datum_t doh_alpn = {
	.data = (unsigned char *)"h2",
	.size = 2
};

static bool https_status_is_redirect(unsigned long status)
{
	switch (status) {
		case 301UL:
		case 302UL:
		case 307UL:
		case 308UL:
			return true;
	}
	return false;
}

static ssize_t https_send_callback(nghttp2_session *session, const uint8_t *data,
                                   size_t length, int flags, void *user_data)
{
	assert(user_data);

	gnutls_session_t tls_session = ((https_ctx_t *)user_data)->tls->session;
	ssize_t len = 0;

	gnutls_record_cork(tls_session);
	if ((len = gnutls_record_send(tls_session, data, length)) <= 0) {
		WARN("TLS, failed to send\n");
		return KNOT_NET_ESEND;
	}
	return len;
}

static int https_on_frame_send_callback(nghttp2_session *session, const nghttp2_frame *frame,
                                        void *user_data)
{
	assert(user_data);

	gnutls_session_t tls_session = ((https_ctx_t *)user_data)->tls->session;
	while (gnutls_record_check_corked(tls_session) > 0) {
		int ret = gnutls_record_uncork(tls_session, 0);
		if (ret < 0 && gnutls_error_is_fatal(ret) != 0) {
			WARN("TLS, failed to send (%s)\n", gnutls_strerror(ret));
			return KNOT_NET_ESEND;
		}
	}
	return KNOT_EOK;
}

static ssize_t https_recv_callback(nghttp2_session *session, uint8_t *data, size_t length,
                                   int flags, void *user_data)
{
	assert(user_data);

	https_ctx_t *ctx = (https_ctx_t *)user_data;
	struct pollfd pfd = {
		.fd = ctx->tls->sockfd,
		.events = POLLIN,
		.revents = 0,
	};

	ssize_t ret = 0;
	while ((ret = gnutls_record_recv(ctx->tls->session, data, length)) <= 0) {
		if (is_read(ctx)) { //Unblock `nghttp2_session_recv(nghttp2_session)`
			return NGHTTP2_ERR_WOULDBLOCK;
		}
		if (ret == 0) {
			WARN("TLS, peer has closed the connection\n");
			return KNOT_NET_ERECV;
		} else if (gnutls_error_is_fatal(ret)) {
			WARN("TLS, failed to receive reply (%s)\n",
			     gnutls_strerror(ret));
			return KNOT_NET_ERECV;
		} else if (poll(&pfd, 1, 1000 * ctx->tls->wait) != 1) {
			WARN("TLS, peer took too long to respond\n");
			return KNOT_ETIMEOUT;
		}
	}

	return ret;
}

static int https_on_data_chunk_recv_callback(nghttp2_session *session, uint8_t flags, int32_t stream_id,
                                             const uint8_t *data, size_t len, void *user_data)
{
	assert(user_data);

	https_ctx_t *ctx = (https_ctx_t *)user_data;
	if (ctx->stream == stream_id) {
		int cpy_len = MIN(len, ctx->recv_buflen);
		memcpy(ctx->recv_buf, data, cpy_len);
		ctx->recv_buf += cpy_len;
		ctx->recv_buflen -= cpy_len;
	}
	return KNOT_EOK;
}

static int https_on_stream_close_callback(nghttp2_session *session, int32_t stream_id, uint32_t error_code, void *user_data)
{
	assert(user_data);

	https_ctx_t *ctx = (https_ctx_t *)user_data;
	if (ctx->stream == stream_id) {
		ctx->stream = -1;
	}
	return KNOT_EOK;
}

static int https_on_header_callback(nghttp2_session *session, const nghttp2_frame *frame,
                                    const uint8_t *name, size_t namelen,
                                    const uint8_t *value, size_t valuelen,
                                    uint8_t flags, void *user_data)
{
	assert(user_data);
	https_ctx_t *ctx = (https_ctx_t *)user_data;

	if (!strncasecmp(":status", (const char *)name, namelen)) {
		char *end;
		long status;
		status = strtoul((const char *)value, &end, 10);
		if (value != (const uint8_t *)end) {
			ctx->status = status;
		}
	}
	else if (!strncasecmp("location", (const char *)name, namelen) &&
		 https_status_is_redirect(ctx->status)) {
		struct http_parser_url redirect_url;
		http_parser_parse_url((const char *)value, valuelen, 0, &redirect_url);

		bool r_auth = redirect_url.field_set & (1 << UF_HOST);
		bool r_path = redirect_url.field_set & (1 << UF_PATH);
		char *old_auth = ctx->authority, *old_path = ctx->path;

		if (r_auth) {
			ctx->authority = strndup((const char *)(value + redirect_url.field_data[UF_HOST].off),
			                         redirect_url.field_data[UF_HOST].len);
		}
		if (r_path) {
			ctx->path = strndup((const char *)(value + redirect_url.field_data[UF_PATH].off),
			                    redirect_url.field_data[UF_PATH].len);
		}
		WARN("HTTP redirect (%s%s)->(%s%s)\n", old_auth, old_path, ctx->authority, ctx->path);
		if (r_auth) {
			free(old_auth);
		}
		if (r_path) {
			free(old_path);
		}
		return https_send_dns_query(ctx, ctx->send_buf, ctx->send_buflen);
	}
	return KNOT_EOK;
}

int https_ctx_init(https_ctx_t *ctx, tls_ctx_t *tls_ctx, const https_params_t *params)
{
	if (ctx == NULL || tls_ctx == NULL || params == NULL) {
		return KNOT_EINVAL;
	}
	if (ctx->session != NULL) { // Already initialized before
		return KNOT_EINVAL;
	}
	if (!params->enable) {
		return KNOT_EINVAL;
	}

	nghttp2_session_callbacks *callbacks;
	nghttp2_session_callbacks_new(&callbacks);
	nghttp2_session_callbacks_set_send_callback(callbacks, https_send_callback);
	nghttp2_session_callbacks_set_on_frame_send_callback(callbacks, https_on_frame_send_callback);
	nghttp2_session_callbacks_set_recv_callback(callbacks, https_recv_callback);
	nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, https_on_data_chunk_recv_callback);
	nghttp2_session_callbacks_set_on_header_callback(callbacks, https_on_header_callback);
	nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, https_on_stream_close_callback);

	int ret = nghttp2_session_client_new(&(ctx->session), callbacks, ctx);
	if (ret != 0) {
		return KNOT_EINVAL;
	}

	nghttp2_session_callbacks_del(callbacks);

	if (pthread_mutex_init(&ctx->recv_mx, NULL) != 0) {
		return KNOT_EINVAL;
	}

	ctx->tls = tls_ctx;
	ctx->params = *params;
	ctx->authority = (tls_ctx->params->hostname) ? strdup(tls_ctx->params->hostname) : NULL;
	ctx->path = strdup((ctx->params.path) ? ctx->params.path : (char *)default_path);
	ctx->stream = -1;

	return KNOT_EOK;
}

static int sockaddr_to_authority(char *buf, const size_t buf_len, const struct sockaddr_storage *ss)
{
	if (buf == NULL || ss == NULL) {
		return KNOT_EINVAL;
	}

	const char *out = NULL;

	/* Convert IPv6 network address string. */
	if (ss->ss_family == AF_INET6) {
		if (buf_len < HTTPS_AUTHORITY_LEN) {
			return KNOT_EINVAL;
		}

		const struct sockaddr_in6 *s = (const struct sockaddr_in6 *)ss;
		buf[0] = '[';

		out = inet_ntop(ss->ss_family, &s->sin6_addr, buf + 1, buf_len - 1);
		if (out == NULL) {
			return KNOT_EINVAL;
		}

		buf += strlen(buf);
		buf[0] = ']';
		buf[1] = '\0';
	/* Convert IPv4 network address string. */
	} else if (ss->ss_family == AF_INET) {
		if (buf_len < INET_ADDRSTRLEN) {
			return KNOT_EINVAL;
		}

		const struct sockaddr_in *s = (const struct sockaddr_in *)ss;

		out = inet_ntop(ss->ss_family, &s->sin_addr, buf, buf_len);
		if (out == NULL) {
			return KNOT_EINVAL;
		}
	/* Unknown network address family. */
	} else {
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

int https_ctx_connect(https_ctx_t *ctx, int sockfd, bool fastopen,
                      struct sockaddr_storage *addr)
{
	if (ctx == NULL || addr == NULL) {
		return KNOT_EINVAL;
	}

	// Create TLS connection
	int ret = tls_ctx_connect(ctx->tls, sockfd, fastopen, addr);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Perform HTTP handshake
	ret = nghttp2_submit_settings(ctx->session, NGHTTP2_FLAG_NONE, settings,
	                              sizeof(settings) / sizeof(*settings));
	if (ret != 0) {
		return KNOT_NET_ESOCKET;
	}
	ret = nghttp2_session_send(ctx->session);
	if (ret != 0) {
		return KNOT_NET_ESOCKET;
	}

	// Save authority server
	if (ctx->authority == NULL) {
		//TODO test
		ctx->authority = (char*)calloc(KNOT_DNAME_TXT_MAXLEN + 1, sizeof(char));
		unsigned int type = GNUTLS_NAME_DNS;
		size_t len = KNOT_DNAME_TXT_MAXLEN + 1;
		ret = gnutls_server_name_get(ctx->tls->session, ctx->authority, &len,
		                             &type, 0);
		if (ret == GNUTLS_E_SUCCESS && ctx->authority[0] == '\0') {
			ret = sockaddr_to_authority(ctx->authority, KNOT_DNAME_TXT_MAXLEN + 1, addr);
			if (ret != KNOT_EOK) {
				free(ctx->authority);
				ctx->authority = NULL;
				return KNOT_EINVAL;
			}
		}
	}

	return KNOT_EOK;
}

static int https_send_dns_query_common(https_ctx_t *ctx, nghttp2_nv *hdrs, size_t hdrs_len, nghttp2_data_provider *data_provider)
{
	assert(hdrs != NULL && hdrs_len > 0);

	ctx->stream = nghttp2_submit_request(ctx->session, NULL, hdrs, hdrs_len,
	                                     data_provider, NULL);
	if (ctx->stream < 0) {
		return KNOT_NET_ESEND;
	}
	int ret = nghttp2_session_send(ctx->session);
	if (ret != 0) {
		return KNOT_NET_ESEND;
	}

	return KNOT_EOK;
}

static int https_send_dns_query_get(https_ctx_t *ctx)
{
	const size_t dns_query_len = strlen(ctx->path) +
	                             sizeof(default_query) +
	                             (ctx->send_buflen * 4) / 3 + 3;
	char dns_query[dns_query_len];
	strlcpy(dns_query, ctx->path, dns_query_len);
	strlcat(dns_query, default_query, dns_query_len);

	size_t tmp_strlen = strlen(dns_query);
	int32_t ret = knot_base64url_encode(ctx->send_buf, ctx->send_buflen,
		(uint8_t *)(dns_query + tmp_strlen), dns_query_len - tmp_strlen - 1);
	if (ret < 0) {
		return KNOT_EINVAL;
	}

	nghttp2_nv hdrs[] = {
		MAKE_STATIC_NV(":method", "GET"),
		MAKE_STATIC_NV(":scheme", "https"),
		MAKE_NV(":authority", 10, ctx->authority, strlen(ctx->authority)),
		MAKE_NV(":path", 5, dns_query, tmp_strlen + ret),
		MAKE_STATIC_NV("accept", "application/dns-message"),
	};

	return https_send_dns_query_common(ctx, hdrs, sizeof(hdrs) / sizeof(*hdrs),
	                                   NULL);
}

static ssize_t https_send_data_callback(nghttp2_session *session, int32_t stream_id,
                                        uint8_t *buf, size_t length, uint32_t *data_flags,
                                        nghttp2_data_source *source, void *user_data)
{
	https_data_provider_t *buffer = source->ptr;
	ssize_t sent = (length < buffer->buf_len) ? length : buffer->buf_len;

	memcpy(buf, buffer->buf, sent);
	buffer->buf += sent;
	buffer->buf_len -= sent;
	if (!buffer->buf_len) {
		*data_flags |= NGHTTP2_DATA_FLAG_EOF;
	}

	return sent;
}

static int https_send_dns_query_post(https_ctx_t *ctx)
{
	                                             // size of number in text form (base 10)
	char content_length[sizeof(size_t) * 3 + 1]; // limit for x->inf: log10(2^(8*sizeof(x))-1)/sizeof(x) = 2,408239965 -> 3
	int content_length_len = sprintf(content_length, "%zu", ctx->send_buflen);

	nghttp2_nv hdrs[] = {
		MAKE_STATIC_NV(":method", "POST"),
		MAKE_STATIC_NV(":scheme", "https"),
		MAKE_NV(":authority", 10, ctx->authority, strlen(ctx->authority)),
		MAKE_NV(":path", 5, ctx->path, strlen(ctx->path)),
		MAKE_STATIC_NV("accept", "application/dns-message"),
		MAKE_STATIC_NV("content-type", "application/dns-message"),
		MAKE_NV("content-length", 14, content_length, content_length_len)
	};

	https_data_provider_t data = {
		.buf = ctx->send_buf,
		.buf_len = ctx->send_buflen
	};

	nghttp2_data_provider data_provider = {
		.source.ptr = &data,
		.read_callback = https_send_data_callback
	};

	return https_send_dns_query_common(ctx, hdrs, sizeof(hdrs) / sizeof(*hdrs),
	                                   &data_provider);
}

int https_send_dns_query(https_ctx_t *ctx, const uint8_t *buf, const size_t buf_len)
{
	if (ctx == NULL || buf == NULL || buf_len == 0) {
		return KNOT_EINVAL;
	}

	ctx->send_buf = buf;
	ctx->send_buflen = buf_len;

	assert(ctx->params.method == POST || ctx->params.method == GET);

	if (ctx->params.method == POST) {
		return https_send_dns_query_post(ctx);
	} else {
		return https_send_dns_query_get(ctx);
	}
}

int https_recv_dns_response(https_ctx_t *ctx, uint8_t *buf, const size_t buf_len)
{
	if (ctx == NULL || buf == NULL || buf_len == 0) {
		return KNOT_EINVAL;
	}

	pthread_mutex_lock(&ctx->recv_mx);
	ctx->recv_buf = buf;
	ctx->recv_buflen = buf_len;

	int ret = nghttp2_session_recv(ctx->session);
	if (ret != 0) {
		pthread_mutex_unlock(&ctx->recv_mx);
		return KNOT_NET_ERECV;
	}
	ctx->recv_buf = NULL;

	pthread_mutex_unlock(&ctx->recv_mx);

	if (ctx->status != HTTP_STATUS_SUCCESS) {
		print_https(ctx);
		return KNOT_NET_ERECV;
	}

	assert(buf_len >= ctx->recv_buflen);
	return buf_len - ctx->recv_buflen;
}

void https_ctx_deinit(https_ctx_t *ctx)
{
	if (ctx == NULL) {
		return;
	}

	nghttp2_session_del(ctx->session);
	ctx->session = NULL;
	pthread_mutex_destroy(&ctx->recv_mx);
	free(ctx->path);
	ctx->path = NULL;
	free(ctx->authority);
	ctx->authority = NULL;
}

void print_https(const https_ctx_t *ctx)
{
	if (!ctx || !ctx->authority || !ctx->path) {
		return;
	}
	printf(";; HTTP session (HTTP/2-%s)-(%s%s)-(status: %lu)\n",
	       ctx->params.method == POST ? "POST" : "GET", ctx->authority,
	       ctx->path, ctx->status);
}

#endif //LIBNGHTTP2
