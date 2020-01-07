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

#include "utils/common/https.h"

#ifdef LIBNGHTTP2

static const char *default_path = "/dns-query";

static const gnutls_datum_t https_protocols[] = {
	{ (unsigned char *)"h2", 2 }
};

static ssize_t https_send_callback(nghttp2_session *session, const uint8_t *data,
                                   size_t length, int flags, void *user_data)
{
	assert(user_data);

	tls_ctx_t *tls_ctx = ((https_ctx_t *)user_data)->tls;

	gnutls_record_cork(tls_ctx->session);

	ssize_t len = 0;
	if ((len = gnutls_record_send(tls_ctx->session, data, length)) <= 0) {
		WARN("TLS, failed to send\n");
		return KNOT_NET_ESEND;
	}

	return (ssize_t)length;
}

static int https_on_frame_send_callback(nghttp2_session *session, const nghttp2_frame *frame,
                                        void *user_data)
{
	assert(user_data);

	tls_ctx_t *tls_ctx = ((https_ctx_t *)user_data)->tls;

	while (gnutls_record_check_corked(tls_ctx->session) > 0) {
		int ret = gnutls_record_uncork(tls_ctx->session, 0);
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
		if (!ctx->read) {
			ctx->read = true;
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
		//TODO recv len bigger than buffer
		memcpy(ctx->recv_buf, data, len);
		ctx->recv_buflen = len;
		ctx->read = false;
		ctx->stream = 0;
	}
	return KNOT_EOK;
}

static int https_on_header_callback(nghttp2_session *session, const nghttp2_frame *frame,
									const uint8_t *name, size_t namelen,
									const uint8_t *value, size_t valuelen,
									uint8_t flags, void *user_data)
{
	assert(user_data);

	if (!strncmp("location", (const char *)name, namelen)) {
		https_ctx_t *ctx = (https_ctx_t *)user_data;
		struct http_parser_url redirect_url;

		http_parser_parse_url(value, valuelen, 0, &redirect_url);
		
		if (redirect_url.field_set & (1 << UF_HOST)) {
			if (ctx->authority_alloc) {
				free(ctx->authority);
			}
			ctx->authority = strndup(value + redirect_url.field_data[UF_HOST].off, redirect_url.field_data[UF_HOST].len);
			ctx->authority_alloc = true;
		}
		if (redirect_url.field_set & (1 << UF_PATH)) {
			if(ctx->path_alloc) {
				free(ctx->path);
			}
			ctx->path = strndup(value + redirect_url.field_data[UF_PATH].off, redirect_url.field_data[UF_PATH].len);
			ctx->path_alloc = true;
		}
		https_send_dns_query(ctx, ctx->send_buf, ctx->send_buflen);
	}
	return KNOT_EOK;
}

int https_ctx_init(https_ctx_t *ctx, tls_ctx_t *tls_ctx, const https_params_t *params)
{
	if (ctx == NULL || tls_ctx == NULL || params == NULL) {
		return KNOT_EINVAL;
	}
	if (ctx->session != NULL) { //Already set
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

	int ret = nghttp2_session_client_new(&(ctx->session), callbacks, ctx);
	if (ret != 0) {
		return KNOT_EINVAL;
	}

	// Callback are already copied (in `nghttp2_session_client_new()`), so lets free them
	nghttp2_session_callbacks_del(callbacks);

	if (pthread_mutex_init(&ctx->recv_mx, NULL) != 0) {
		return KNOT_EINVAL;
	}

	ctx->params = params;
	ctx->authority = (tls_ctx->params->hostname) ? tls_ctx->params->hostname : NULL;
	ctx->authority_alloc = false;
	ctx->path = (ctx->params->path) ? ctx->params->path : default_path;
	ctx->path_alloc = false;
	ctx->tls = tls_ctx;
	ctx->read = true;

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

int https_ctx_connect(https_ctx_t *ctx, const int sockfd, struct sockaddr_storage *address,
                      const char *remote)
{
	if (ctx == NULL || address == NULL) {
		return KNOT_EINVAL;
	}

	// Create TLS connection
	int ret = gnutls_init(&ctx->tls->session, GNUTLS_CLIENT | GNUTLS_NONBLOCK);
	if (ret != GNUTLS_E_SUCCESS) {
		return KNOT_NET_ECONNECT;
	}

	ret = gnutls_set_default_priority(ctx->tls->session);
	if (ret != GNUTLS_E_SUCCESS) {
		return KNOT_NET_ECONNECT;
	}

	ret = gnutls_credentials_set(ctx->tls->session, GNUTLS_CRD_CERTIFICATE,
	                             ctx->tls->credentials);
	if (ret != GNUTLS_E_SUCCESS) {
		return KNOT_NET_ECONNECT;
	}

	if (remote != NULL) {
		ret = gnutls_server_name_set(ctx->tls->session, GNUTLS_NAME_DNS, remote,
		                             strlen(remote));
		if (ret != GNUTLS_E_SUCCESS) {
			return KNOT_NET_ECONNECT;
		}
	}

	gnutls_session_set_ptr(ctx->tls->session, ctx->tls);
	gnutls_transport_set_int(ctx->tls->session, sockfd);
	gnutls_handshake_set_timeout(ctx->tls->session, 1000 * ctx->tls->wait);

	ret = gnutls_alpn_set_protocols(ctx->tls->session, https_protocols, sizeof(https_protocols)/sizeof(*https_protocols), 0);
	if(ret != GNUTLS_E_SUCCESS) {
		return KNOT_NET_ECONNECT;
	}

	// Initialize poll descriptor structure.
	struct pollfd pfd = {
		.fd = sockfd,
		.events = POLLIN,
		.revents = 0,
	};

	// Perform the TLS handshake
	do {
		ret = gnutls_handshake(ctx->tls->session);
		if (ret != GNUTLS_E_SUCCESS && gnutls_error_is_fatal(ret) == 0) {
			if (poll(&pfd, 1, 1000 * ctx->tls->wait) != 1) {
				WARN("TLS, peer took too long to respond\n");
				return KNOT_NET_ETIMEOUT;
			}
		}
	} while (ret != GNUTLS_E_SUCCESS && gnutls_error_is_fatal(ret) == 0);
	if (ret != GNUTLS_E_SUCCESS) {
		WARN("TLS, handshake failed (%s)\n", gnutls_strerror(ret));
		tls_ctx_close(ctx->tls);
		return KNOT_NET_ESOCKET;
	}

	// Save the socket descriptor.
	ctx->tls->sockfd = sockfd;

	// Perform HTTP handshake
	static const nghttp2_settings_entry settings[] = {
		{ NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, HTTPS_MAX_STREAMS }
	};

	ret = nghttp2_submit_settings(ctx->session, NGHTTP2_FLAG_NONE, settings, sizeof(settings) / sizeof(*settings));
	if (ret != 0) {
		return KNOT_NET_ESOCKET;
	}

	ret = nghttp2_session_send(ctx->session);
	if (ret != 0) {
		return KNOT_NET_ESOCKET;
	}

	// Save authority server
	if (ctx->authority_alloc) {
		free(ctx->authority);
	}
	ctx->authority = (char*)calloc(HTTPS_AUTHORITY_LEN, sizeof(char));
	ctx->authority_alloc = true;
	ret = sockaddr_to_authority(ctx->authority, HTTPS_AUTHORITY_LEN, address);
	if (ret != KNOT_EOK) {
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

static int https_send_dns_query_get(https_ctx_t *ctx, const uint8_t *buf, const size_t buf_len)
{
	const size_t dns_query_len = strlen(ctx->path) + sizeof("?dns=") + 1 + (buf_len * 4) / 3;
	char dns_query[dns_query_len];
	strncpy(dns_query, ctx->path, dns_query_len);
	strncat(dns_query, "?dns=", dns_query_len);

	size_t tmp_strlen = strlen(dns_query);
	int32_t ret = base64url_encode(buf, buf_len,
		(uint8_t *)dns_query + tmp_strlen, dns_query_len - (tmp_strlen - 1)
	);
	if (ret < 0) {
		return KNOT_EINVAL;
	}

	nghttp2_nv hdrs[] = {
		MAKE_STATIC_NV(":method", "GET"),
		MAKE_STATIC_NV(":scheme", "https"),
		MAKE_NV(":authority", 10, ctx->authority, strlen(ctx->authority)),
		MAKE_NV(":path", 5, dns_query, tmp_strlen + ret - 1),
		MAKE_STATIC_NV("accept", "application/dns-message"),
	};

	ctx->stream= nghttp2_submit_request(ctx->session, NULL, hdrs,
	                                      sizeof(hdrs) / sizeof(*hdrs),
										  NULL, NULL);
	if (ctx->stream < 0) {
		return KNOT_NET_ESEND;
	}

	ret = nghttp2_session_send(ctx->session);
	if (ret != 0) {
		return KNOT_NET_ESEND;
	}

	return KNOT_EOK;
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

	if (sent == buffer->buf_len) {
		*data_flags |= NGHTTP2_DATA_FLAG_EOF;
	}

	return sent;
}

static int https_send_dns_query_post(https_ctx_t *ctx, const uint8_t *buf, const size_t buf_len)
{
	char content_length[sizeof(size_t) * 3 + 1];
	int content_length_len = sprintf(content_length, "%ld", buf_len);

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
		.buf = buf,
		.buf_len = buf_len
	};

	nghttp2_data_provider data_prd = {
		.source.ptr = &data,
		.read_callback = https_send_data_callback
	};

	ctx->stream = nghttp2_submit_request(ctx->session, NULL, hdrs,
	                                      sizeof(hdrs) / sizeof(nghttp2_nv),
	                                      &data_prd, NULL);
	if (ctx->stream < 0) {
		return KNOT_NET_ESEND;
	}

	int ret = nghttp2_session_send(ctx->session);
	if (ret != 0) {
		return KNOT_NET_ESEND;
	}

	return KNOT_EOK;
}

int https_send_dns_query(https_ctx_t *ctx, const uint8_t *buf, const size_t buf_len)
{
	if (ctx == NULL || buf == NULL || buf_len == 0) {
		return KNOT_EINVAL;
	}

	ctx->send_buf = buf;
	ctx->send_buflen = buf_len;

	if (ctx->params->method == POST || HTTPS_USE_POST(ctx->params->method, buf_len)) {
		return https_send_dns_query_post(ctx, buf, buf_len);
	} else {
		return https_send_dns_query_get(ctx, buf, buf_len);
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

	return ctx->recv_buflen;
}

void https_ctx_deinit(https_ctx_t *ctx)
{
	if (ctx == NULL) {
		return;
	}

	nghttp2_session_del(ctx->session);
	pthread_mutex_destroy(&ctx->recv_mx);

	free(ctx->params->path);
	if(ctx->path_alloc) {
		free(ctx->path);
		ctx->path = NULL;
		ctx->path_alloc = false;
	}
}


void print_https(const https_ctx_t *ctx)
{
	if (ctx == NULL) {
		return;
	}

	printf(";; HTTPS session (HTTP/2)-(%s%s)\n", ctx->authority, ctx->path);
}

#endif //LIBNGHTTP2
