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

static const char https_tmp_uri[] = "/dns-query?dns=";

static const gnutls_datum_t https_protocols[] = {
	{ (unsigned char *)"h2", 2 }
};

static ssize_t https_send_callback(nghttp2_session *session, const uint8_t *data, size_t length, int flags, void *user_data)
{
    assert(user_data);

    tls_ctx_t *tls_ctx = ((https_ctx_t *)user_data)->tls;

	gnutls_record_cork(tls_ctx->session);

    ssize_t len = 0;
	if ( (len = gnutls_record_send(tls_ctx->session, data, length)) <= 0) {
		WARN("TLS, failed to send\n");
		return KNOT_NET_ESEND;
	}

    return (ssize_t)length;
}

static int https_on_frame_send_callback(nghttp2_session *session, const nghttp2_frame *frame, void *user_data)
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

static ssize_t https_recv_callback(nghttp2_session *session, uint8_t *data, size_t length, int flags, void *user_data)
{
	assert(user_data);

	https_ctx_t *ctx = (https_ctx_t *)user_data;
    
    struct pollfd pfd = {
		.fd = ctx->tls->sockfd,
		.events = POLLIN,
		.revents = 0,
	};

    ssize_t ret = 0;
    while ( (ret = gnutls_record_recv(ctx->tls->session, data, length)) <= 0) {
		if (!ctx->stream_id) { //TODO Concurrency receive 
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

static int https_on_stream_close_callback(nghttp2_session *session, int32_t stream_id, uint32_t error_code, void *user_data)
{
	assert(user_data);

	https_ctx_t *ctx = (https_ctx_t *)user_data;

	ctx->stream_id = 0;

    return  KNOT_EOK;
}

static int https_on_data_chunk_recv_callback(nghttp2_session *session, uint8_t flags, int32_t stream_id, const uint8_t *data, size_t len, void *user_data)
{
	assert(user_data);

    https_ctx_t *ctx = (https_ctx_t *)user_data;

	if (ctx->stream_id == stream_id) {
    	memcpy(ctx->buf, data, len);
    	ctx->buflen = len;
	}

	return KNOT_EOK;
}

int https_ctx_init(https_ctx_t *ctx, tls_ctx_t *tls_ctx, const https_params_t *params)
{
	if (ctx->session != NULL) {
		return KNOT_EINVAL;
	}
    if (params == NULL || !params->enable) {
		return KNOT_EINVAL;
	}
    
    nghttp2_session_callbacks *callbacks;
    nghttp2_session_callbacks_new(&callbacks);
    nghttp2_session_callbacks_set_send_callback(callbacks, https_send_callback);
	nghttp2_session_callbacks_set_on_frame_send_callback(callbacks, https_on_frame_send_callback);
    nghttp2_session_callbacks_set_recv_callback(callbacks, https_recv_callback);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, https_on_stream_close_callback);
	nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, https_on_data_chunk_recv_callback);

    int ret = nghttp2_session_client_new(&(ctx->session), callbacks, ctx);
	if (ret != 0) {
		return KNOT_EINVAL;
	}

	// Callback are already copied (in `nghttp2_session_client_new()`), so lets free them
    nghttp2_session_callbacks_del(callbacks);

	ctx->stream_id = 0;
    ctx->params = params;
    ctx->tls = tls_ctx;

    return KNOT_EOK;
}

static int sockaddr_to_authority(char *buf, const size_t buf_len, const struct sockaddr_storage *ss)
{
	if (ss == NULL || buf == NULL) {
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
		if (!out) 
			return KNOT_EINVAL;

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
		if (!out) 
			return KNOT_EINVAL;
	/* Unknown network address family. */
	} else {
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

int https_ctx_connect(https_ctx_t *ctx, const int sockfd, struct sockaddr_storage *address, const char *remote)
{
    if (ctx == NULL) {
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
        {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, HTTPS_MAX_STREAMS}
    };

    ret = nghttp2_submit_settings(ctx->session, NGHTTP2_FLAG_NONE, settings, sizeof(settings) / sizeof(*settings));
	if(ret != 0) {
		return KNOT_NET_ESOCKET;
	}

    ret = nghttp2_session_send(ctx->session);
	if(ret != 0) {
		return KNOT_NET_ESOCKET;
	}

	// Save authority server
	ret = sockaddr_to_authority(ctx->authority, HTTPS_AUTHORITY_LEN, address);
	if (ret != KNOT_EOK) {
		return KNOT_EINVAL;
	}

    return KNOT_EOK;
}

/** TODO POST
static ssize_t https_send_data_callback(nghttp2_session *session,
                                  int32_t stream_id, uint8_t *buf,
                                  size_t length, uint32_t *data_flags,
                                  nghttp2_data_source *source,
                                  void *user_data) {
	https_data_provider_t *buffer = source->ptr;
	ssize_t r = buffer->buf_len;
	memcpy(buf, buffer->buf, buffer->buf_len);
  //if (r == -1) {
  //  return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
  //}
	//if (r == 0) {
		*data_flags |= NGHTTP2_DATA_FLAG_EOF;
	//}
	return r;
}
**/

int https_send_dns_query(https_ctx_t *ctx, const uint8_t *buf, const size_t buf_len)
{
	if (ctx->stream_id > 0) { //TODO concurrency of send/receive
		return KNOT_NET_ESEND;
	}
	
    const size_t dns_query_len = sizeof(https_tmp_uri) + 1 + (buf_len * 4) / 3;
    uint8_t * dns_query = (uint8_t *)calloc(dns_query_len, sizeof(uint8_t));
    memcpy(dns_query, https_tmp_uri, sizeof(https_tmp_uri));
    
    int32_t ret = base64url_encode(buf, buf_len,
            dns_query + sizeof(https_tmp_uri) - 1, dns_query_len - (sizeof(https_tmp_uri) - 2)
    );
	if (ret < 0) {
		free(dns_query);
		return KNOT_EINVAL;
	}

    nghttp2_nv hdrs[] = {
        MAKE_STATIC_NV(":method", "GET"),
		//MAKE_STATIC_NV(":method", "POST"), //TODO POST
        MAKE_STATIC_NV(":scheme", "https"),
		MAKE_NV(":authority", 10, ctx->authority, strlen(ctx->authority)),
		MAKE_NV(":path", 5, dns_query, sizeof(https_tmp_uri) + ret - 2),
        //MAKE_STATIC_NV(":path", "/dns-query"), //TODO POST
        MAKE_STATIC_NV("accept", "application/dns-message")
    };

	/** TODO POST
	https_data_provider_t data = {
		.buf = buf,
		.buf_len = buf_len
	};

	nghttp2_data_provider data_prd;
	data_prd.source.ptr = &data;
	data_prd.read_callback = https_send_data_callback;
	**/

    const int id = nghttp2_submit_request(ctx->session, NULL, hdrs, sizeof(hdrs)/sizeof(*hdrs), NULL, NULL);
	//int id = nghttp2_submit_request(ctx->session, NULL, hdrs, sizeof(hdrs) / sizeof(nghttp2_nv), &data_prd, ctx->tls); //TODO POST
    if (id < 0) {
		free(dns_query);
        return KNOT_NET_ESEND;
    }
	ctx->stream_id = id;

    ret = nghttp2_session_send(ctx->session);
	if (ret != 0) {
		free(dns_query);
		return KNOT_NET_ESEND;
	}
    
	free(dns_query);
	return KNOT_EOK;
}

int https_recv_dns_response(https_ctx_t *ctx, uint8_t *buf, const size_t buf_len)
{
	if (ctx->stream_id <= 0) { //TODO concurrency of send/receive
		return KNOT_NET_ERECV;
	}

    ctx->buf = buf;
    ctx->buflen = buf_len;

    int ret = nghttp2_session_recv(ctx->session);
	if (ret != 0) {
		return KNOT_NET_ERECV;
	}

	ctx->buf = NULL;
    
	return ctx->buflen;
}

#endif //LIBNGHTTP2