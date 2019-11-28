#include "utils/common/https.h"

#ifdef LIBNGHTTP2

static ssize_t https_send_callback(nghttp2_session *session, const uint8_t *data, size_t length, int flags, void *user_data)
{
    tls_ctx_t *tls_ctx = ((https_ctx_t *)user_data)->tls;

	gnutls_record_cork(tls_ctx->session);

    ssize_t len = 0;
	if (len = gnutls_record_send(tls_ctx->session, data, length) <= 0) {
		WARN("TLS, failed to send\n");
		return KNOT_NET_ESEND;
	}

    return (ssize_t)length;
}

static ssize_t https_on_frame_send_callback(nghttp2_session *session, const nghttp2_frame *frame, void *user_data)
{
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
	https_ctx_t *ctx = (https_ctx_t *)user_data;
    
    struct pollfd pfd = {
		.fd = ctx->tls->sockfd,
		.events = POLLIN,
		.revents = 0,
	};

    ssize_t ret = 0;
    while ( (ret = gnutls_record_recv(ctx->tls->session, data, length)) <= 0) {
		if (!ctx->stream_id) {
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

static ssize_t https_on_stream_close_callback(nghttp2_session *session, int32_t stream_id, uint32_t error_code, void *user_data)
{
	https_ctx_t *ctx = (https_ctx_t *)user_data;

	ctx->stream_id = 0;

    return  KNOT_EOK;
}

static ssize_t https_on_data_chunk_recv_callback(nghttp2_session *session, uint8_t flags, int32_t stream_id, const uint8_t *data, size_t len, void *user_data)
{
    https_ctx_t *ctx = (https_ctx_t *)user_data;

	if (ctx->stream_id == stream_id) {
    	int ret = memcpy(ctx->buf, data, len);
    	ctx->buflen = len;
	}

	return KNOT_EOK;
}

int https_on_frame_recv_callback(nghttp2_session *session, const nghttp2_frame *frame, void *user_data)
{

    https_ctx_t *ctx = (https_ctx_t *)user_data;
	//ctx->stream_id = 0;

    return KNOT_EOK;

}

int https_ctx_init(https_ctx_t *ctx, tls_ctx_t *tls_ctx, const https_params_t *params)
{
    ctx->session = NULL;
	ctx->stream_id = -1;

    if (params && params->enable) {
        ctx->params = params;
        ctx->tls = tls_ctx;

        nghttp2_session_callbacks *callbacks;
        nghttp2_session_callbacks_new(&callbacks);
        nghttp2_session_callbacks_set_send_callback(callbacks, https_send_callback);
	    nghttp2_session_callbacks_set_on_frame_send_callback(callbacks, https_on_frame_send_callback);
        nghttp2_session_callbacks_set_recv_callback(callbacks, https_recv_callback);
        nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, https_on_stream_close_callback);
	    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, https_on_data_chunk_recv_callback);
        nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, https_on_frame_recv_callback);

        nghttp2_session_client_new(&(ctx->session), callbacks, ctx);

        // Callback are already copied (in `nghttp2_session_client_new()`), so lets free them
        nghttp2_session_callbacks_del(callbacks);

        return KNOT_EOK;
    }
    return KNOT_EINVAL;
}

int https_ctx_connect(https_ctx_t *ctx, int sockfd, const char *remote)
{
    if (ctx == NULL) {
		return KNOT_EINVAL;
	}

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


    static const gnutls_datum_t protos[] = {
        {"h2", 2}
    };
	ret = gnutls_alpn_set_protocols(ctx->tls->session, protos, sizeof(protos)/sizeof(*protos), 0);
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
    int rv = nghttp2_submit_settings(ctx->session, NGHTTP2_FLAG_NONE, settings, sizeof(settings) / sizeof(*settings));
    nghttp2_session_send(ctx->session);
    return KNOT_EOK;
}

int https_send_dns_query(https_ctx_t *ctx, const uint8_t *buf, const size_t buf_len) //TODO make short (without edns)
{
    static const char tmp_uri[] = "/dns-query?dns=";

    size_t dns_query_len = sizeof(tmp_uri) + 1 + (buf_len * 4)/3;
    uint8_t *dns_query = (uint8_t *)calloc(dns_query_len, sizeof(uint8_t));
    memcpy(dns_query, tmp_uri, sizeof(tmp_uri));
    
    int32_t ret = base64url_encode(buf, buf_len,
            dns_query + sizeof(tmp_uri) - 1, dns_query_len - (sizeof(tmp_uri) - 2)
    );

    nghttp2_nv hdrs[] = {
        MAKE_STATIC_NV(":method", "GET"),
        MAKE_STATIC_NV(":scheme", "https"),
        MAKE_STATIC_NV(":authority", "1.1.1.1"),
        MAKE_NV(":path", 5, dns_query, sizeof(tmp_uri) + ret - 2),
        MAKE_STATIC_NV("accept", "application/dns-message")
    };

    int id = nghttp2_submit_request(ctx->session, NULL, hdrs, sizeof(hdrs) / sizeof(nghttp2_nv), NULL, ctx->tls);
    if (id < 0) {
        return KNOT_NET_ESEND;
    }
	ctx->stream_id = id;

    ret = nghttp2_session_send(ctx->session);
    free(dns_query);
    return KNOT_EOK;
}

int https_recv_dns_response(https_ctx_t *ctx, uint8_t *buf, const size_t buf_len)
{
    ctx->buf = buf;
    ctx->buflen = buf_len;
    nghttp2_session_recv(ctx->session);
    return ctx->buflen;
}

int https_ctx_close(https_ctx_t *ctx)
{
	if (ctx == NULL) {
		return;
	}
    tls_ctx_close(ctx->tls);
    
}

void https_ctx_deinit(https_ctx_t *ctx)
{
	if (!ctx || !ctx->tls) {
		return;
	}
}

#endif //LIBNGHTTP2