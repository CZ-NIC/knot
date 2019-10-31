#include "utils/common/https.h"

#ifdef LIBNGHTTP2

static ssize_t https_send_callback(nghttp2_session *session, const uint8_t *data,
                             size_t length, int flags, void *user_data)
{
    tls_ctx_t *tls_ctx = (tls_ctx_t *)user_data;
    tls_ctx_send(tls_ctx, data, length);
    return (ssize_t)length;
}

int https_ctx_init(https_ctx_t *ctx, tls_ctx_t *tls_ctx, const https_params_t *params)
{
    ctx->session = NULL;
    if (params && params->enable) {
        ctx->params = params;
        ctx->tls = tls_ctx;

        nghttp2_session_callbacks *callbacks;
        nghttp2_session_callbacks_new(&callbacks);
        nghttp2_session_callbacks_set_send_callback(callbacks, https_send_callback);
        
        nghttp2_session_client_new(&(ctx->session), callbacks, tls_ctx);

        // Callback are already copied (in `nghttp2_session_client_new()`), so lets free them
        nghttp2_session_callbacks_del(callbacks);

        return KNOT_EOK;
    }
    return KNOT_NET_ECONNECT;
}

int https_send_dns_query(https_ctx_t *ctx, const uint8_t *buf, const size_t buf_len)
{
    nghttp2_nv hdrs[] = {
        MAKE_NV(":method", "GET"),
        MAKE_NV(":scheme", "https"),
        MAKE_NV(":authority", "cloudflare-dns.com"), //TODO make reverse lookup
        MAKE_NV(":path", "/dns-query?dns=X"), //TODO where X is BASE64 encoded wireformat message
        MAKE_NV("accept", "application/dns-message")
    };
    nghttp2_submit_request(ctx, NULL, hdrs, 4, NULL, ctx->tls);
    return KNOT_EOK;
}

void https_ctx_deinit(https_ctx_t *ctx)
{
	if (ctx == NULL) {
		return;
	}

}

#endif