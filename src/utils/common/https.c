#include "utils/common/https.h"

#include <stdio.h>

#ifdef LIBNGHTTP2

static ssize_t https_send_callback(nghttp2_session *session, const uint8_t *data,
                             size_t length, int flags, void *user_data)
{
    tls_ctx_t *tls_ctx = (tls_ctx_t *)user_data;
    fprintf(stderr, "%s\n", data);
    tls_ctx_send(tls_ctx, data, length);
    return (ssize_t)length;
}

static ssize_t https_recv_callback(nghttp2_session *session, uint8_t *data,
                             size_t length, int flags, void *user_data)
{
    tls_ctx_t *tls_ctx = (tls_ctx_t *)user_data;
    struct pollfd pfd = {
		.fd = tls_ctx->sockfd,
		.events = POLLIN,
		.revents = 0,
	};
    ssize_t ret = 0;
    while(ret = gnutls_record_recv(tls_ctx->session, data, length) <= 0) {
        if (ret == 0) {
		    WARN("TLS, peer has closed the connection\n");
		    return KNOT_NET_ERECV;
	    } else if (gnutls_error_is_fatal(ret)) {
            WARN("TLS, failed to receive reply (%s)\n",
			     gnutls_strerror(ret));
			return KNOT_NET_ERECV;
        } else if (poll(&pfd, 1, 1000 * tls_ctx->wait) != 1) {
		    WARN("TLS, peer took too long to respond\n");
		    return KNOT_NET_ETIMEOUT;
	    }
    }
    fprintf(stderr, "%s\n", data);
    return KNOT_EOK;
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
        nghttp2_session_callbacks_set_recv_callback(callbacks, https_recv_callback);

        nghttp2_session_client_new(&(ctx->session), callbacks, tls_ctx);

        // Callback are already copied (in `nghttp2_session_client_new()`), so lets free them
        nghttp2_session_callbacks_del(callbacks);

        return KNOT_EOK;
    }
    return KNOT_NET_ECONNECT;
}

int https_ctx_connect(https_ctx_t *ctx)
{
    /* client 24 bytes magic string will be sent by nghttp2 library */
    int rv = nghttp2_submit_settings(ctx->session, NGHTTP2_FLAG_NONE, NULL, 0);
    nghttp2_session_send(ctx->session);
    return KNOT_EOK;
}
/**
static void print_header(FILE *f, const uint8_t *name, size_t namelen,
                         const uint8_t *value, size_t valuelen) {
  fwrite(name, 1, namelen, f);
  fprintf(f, ": ");
  fwrite(value, 1, valuelen, f);
  fprintf(f, "\n");
}

static void print_headers(FILE *f, nghttp2_nv *nva, size_t nvlen) {
  size_t i;
  for (i = 0; i < nvlen; ++i) {
    print_header(f, nva[i].name, nva[i].namelen, nva[i].value, nva[i].valuelen);
  }
  fprintf(f, "\n");
}
**/
int https_send_dns_query(https_ctx_t *ctx, const uint8_t *buf, const size_t buf_len)
{
    const char tmp_uri[] = "/dns-query?dns=";

    size_t dns_query_len = sizeof(tmp_uri) + 1 + (buf_len * 4)/3;
    uint8_t *dns_query = (uint8_t *)calloc(dns_query_len, sizeof(uint8_t));
    memcpy(dns_query, tmp_uri, sizeof(tmp_uri));
    
    int32_t ret = base64_encode(buf, buf_len,
            dns_query + sizeof(tmp_uri) - 1, dns_query_len - (sizeof(tmp_uri) - 2)
    );

    nghttp2_nv hdrs[] = {
        MAKE_STATIC_NV(":method", "GET"),
        MAKE_STATIC_NV(":scheme", "https"),
        MAKE_STATIC_NV(":authority", "cloudflare-dns.com"), //TODO make reverse lookup
        //MAKE_NV(":path", 5, dns_query, sizeof(tmp_uri) + ret - 2), 
        MAKE_STATIC_NV(":path", "/dns-query?dns=q80BAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB"),
        MAKE_STATIC_NV("accept", "application/dns-message")
    };
    int id = nghttp2_submit_request(ctx->session, NULL, hdrs, sizeof(hdrs) / sizeof(nghttp2_nv), NULL, ctx->tls);
    ret = nghttp2_session_send(ctx->session);
    free(dns_query);
    return KNOT_EOK;
}

int https_recv_dns_response(https_ctx_t *ctx)
{
    return nghttp2_session_recv(ctx->session);
    //return KNOT_EOK;
}

void https_ctx_deinit(https_ctx_t *ctx)
{
	if (ctx == NULL) {
		return;
	}

}

#endif //LIBNGHTTP2