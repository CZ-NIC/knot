#include "utils/common/https.h"

static ssize_t https_send_callback(nghttp2_session *session, const uint8_t *data,
                             size_t length, int flags, void *user_data)
{
    return 0;
}

int https_ctx_init(https_ctx_t *ctx, const https_params_t *params)
{
    ctx->session = NULL;
    if (params && params->enable) {
        //nghttp2_session_callbacks *callbacks;
        //nghttp2_session_callbacks_new(&callbacks);
        //nghttp2_session_callbacks_set_send_callback(callbacks, https_send_callback);
        
        //nghttp2_session_client_new(&(ctx->session), callbacks, NULL);
    }
    return KNOT_EOK;
}

void https_ctx_deinit(https_ctx_t *ctx)
{
	if (ctx == NULL) {
		return;
	}

}