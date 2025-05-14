/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <string.h>

#include "knot/query/tls-requestor.h"
#include "knot/query/requestor.h"
#include "libknot/error.h"
#include "libknot/quic/tls.h"
#include "contrib/conn_pool.h"

int knot_tls_req_ctx_init(knot_tls_req_ctx_t *ctx,
			  int fd,
			  const struct sockaddr_storage *remote,
			  const struct sockaddr_storage *local,
			  const struct knot_creds *local_creds,
			  const char *peer_hostname,
			  const uint8_t *peer_pin,
			  uint8_t peer_pin_len,
			  bool *reused_fd,
			  int io_timeout_ms)
{
	struct knot_creds *creds =
		knot_creds_init_peer(local_creds, peer_hostname, peer_pin, peer_pin_len);
	if (creds == NULL) {
		return KNOT_ENOMEM;
	}

	// Use HS = 4x IO timeout, as the RMT IO timeout is usually high.
	ctx->ctx = knot_tls_ctx_new(creds, io_timeout_ms, 4 * io_timeout_ms,
	                            KNOT_TLS_CLIENT | KNOT_TLS_DNS | KNOT_TLS_EARLY_DATA);
	if (ctx->ctx == NULL) {
		knot_creds_free(creds);
		return KNOT_ENOMEM;
	}

	ctx->conn = knot_tls_conn_new(ctx->ctx, fd);
	if (ctx->conn == NULL) {
		knot_tls_req_ctx_deinit(ctx);
		return KNOT_ERROR;
	}

	intptr_t sessticket = conn_pool_get(global_sessticket_pool, local, remote);
	if (sessticket != CONN_POOL_FD_INVALID) {
		int ret = knot_tls_session_load(ctx->conn, (void *)sessticket);
		if (ret != KNOT_EOK) {
			global_sessticket_pool->close_cb(sessticket);
			sessticket = CONN_POOL_FD_INVALID;
		} else if (reused_fd != NULL) {
			*reused_fd = true;
		}
	}

	return KNOT_EOK;
}

void knot_tls_req_ctx_maint(knot_tls_req_ctx_t *ctx, struct knot_request *r)
{
	if (global_sessticket_pool != NULL &&
	    knot_tls_session_available(ctx->conn)) {
		void *sessticket = knot_tls_session_save(ctx->conn);
		if (sessticket != NULL) {
			intptr_t tofree = conn_pool_put(global_sessticket_pool, &r->source,
			                                &r->remote, (intptr_t)sessticket);
			global_sessticket_pool->close_cb(tofree);
		}
	}
}

void knot_tls_req_ctx_deinit(knot_tls_req_ctx_t *ctx)
{
	if (ctx != NULL) {
		if (ctx->ctx != NULL) {
			knot_creds_free(ctx->ctx->creds);
		}
		knot_tls_conn_del(ctx->conn);
		knot_tls_ctx_free(ctx->ctx);
		memset(ctx, 0, sizeof(*ctx));
	}
}
