/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <unistd.h>
#include <hiredis/alloc.h>
#include <hiredis/sds.h>

#include "knot/common/hiredis.h"
#include "libknot/errcode.h"
#include "libknot/quic/tls.h"

typedef struct {
	struct knot_tls_ctx *tls;
	struct knot_tls_conn *conn;
} redis_tls_ctx_t;

static void knot_redis_tls_close(redisContext *ctx);
static void knot_redis_tls_free(void *privctx);
static ssize_t knot_redis_tls_read(struct redisContext *ctx, char *buff, size_t size);
static ssize_t knot_redis_tls_write(struct redisContext *ctx);

redisContextFuncs redisContextGnuTLSFuncs = {
	.close = knot_redis_tls_close,
	.free_privctx = knot_redis_tls_free,
	.read = knot_redis_tls_read,
	.write = knot_redis_tls_write
};

static void ctx_deinit(redis_tls_ctx_t *ctx)
{
	if (ctx != NULL) {
		knot_tls_conn_del(ctx->conn);
		if (ctx->tls != NULL) {
			knot_creds_free(ctx->tls->creds);
			knot_tls_ctx_free(ctx->tls);
		}
		hi_free(ctx);
	}
}

static void knot_redis_tls_close(redisContext *ctx)
{
	redis_tls_ctx_t *tls_ctx = ctx->privctx;
	if (ctx && ctx->fd != REDIS_INVALID_FD) {
		knot_tls_conn_del(tls_ctx->conn);
		close(ctx->fd);
		ctx->fd = REDIS_INVALID_FD;
	}
}

static void knot_redis_tls_free(void *privctx)
{
	ctx_deinit((redis_tls_ctx_t *)privctx);
}

static ssize_t knot_redis_tls_read(struct redisContext *ctx, char *buff, size_t size)
{
	redis_tls_ctx_t *tls_ctx = ctx->privctx;

	int ret = knot_tls_recv(tls_ctx->conn, buff, size);
	if (ret >= 0) {
		return ret;
	} else if (ret == KNOT_EBADCERTKEY ||
	           ret == KNOT_NET_ERECV ||
	           ret == KNOT_NET_ECONNECT ||
	           ret == KNOT_NET_EHSHAKE ||
	           ret == KNOT_ETIMEOUT
	) {
		return -1;
	}
	return 0;
}

static ssize_t knot_redis_tls_write(struct redisContext *ctx)
{
	redis_tls_ctx_t *tls_ctx = ctx->privctx;

	int ret = knot_tls_send(tls_ctx->conn, ctx->obuf, sdslen(ctx->obuf));
	if (ret >= 0) {
		return ret;
	} else if (ret == KNOT_EBADCERTKEY ||
	           ret == KNOT_NET_ESEND ||
	           ret == KNOT_NET_ECONNECT ||
	           ret == KNOT_NET_EHSHAKE ||
	           ret == KNOT_ETIMEOUT
	) {
		return -1;
	}
	return 0;
}

int hiredis_attach_gnutls(redisContext *ctx, struct knot_creds *creds)
{
	redis_tls_ctx_t *privctx = hi_calloc(1, sizeof(redis_tls_ctx_t));
	if (ctx == NULL) {
		return KNOT_ENOMEM;
	}

	privctx->tls = knot_tls_ctx_new(creds, 10000, 10000, KNOT_TLS_CLIENT);
	if (privctx->tls == NULL) {
		ctx_deinit(privctx);
		return KNOT_EINVAL;
	}

	privctx->conn = knot_tls_conn_new(privctx->tls, ctx->fd);
	if (privctx->conn == NULL) {
		ctx_deinit(privctx);
		return KNOT_ECONN;
	}

	if (knot_tls_handshake(privctx->conn, true) != KNOT_EOK) {
		return KNOT_ECONN;
	}

	ctx->funcs = &redisContextGnuTLSFuncs;
	ctx->privctx = privctx;

	return KNOT_EOK;
}
