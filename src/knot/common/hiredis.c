/*  Copyright (C) 2025 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
		if (ctx->tls != NULL) {
			knot_creds_free(ctx->tls->creds);
		}
		knot_tls_conn_del(ctx->conn);
		knot_tls_ctx_free(ctx->tls);
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
	redis_tls_ctx_t *tls_ctx = privctx;
	ctx_deinit(tls_ctx);
}

static ssize_t knot_redis_tls_read(struct redisContext *ctx, char *buff, size_t size)
{
	redis_tls_ctx_t *tls_ctx = ctx->privctx;

	int ret = knot_tls_recv(tls_ctx->conn, buff, size);
	if (ret >= 0) {
		return ret;
	} else if (ret == KNOT_NET_ERECV ||
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
	} else if (ret == KNOT_NET_ESEND ||
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

	ctx->funcs = &redisContextGnuTLSFuncs;
	ctx->privctx = privctx;

	return KNOT_EOK;
}
