/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include "knot/common/hiredis.h"

#include "contrib/sockaddr.h"
#include "knot/common/log.h"
#include "libknot/errcode.h"

#ifdef ENABLE_REDIS_TLS
#include <hiredis/alloc.h>
#include <hiredis/sds.h>

#include "libknot/quic/tls.h"
#include "libknot/quic/tls_common.h"

typedef struct {
	struct knot_creds *local_creds;
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
			knot_tls_ctx_free(ctx->tls);
		}
		knot_creds_free(ctx->local_creds);
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
	} else if (ret == KNOT_EBADCERT ||
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
	} else if (ret == KNOT_EBADCERT ||
	           ret == KNOT_NET_ESEND ||
	           ret == KNOT_NET_ECONNECT ||
	           ret == KNOT_NET_EHSHAKE ||
	           ret == KNOT_ETIMEOUT
	) {
		return -1;
	}
	return 0;
}

static int hiredis_attach_gnutls(redisContext *ctx, struct knot_creds *local_creds,
                                 struct knot_creds *creds)
{
	redis_tls_ctx_t *privctx = hi_calloc(1, sizeof(redis_tls_ctx_t));
	if (ctx == NULL) {
		return KNOT_ENOMEM;
	}
	privctx->local_creds = local_creds;

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
#endif // ENABLE_REDIS_TLS

redisContext *rdb_connect(conf_t *conf)
{
	conf_val_t db_listen = conf_db_param(conf, C_ZONE_DB_LISTEN);
	struct sockaddr_storage addr = conf_addr(&db_listen, NULL);

	int port = sockaddr_port(&addr);
	sockaddr_port_set(&addr, 0);

	char addr_str[SOCKADDR_STRLEN];
	if (sockaddr_tostr(addr_str, sizeof(addr_str), &addr) <= 0) {
		return NULL;
	}

	const struct timeval timeout = { 0 };

	redisContext *rdb;
	if (addr.ss_family == AF_UNIX) {
		rdb = redisConnectUnixWithTimeout(addr_str, timeout);
	} else {
		rdb = redisConnectWithTimeout(addr_str, port, timeout);
	}
	if (rdb == NULL) {
		log_error("rdb, failed to connect");
	} else if (rdb->err) {
		log_error("rdb, failed to connect (%s)", rdb->errstr);
		return NULL;
	}

#ifdef ENABLE_REDIS_TLS
	if (conf_get_bool(conf, C_DB, C_ZONE_DB_TLS)) {
		struct knot_creds *local_creds = NULL;
		char *cert_file = conf_tls(conf, C_CERT_FILE);
		if (cert_file != NULL) {
			char *key_file = conf_tls(conf, C_KEY_FILE);
			conf_val_t cafiles_val = conf_get(conf, C_SERVER, C_CA_FILE);
			size_t nfiles = conf_val_count(&cafiles_val);
			const char *ca_files[nfiles + 1];
			bool system_ca = false;

			memset(ca_files, 0, sizeof(ca_files));
			for (size_t i = 0; cafiles_val.code == KNOT_EOK; conf_val_next(&cafiles_val)) {
				const char *file = conf_str(&cafiles_val);
				if (*file == '\0') {
					system_ca = true;
				} else {
					ca_files[i++] = file;
				}
			}

			int ret = knot_creds_init(&local_creds, key_file, cert_file,
			                          ca_files, system_ca, 0, 0);
			free(key_file);
			free(cert_file);
			if (ret != KNOT_EOK) {
				redisFree(rdb);
				return NULL;
			}
		}

		const char *hostnames[KNOT_TLS_MAX_PINS] = { 0 };
		conf_val_t val = conf_db_param(conf, C_ZONE_DB_CERT_HOSTNAME);
		for (size_t i = 0; val.code == KNOT_EOK; i++) {
			hostnames[i] = conf_str(&val);
			conf_val_next(&val);
		}

		const uint8_t *pins[KNOT_TLS_MAX_PINS] = { 0 };
		val = conf_db_param(conf, C_ZONE_DB_CERT_KEY);
		for (size_t i = 0; val.code == KNOT_EOK; i++) {
			size_t len;
			pins[i] = (uint8_t *)conf_bin(&val, &len);
			conf_val_next(&val);
		}

		struct knot_creds *creds = knot_creds_init_peer(local_creds, hostnames, pins);
		if (creds == NULL) {
			knot_creds_free(local_creds);
			redisFree(rdb);
			return NULL;
		}

		int ret = hiredis_attach_gnutls(rdb, local_creds, creds);
		if (ret != KNOT_EOK) {
			knot_creds_free(local_creds);
			knot_creds_free(creds);
			redisFree(rdb);
			return NULL;
		}
	}
#endif // ENABLE_REDIS_TLS

	return rdb;
}

void rdb_disconnect(redisContext* rdb)
{
	if (rdb != NULL) {
		// TODO: is anything more needed for TLS case?
		redisFree(rdb);
	}
}
