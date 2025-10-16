/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include "knot/common/hiredis.h"
#include "contrib/conn_pool.h"
#include "contrib/openbsd/strlcpy.h"
#include "contrib/sockaddr.h"
#include "contrib/strtonum.h"
#include "knot/common/log.h"
#include "knot/zone/redis.h"
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

	privctx->tls = knot_tls_ctx_new(creds, 5000, 2000, KNOT_TLS_CLIENT);
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

static redisContext *connect_addr(conf_t *conf, const char *addr_str, int port)
{
	const struct timeval timeout = { 10, 0 };

	redisContext *rdb;
	if (port == 0) {
		rdb = redisConnectUnixWithTimeout(addr_str, timeout);
	} else {
		rdb = redisConnectWithTimeout(addr_str, port, timeout);
	}
	if (rdb == NULL || rdb->err != REDIS_OK) {
		log_debug("rdb, failed to connect, remote %s%s%.0u (%s)",
		          addr_str, (port != 0 ? "@" : ""), port,
		          (rdb != NULL ? rdb->errstr : "no reply"));
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
				log_error("rdb, failed to initialize credentials or to load certificates (%s)",
				          knot_strerror(ret));
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
			log_debug("rdb, failed to use TLS (%s)", knot_strerror(KNOT_ENOMEM));
			knot_creds_free(local_creds);
			redisFree(rdb);
			return NULL;
		}

		int ret = hiredis_attach_gnutls(rdb, local_creds, creds);
		if (ret != KNOT_EOK) {
			log_debug("rdb, failed to use TLS (%s)", knot_strerror(ret));
			knot_creds_free(local_creds);
			knot_creds_free(creds);
			redisFree(rdb);
			return NULL;
		}
	}
#endif // ENABLE_REDIS_TLS

	return rdb;
}

int rdb_addr_to_str(struct sockaddr_storage *addr, char *out, size_t out_len, int *port)
{
	*port = 0;

	if (addr->ss_family == AF_UNIX) {
		const char *path = ((struct sockaddr_un *)addr)->sun_path;
		if (path[0] != '/') { // hostname
			size_t len = strlcpy(out, path, out_len);
			if (len == 0 || len >= out_len) {
				return KNOT_EINVAL;
			}

			char *port_sep = strchr(out, '@');
			if (port_sep != NULL) {
				*port_sep = '\0';
				uint16_t num;
				int ret = str_to_u16(port_sep + 1, &num);
				if (ret != KNOT_EOK || num == 0) {
					return KNOT_EINVAL;
				}
				*port = num;
			} else {
				*port = CONF_REDIS_PORT;
			}
		}
	} else {
		*port = sockaddr_port(addr);
		sockaddr_port_set(addr, 0);

		if (sockaddr_tostr(out, out_len, addr) <= 0 || *port == 0) {
			return KNOT_EINVAL;
		}
	}

	return KNOT_EOK;
}

static int get_master(redisContext *rdb, char *out, size_t out_len, int *port)
{
	redisReply *masters_reply = redisCommand(rdb, "SENTINEL masters");
	if (masters_reply == NULL || masters_reply->type != REDIS_REPLY_ARRAY ||
	    masters_reply->elements == 0) {
		if (masters_reply != NULL) {
			freeReplyObject(masters_reply);
		}
		return KNOT_ENOENT;
	}

	redisReply *first_master = masters_reply->element[0];
	const char *master_name = NULL;

	for (size_t j = 0; j < first_master->elements; j += 2) {
		const char *field = first_master->element[j]->str;
		const char *value = first_master->element[j + 1]->str;
		if (strcmp(field, "name") == 0) {
			master_name = value;
			break;
		}
	}
	if (master_name == NULL) {
		freeReplyObject(masters_reply);
		return KNOT_ENOENT;
	}

	redisReply *addr_reply = redisCommand(rdb, "SENTINEL get-master-addr-by-name %s",
	                                      master_name);
	freeReplyObject(masters_reply);

	if (addr_reply == NULL || addr_reply->type != REDIS_REPLY_ARRAY ||
	    addr_reply->elements != 2) {
		if (addr_reply != NULL) {
			freeReplyObject(addr_reply);
		}
		return KNOT_ENOENT;
	}
	const char *ip_str = addr_reply->element[0]->str;
	const char *port_str = addr_reply->element[1]->str;

	size_t len = strlcpy(out, ip_str, out_len);
	if (len == 0 || len >= out_len) {
		freeReplyObject(addr_reply);
		return KNOT_ERANGE;
	}

	uint16_t num;
	int ret = str_to_u16(port_str, &num);
	if (ret != KNOT_EOK || num == 0) {
		freeReplyObject(addr_reply);
		return KNOT_EINVAL;
	}
	*port = num;

	freeReplyObject(addr_reply);

	return KNOT_EOK;
}

redisContext *rdb_connect(conf_t *conf, bool require_master)
{
	int port = 0;
	int role = -1;
	char addr_str[SOCKADDR_STRLEN - SOCKADDR_STRLEN_EXT] = "\0";
	redisContext *rdb = NULL;

	conf_val_t db_listen = conf_db_param(conf, C_ZONE_DB_LISTEN);
	while (db_listen.code == KNOT_EOK) {
		struct sockaddr_storage addr = conf_addr(&db_listen, NULL);

		rdb = (void *)conn_pool_get(global_redis_pool, &addr, &addr);
		if (rdb != NULL && (intptr_t)rdb != CONN_POOL_FD_INVALID) {
			role = zone_redis_role(rdb);
			if (!require_master || role == 0) {
				goto connected;
			}
			redisFree(rdb);
		}

		conf_val_next(&db_listen);
	}

	conf_val_reset(&db_listen);
	while (db_listen.code == KNOT_EOK) {
		struct sockaddr_storage addr = conf_addr(&db_listen, NULL);

		if (rdb_addr_to_str(&addr, addr_str, sizeof(addr_str), &port) != KNOT_EOK ||
		    (rdb = connect_addr(conf, addr_str, port)) == NULL) {
			conf_val_next(&db_listen);
			continue;
		}

		role = zone_redis_role(rdb);
		if (role == 0) { // Master
			goto connected;
		} else if (role == 1 && !require_master) { // Replica
			goto connected;
		} else if (role == 2) { // Sentinel
			if (get_master(rdb, addr_str, sizeof(addr_str), &port) == KNOT_EOK &&
			    (rdb = connect_addr(conf, addr_str, port)) == KNOT_EOK) {
				goto connected;
			}
		}

		conf_val_next(&db_listen);
	}

	return NULL;

connected:
	if (log_enabled_debug()) {
		bool tcp = rdb->connection_type == REDIS_CONN_TCP;
		bool pool = addr_str[0] == '\0';
		bool tls = false;
#ifdef ENABLE_REDIS_TLS
		tls = rdb->privctx != NULL;
#endif // ENABLE_REDIS_TLS
		log_debug("rdb, connected, remote %s%s%.0u%s%s%s",
		          (tcp ? rdb->tcp.host : rdb->unix_sock.path),
		          (tcp ? "@" : ""),
		          (tcp ? rdb->tcp.port : 0),
		          (tls ? " TLS" : ""),
		          (role == 1 ? " replica" : ""),
		          (pool ? " pool" : ""));
	}

	return rdb;
}

void rdb_disconnect(redisContext *rdb, bool pool_save)
{
	if (rdb != NULL && pool_save) {
		struct sockaddr_storage addr = { 0 };
		// struct redisContext seems not to have a way to read out sockaddr, only a string, so try-and-error parse the string
		if (sockaddr_set(&addr, AF_INET6, rdb->tcp.host, rdb->tcp.port) == KNOT_EOK ||
		    sockaddr_set(&addr, AF_INET, rdb->tcp.host, rdb->tcp.port) == KNOT_EOK ||
		    sockaddr_set(&addr, AF_UNIX, rdb->unix_sock.path, 0) == KNOT_EOK) {
			rdb = (void *)conn_pool_put(global_redis_pool, &addr, &addr, (intptr_t)rdb);
		}
	}

	if (rdb != NULL && (intptr_t)rdb != CONN_POOL_FD_INVALID) {
		redisFree(rdb);
	}
}

bool rdb_compatible(redisContext *rdb)
{
	if (rdb == NULL) {
		return false;
	}

#ifdef ENDIANITY_LITTLE
  #define ENDIAN 1
#else
  #define ENDIAN 0
#endif

	const char *lua = "local n=1; local s=string.dump(function() return n end); " \
	                  "local e=string.byte(s,7); if e==0 then return 0 else return 1 end";

	redisReply *reply = redisCommand(rdb, "EVAL %s 0", lua);
	bool res = (reply != NULL &&
	            reply->type == REDIS_REPLY_INTEGER &&
	            reply->integer == ENDIAN);
	freeReplyObject(reply);
	return res;
}
