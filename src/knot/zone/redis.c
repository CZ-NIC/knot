/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include "knot/zone/redis.h"

#include <string.h>

#ifdef ENABLE_REDIS

#include "knot/common/hiredis.h"

struct redisContext *zone_redis_connect(conf_t *conf)
{
	return rdb_connect(conf);
}

void zone_redis_disconnect(struct redisContext *ctx)
{
	return rdb_disconnect(ctx);
}

static int check_reply(struct redisContext *rdb, redisReply *reply,
                       int expected_type, zone_redis_err_t err)
{
	if (reply == NULL) {
		if (rdb->err != REDIS_OK) {
			strlcpy(err, rdb->errstr, sizeof(zone_redis_err_t));
		} else {
			strlcpy(err, "no reply", sizeof(zone_redis_err_t));
		}
		return KNOT_ERDB;
	} else if (reply->type == REDIS_REPLY_ERROR) {
		strlcpy(err, reply->str, sizeof(zone_redis_err_t));
		return KNOT_ERDB;
	} else if (reply->type != expected_type) {
		strlcpy(err, "unexpected reply", sizeof(zone_redis_err_t));
		return KNOT_ERDB;
	} else if (reply->type == REDIS_REPLY_ARRAY && reply->elements == 0) {
		return KNOT_ENOENT;
	} else if (reply->type == REDIS_REPLY_STATUS && strcmp(RDB_RETURN_OK, reply->str) != 0) {
		return KNOT_EACCES;
	}

	return KNOT_EOK;
}

int zone_redis_txn_begin(zone_redis_txn_t *txn, struct redisContext *rdb,
                         uint8_t instance, const knot_dname_t *zone_name,
                         bool incremental)
{
	if (txn == NULL || rdb == NULL || zone_name == NULL) {
		return KNOT_EINVAL;
	}

	txn->rdb = rdb;
	txn->instance = instance;
	txn->origin = zone_name;
	txn->origin_len = knot_dname_size(zone_name);
	txn->incremental = incremental;
	txn->removals = false;
	txn->err[0] = '\0';

	const char *cmd = txn->incremental ? RDB_CMD_UPD_BEGIN  " %b %b" :
	                                     RDB_CMD_ZONE_BEGIN " %b %b";

	redisReply *reply = redisCommand(txn->rdb, cmd, txn->origin, txn->origin_len,
	                                 &txn->instance, sizeof(txn->instance));
	int ret = check_reply(rdb, reply, REDIS_REPLY_STRING, txn->err);
	if (ret != KNOT_EOK) {
		freeReplyObject(reply);
		return ret;
	}
	if (reply->len != sizeof(txn->rdb_txn)) {
		freeReplyObject(reply);
		return KNOT_EMALF;
	}

	memcpy(&txn->rdb_txn, reply->str, sizeof(txn->rdb_txn));
	freeReplyObject(reply);

	return KNOT_EOK;
}

int zone_redis_write_rrset(zone_redis_txn_t *txn, const knot_rrset_t *rr)
{
	if (txn == NULL || rr == NULL || (txn->removals && !txn->incremental)) {
		return KNOT_EINVAL;
	}

	const char *cmd = !txn->incremental ? RDB_CMD_ZONE_STORE " %b %b %b %d %d %d %b" :
	                  txn->removals ?     RDB_CMD_UPD_REMOVE " %b %b %b %d %d %d %b" :
	                                      RDB_CMD_UPD_ADD    " %b %b %b %d %d %d %b";

	redisReply *reply = redisCommand(txn->rdb, cmd, txn->origin, txn->origin_len,
	                                 &txn->rdb_txn, sizeof(txn->rdb_txn),
	                                 rr->owner, knot_dname_size(rr->owner), rr->type, rr->ttl,
	                                 rr->rrs.count, rr->rrs.rdata, rr->rrs.size);
	int ret = check_reply(txn->rdb, reply, REDIS_REPLY_STATUS, txn->err);
	if (ret != KNOT_EOK) {
		return ret;
	}

	freeReplyObject(reply);

	return KNOT_EOK;
}

int zone_redis_write_node(zone_redis_txn_t *txn, const zone_node_t *node)
{
	if (txn == NULL || node == NULL) {
		return KNOT_EINVAL;
	}

	int ret = KNOT_EOK;
	for (uint16_t i = 0; i < node->rrset_count && ret == KNOT_EOK; i++) {
		knot_rrset_t rrset = node_rrset_at(node, i);
		ret = zone_redis_write_rrset(txn, &rrset);
	}

	return ret;
}

int zone_redis_txn_commit(zone_redis_txn_t *txn)
{
	if (txn == NULL) {
		return KNOT_EINVAL;
	}

	const char *cmd = txn->incremental ? RDB_CMD_UPD_COMMIT  " %b %b" :
	                                     RDB_CMD_ZONE_COMMIT " %b %b";

	redisReply *reply = redisCommand(txn->rdb, cmd, txn->origin, txn->origin_len,
	                                 &txn->rdb_txn, sizeof(txn->rdb_txn));
	int ret = check_reply(txn->rdb, reply, REDIS_REPLY_STATUS, txn->err);
	if (ret != KNOT_EOK) {
		freeReplyObject(reply);
		return ret;
	}

	memset(txn, 0, sizeof(*txn));
	freeReplyObject(reply);

	return KNOT_EOK;
}

int zone_redis_txn_abort(zone_redis_txn_t *txn)
{
	if (txn == NULL) {
		return KNOT_EINVAL;
	}

	const char *cmd = txn->incremental ? RDB_CMD_UPD_ABORT  " %b %b" :
	                                     RDB_CMD_ZONE_ABORT " %b %b";

	redisReply *reply = redisCommand(txn->rdb, cmd, txn->origin, txn->origin_len,
	                                 &txn->rdb_txn, sizeof(txn->rdb_txn));
	int ret = check_reply(txn->rdb, reply, REDIS_REPLY_STATUS, txn->err);
	if (ret != KNOT_EOK) {
		freeReplyObject(reply);
		return ret;
	}

	memset(txn, 0, sizeof(*txn));
	freeReplyObject(reply);

	return KNOT_EOK;
}

#else // ENABLE_REDIS

struct redisContext *zone_redis_connect(conf_t *conf)
{
	return NULL;
}

void zone_redis_disconnect(struct redisContext *ctx)
{
	return;
}

int zone_redis_txn_begin(zone_redis_txn_t *txn, struct redisContext *rdb,
                         uint8_t instance, const knot_dname_t *zone_name,
                         bool incremental)
{
	return KNOT_ENOTSUP;
}

int zone_redis_write_rrset(zone_redis_txn_t *txn, const knot_rrset_t *rr)
{
	return KNOT_ENOTSUP;
}

int zone_redis_write_node(zone_redis_txn_t *txn, const zone_node_t *node)
{
	return KNOT_ENOTSUP;
}

int zone_redis_txn_commit(zone_redis_txn_t *txn)
{
	return KNOT_ENOTSUP;
}

int zone_redis_txn_abort(zone_redis_txn_t *txn)
{
	return KNOT_ENOTSUP;
}

#endif // ENABLE_REDIS
