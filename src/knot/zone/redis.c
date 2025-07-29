/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include "knot/zone/contents.h"
#include "knot/zone/redis.h"

#include <string.h>

#ifdef ENABLE_REDIS

#include "knot/common/hiredis.h"

static int error_from_redis(int code)
{
	return code ? code : KNOT_ECONN; // FIXME
}

struct redisContext *zone_redis_connect(conf_t *conf)
{
	return rdb_connect(conf);
}

int zone_redis_txn_begin(struct zone_redis_txn *txn, struct redisContext *rdb,
                         uint8_t instance,
                         const knot_dname_t *zone_name, bool incremental)
{
	if (txn == NULL || zone_name == NULL || txn->rdb != NULL) {
		return KNOT_EINVAL;
	}

	txn->rdb = rdb;
	txn->instance = instance;
	txn->origin = zone_name; // TODO copy to heap?
	txn->origin_len = knot_dname_size(zone_name);
	txn->incremental = incremental;

	const char *cmd = txn->incremental ? RDB_CMD_UPD_BEGIN " %b %b" : RDB_CMD_ZONE_BEGIN " %b %b";

	redisReply *reply = redisCommand(txn->rdb, cmd, txn->origin, txn->origin_len,
	                                 &txn->instance, sizeof(txn->instance));
	if (reply == NULL) {
		return error_from_redis(rdb->err);
	} else if (reply->type != REDIS_REPLY_STRING || reply->len != sizeof(txn->rdb_txn)) {
		printf("begin %s\n", reply->str);
		freeReplyObject(reply);
		return KNOT_EMALF;
	}

	memcpy(&txn->rdb_txn, reply->str, sizeof(txn->rdb_txn));
	freeReplyObject(reply);

	return KNOT_EOK;
}

int zone_redis_write_rrset(struct zone_redis_txn *txn, const knot_rrset_t *rr)
{
	if (txn == NULL || rr == NULL || (txn->removals && !txn->incremental)) {
		return KNOT_EINVAL;
	}

	const char *cmd = !txn->incremental ? RDB_CMD_ZONE_STORE " %b %b %b %d %d %d %b" :
		txn->removals ? RDB_CMD_UPD_REMOVE " %b %b %b %d %d %d %b" : RDB_CMD_UPD_ADD " %b %b %b %d %d %d %b";

	redisReply *reply = redisCommand(txn->rdb, cmd, txn->origin, txn->origin_len,
	                                 &txn->rdb_txn, sizeof(txn->rdb_txn),
	                                 rr->owner, knot_dname_size(rr->owner), rr->type, rr->ttl,
	                                 rr->rrs.count, rr->rrs.rdata, rr->rrs.size);
	if (reply == NULL) {
		return error_from_redis(txn->rdb->err);
	} else if (reply->type != REDIS_REPLY_STATUS ||
	           memcmp(RDB_RETURN_OK, reply->str, reply->len) != 0) {
		printf("wr rr %s\n", reply->str);
		freeReplyObject(reply);
		return KNOT_EACCES;
	}
	freeReplyObject(reply);
	return KNOT_EOK;
}

int zone_redis_write_node(struct zone_redis_txn *txn, const zone_node_t *node)
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

int zone_redis_txn_commit(struct zone_redis_txn *txn)
{
	if (txn == NULL) {
		return KNOT_EINVAL;
	}

	const char *cmd = txn->incremental ? RDB_CMD_UPD_COMMIT " %b %b" : RDB_CMD_ZONE_COMMIT " %b %b";

	redisReply *reply = redisCommand(txn->rdb, cmd, txn->origin, txn->origin_len,
	                                 &txn->rdb_txn, sizeof(txn->rdb_txn));
	if (reply == NULL) {
		return error_from_redis(txn->rdb->err);
	} else if (reply->type != REDIS_REPLY_STATUS ||
	           memcmp(RDB_RETURN_OK, reply->str, reply->len) != 0) {
		printf("commit %s\n", reply->str);
		freeReplyObject(reply);
		return KNOT_EACCES;
	}
	freeReplyObject(reply);

	memset(txn, 0, sizeof(*txn));

	return KNOT_EOK;
}

int zone_redis_txn_abort(struct zone_redis_txn *txn)
{
	if (txn == NULL) {
		return KNOT_EINVAL;
	}

	const char *cmd = txn->incremental ? RDB_CMD_UPD_ABORT " %b %b" : RDB_CMD_ZONE_ABORT " %b %b";

	redisReply *reply = redisCommand(txn->rdb, cmd, txn->origin, txn->origin_len,
	                                 &txn->rdb_txn, sizeof(txn->rdb_txn));
	if (reply == NULL) {
		return error_from_redis(txn->rdb->err);
	} else if (reply->type != REDIS_REPLY_STATUS ||
	           memcmp(RDB_RETURN_OK, reply->str, reply->len) != 0) {
		freeReplyObject(reply);
		return KNOT_EACCES;
	}
	freeReplyObject(reply);

	memset(txn, 0, sizeof(*txn));

	return KNOT_EOK;
}

static int process_rdb_rr(zone_contents_t *contents, redisReply *data)
{
	knot_dname_t *r_owner = (knot_dname_t *)data->element[0]->str;
	uint16_t r_type = data->element[1]->integer;
	uint32_t r_ttl = data->element[2]->integer;
	knot_rdataset_t r_data = {
	        .count = data->element[3]->integer,
	        .size = data->element[4]->len,
	        .rdata = (knot_rdata_t *)data->element[4]->str
	};

	knot_dname_t *owner = knot_dname_copy(r_owner, NULL);
	if (owner == NULL) {
		return KNOT_ENOMEM;
	}

	knot_rrset_t rrs;
	knot_rrset_init(&rrs, owner, r_type, KNOT_CLASS_IN, r_ttl);

	int ret = knot_rdataset_copy(&rrs.rrs, &r_data, NULL);
	if (ret == KNOT_EOK) {
		zone_node_t *n = NULL;
		ret = zone_contents_add_rr(contents, &rrs, &n);
	}
	knot_rrset_clear(&rrs, NULL);
	return ret;
}

int zone_redis_serial(struct redisContext *rdb, uint8_t instance,
                      const knot_dname_t *zone, uint32_t *serial)
{
	if (rdb == NULL || zone == NULL || serial == NULL) {
		return KNOT_EINVAL;
	}

	int64_t val = -1;
	redisReply *reply = redisCommand(rdb, RDB_CMD_ZONE_EXISTS " %b %b",
	                                 zone, knot_dname_size(zone),
	                                 &instance, sizeof(instance));
	if (reply != NULL && reply->type == REDIS_REPLY_INTEGER) {
		val = reply->integer;
	}
	freeReplyObject(reply);

	redisFree(rdb);

	return (val != -1) ? KNOT_EOK : KNOT_ENOENT;
}

int zone_redis_load(struct redisContext *rdb, uint8_t instance,
                    const knot_dname_t *zone_name, struct zone_contents **out,
                    char log_err[256])
{
	if (rdb == NULL || zone_name == NULL || out == NULL) {
		return KNOT_EINVAL;
	}

	zone_contents_t *c = zone_contents_new(zone_name, true);
	if (c == NULL) {
		return KNOT_ENOMEM;
	}

	int ret = KNOT_EOK;
	redisReply *reply = redisCommand(rdb, RDB_CMD_ZONE_LOAD " %b %b",
	                                 zone_name, knot_dname_size(zone_name),
	                                 &instance, sizeof(instance));
	if (reply == NULL) {
		ret = error_from_redis(rdb->err);
		snprintf(log_err, 256, "failed to connect to database");
		goto finish;
	} else if (reply->type == REDIS_REPLY_ERROR) {
		ret = KNOT_ERROR;
		snprintf(log_err, 256, "failed to load from database (%s)", reply->str);
		goto finish;
	} else if (reply->type != REDIS_REPLY_ARRAY) {
		ret = KNOT_EMALF;
		snprintf(log_err, 256, "failed to load from database (bad data)");
		goto finish;
	}

	for (size_t i = 0; i < reply->elements; i++) {
		redisReply *data = reply->element[i];
		ret = process_rdb_rr(c, data);
		if (ret != KNOT_EOK) {
			snprintf(log_err, 256, "failed to process database data (%s)", knot_strerror(ret));
			goto finish;
		}
	}

finish:
	if (reply != NULL) {
		freeReplyObject(reply);
	}
	if (ret == KNOT_EOK) {
		*out = c;
	} else {
		zone_contents_deep_free(c);
	}
	return ret;
}

#else // ENABLE_REDIS

struct redisContext *zone_redis_connect(conf_t *conf)
{
	return NULL;
}

int zone_redis_txn_begin(struct zone_redis_txn *txn, struct redisContext *rdb,
                         uint8_t instance,
                         const knot_dname_t *zone_name, bool incremental)
{
	return KNOT_ENOTSUP;
}

int zone_redis_write_rrset(struct zone_redis_txn *txn, const knot_rrset_t *rr)
{
	return KNOT_ENOTSUP;
}

int zone_redis_write_node(struct zone_redis_txn *txn, const zone_node_t *node)
{
	return KNOT_ENOTSUP;
}

int zone_redis_txn_commit(struct zone_redis_txn *txn)
{
	return KNOT_ENOTSUP;
}

int zone_redis_txn_abort(struct zone_redis_txn *txn)
{
	return KNOT_ENOTSUP;
}

int zone_redis_serial(struct redisContext *rdb, uint8_t instance,
                      const knot_dname_t *zone, uint32_t *serial)
{
	return KNOT_ENOTSUP;
}

int zone_redis_load(struct redisContext *rdb, uint8_t instance,
                    const knot_dname_t *zone_name, struct zone_contents **out,
                    char log_err[256])
{
	return KNOT_ENOTSUP;
}

#endif // ENABLE_REDIS
