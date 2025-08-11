/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <string.h>

#include "knot/zone/redis.h"
#include "knot/zone/contents.h"

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

void zone_redis_disconnect(struct redisContext *ctx, bool pool_save)
{
	return rdb_disconnect(ctx, pool_save);
}

bool zone_redis_ping(struct redisContext *ctx)
{
	if (ctx == NULL) {
		return false;
	}

	redisReply *reply = redisCommand(ctx, "PING");
	bool res = (reply != NULL &&
	            reply->type == REDIS_REPLY_STATUS &&
	            strcmp(reply->str, "PONG") == 0);
	freeReplyObject(reply);
	return res;
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

	redisReply *reply = redisCommand(rdb, RDB_CMD_ZONE_EXISTS " %b %b",
	                                 zone, knot_dname_size(zone),
	                                 &instance, sizeof(instance));
	if (reply != NULL && reply->type == REDIS_REPLY_INTEGER) {
		*serial = reply->integer;
		freeReplyObject(reply);
		return KNOT_EOK;
	} else {
		freeReplyObject(reply);
		return KNOT_ENOENT;
	}
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

static int process_rdb_upd(zone_redis_load_upd_cb_t cb, void *ctx, redisReply *data)
{
	knot_dname_t *r_owner = (knot_dname_t *)data->element[0]->str;
	uint16_t r_type = data->element[1]->integer;
	uint32_t r_ttl_rem = data->element[2]->integer;
	uint32_t r_ttl_add = data->element[3]->integer;
	knot_rdataset_t r_data_rem = {
		.count = data->element[4]->integer,
		.size = data->element[5]->len,
		.rdata = (knot_rdata_t *)data->element[5]->str
	};
	knot_rdataset_t r_data_add = {
		.count = data->element[6]->integer,
		.size = data->element[7]->len,
		.rdata = (knot_rdata_t *)data->element[7]->str
	};

	knot_dname_t *owner = knot_dname_copy(r_owner, NULL);
	if (owner == NULL) {
		return KNOT_ENOMEM;
	}

	knot_rrset_t rrs;
	knot_rrset_init(&rrs, owner, r_type, KNOT_CLASS_IN, r_ttl_rem);

	int ret = knot_rdataset_copy(&rrs.rrs, &r_data_rem, NULL);
	if (ret == KNOT_EOK) {
		ret = cb(&rrs, false, ctx);
	}
	if (ret == KNOT_EOK) {
		knot_rdataset_clear(&rrs.rrs, NULL);
		ret = knot_rdataset_copy(&rrs.rrs, &r_data_add, NULL);
		rrs.ttl = r_ttl_add;
	}
	if (ret == KNOT_EOK) {
		ret = cb(&rrs, true, ctx);
	}

	knot_rrset_clear(&rrs, NULL);
	return ret;
}

int zone_redis_load_upd(struct redisContext *rdb, uint8_t instance,
                        const knot_dname_t *zone_name, uint32_t soa_from,
                        zone_redis_load_upd_cb_t cb, void *ctx,
                        char log_err[256])
{
	if (rdb == NULL || zone_name == NULL || cb == NULL) {
		return KNOT_EINVAL;
	}

	int ret = KNOT_EOK;
	redisReply *reply = redisCommand(rdb, RDB_CMD_UPD_LOAD " %b %b %d",
	                                 zone_name, knot_dname_size(zone_name),
	                                 &instance, sizeof(instance),
	                                 soa_from);
	if (reply == NULL) {
		snprintf(log_err, 256, "failed to connect to database");
		return error_from_redis(rdb->err);
	} else if (reply->type == REDIS_REPLY_ERROR) {
		snprintf(log_err, 256, "failed to load from database (%s)", reply->str);
		ret = KNOT_ERROR;
	} else if (reply->type != REDIS_REPLY_ARRAY) {
		snprintf(log_err, 256, "failed to load from database (bad data)");
		ret = KNOT_EMALF;
	} else if (reply->elements == 0) {
		ret = KNOT_ENOENT;
	}

	for (size_t i = 0; i < reply->elements && ret == KNOT_EOK; i++) {
		redisReply *changeset = reply->element[i];
		for (size_t j = 0; j < changeset->elements && ret == KNOT_EOK; j++) {
			redisReply *data = changeset->element[j];
			ret = process_rdb_upd(cb, ctx, data);
			if (ret != KNOT_EOK) {
				snprintf(log_err, 256, "failed to process database data (%s)", knot_strerror(ret));
			}
		}
	}

	freeReplyObject(reply);
	return ret;
}

#else // ENABLE_REDIS

struct redisContext *zone_redis_connect(conf_t *conf)
{
	return NULL;
}

void zone_redis_disconnect(struct redisContext *ctx, bool pool_save)
{
	return;
}

bool zone_redis_ping(struct redisContext *ctx)
{
	return false;
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

int zone_redis_load_upd(struct redisContext *rdb, uint8_t instance,
                        const knot_dname_t *zone_name, uint32_t soa_from,
                        zone_redis_load_upd_cb_t cb, void *ctx,
                        char log_err[256])
{
	return KNOT_ENOTSUP;
}

#endif // ENABLE_REDIS
