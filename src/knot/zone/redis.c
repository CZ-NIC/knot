/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <string.h>

#include "knot/zone/redis.h"
#include "knot/zone/contents.h"

#ifdef ENABLE_REDIS
#include "contrib/openbsd/strlcpy.h"
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

int zone_redis_serial(struct redisContext *rdb, uint8_t instance,
                      const knot_dname_t *zone, uint32_t *serial,
                      zone_redis_err_t err)
{
	if (rdb == NULL) {
		return KNOT_NET_ECONNECT;
	} else if (zone == NULL || serial == NULL || err == NULL) {
		return KNOT_EINVAL;
	}

	redisReply *reply = redisCommand(rdb, RDB_CMD_ZONE_EXISTS " %b %b",
	                                 zone, knot_dname_size(zone),
	                                 &instance, sizeof(instance));
	int ret = check_reply(rdb, reply, REDIS_REPLY_INTEGER, err);
	if (ret != KNOT_EOK) {
		freeReplyObject(reply);
		return ret;
	}

	*serial = reply->integer;
	freeReplyObject(reply);

	return KNOT_EOK;
}

static int process_rdb_rr(zone_contents_t *contents, redisReply *data)
{
	if (data->elements != 5) {
		return KNOT_EMALF;
	}

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

int zone_redis_load(struct redisContext *rdb, uint8_t instance,
                    const knot_dname_t *zone_name, struct zone_contents **out,
                    zone_redis_err_t err)
{
	if (rdb == NULL) {
		return KNOT_NET_ECONNECT;
	} else if (zone_name == NULL || out == NULL || err == NULL) {
		return KNOT_EINVAL;
	}

	redisReply *reply = redisCommand(rdb, RDB_CMD_ZONE_LOAD " %b %b",
	                                 zone_name, knot_dname_size(zone_name),
	                                 &instance, sizeof(instance));
	int ret = check_reply(rdb, reply, REDIS_REPLY_ARRAY, err);
	if (ret != KNOT_EOK) {
		freeReplyObject(reply);
		return ret;
	}

	zone_contents_t *cont = zone_contents_new(zone_name, true);
	if (cont == NULL) {
		freeReplyObject(reply);
		return KNOT_ENOMEM;
	}

	for (size_t i = 0; i < reply->elements; i++) {
		redisReply *data = reply->element[i];
		ret = process_rdb_rr(cont, data);
		if (ret != KNOT_EOK) {
			break;
		}
	}

	if (ret == KNOT_EOK) {
		*out = cont;
	} else {
		zone_contents_deep_free(cont);
	}

	freeReplyObject(reply);

	return ret;
}

static int process_rdb_upd(zone_redis_load_upd_cb_t cb, void *ctx, redisReply *data)
{
	if (data->elements != 8) {
		return KNOT_EMALF;
	}

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
                        zone_redis_err_t err)
{
	if (rdb == NULL) {
		return KNOT_NET_ECONNECT;
	} else if (zone_name == NULL || cb == NULL || err == NULL) {
		return KNOT_EINVAL;
	}

	redisReply *reply = redisCommand(rdb, RDB_CMD_UPD_LOAD " %b %b %d",
	                                 zone_name, knot_dname_size(zone_name),
	                                 &instance, sizeof(instance), soa_from);
	int ret = check_reply(rdb, reply, REDIS_REPLY_ARRAY, err);
	if (ret != KNOT_EOK) {
		freeReplyObject(reply);
		return ret;
	}

	for (size_t i = 0; i < reply->elements && ret == KNOT_EOK; i++) {
		redisReply *changeset = reply->element[i];
		for (size_t j = 0; j < changeset->elements && ret == KNOT_EOK; j++) {
			redisReply *data = changeset->element[j];
			ret = process_rdb_upd(cb, ctx, data);
			if (ret != KNOT_EOK) {
				break;
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

int zone_redis_serial(struct redisContext *rdb, uint8_t instance,
                      const knot_dname_t *zone, uint32_t *serial,
                      zone_redis_err_t err)
{
	return KNOT_ENOTSUP;
}

int zone_redis_load(struct redisContext *rdb, uint8_t instance,
                    const knot_dname_t *zone_name, struct zone_contents **out,
                    zone_redis_err_t err)
{
	return KNOT_ENOTSUP;
}

int zone_redis_load_upd(struct redisContext *rdb, uint8_t instance,
                        const knot_dname_t *zone_name, uint32_t soa_from,
                        zone_redis_load_upd_cb_t cb, void *ctx,
                        zone_redis_err_t err)
{
	return KNOT_ENOTSUP;
}

#endif // ENABLE_REDIS
