/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: LGPL-2.1-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define REDISMODULE_MAIN // Fixes loading error undefined symbol: RedisModule_ReplySetArrayLength.
#include "contrib/redis/redismodule.h"
#include "redis/knot.h"
#include "redis/libs.h"
#include "redis/arg.h"

#define RRSET_ENCODING_VERSION	1

#define SCORE_SOA		0.
#define SCORE_DEFAULT		1.

#define INSTANCE_MIN		1
#define INSTANCE_MAX		8
#define TXN_MIN			0
#define TXN_MAX			8
#define TXN_MAX_COUNT		(TXN_MAX - TXN_MIN + 1)
#define TXN_ID_ACTIVE		UINT8_MAX
#define ZONE_META_INACTIVE	UINT8_MAX
#define TTL_EMPTY		UINT32_MAX

#define RRSET_KEY_MAXLEN (RDB_PREFIX_LEN + 1 + KNOT_DNAME_MAXLEN + KNOT_DNAME_MAXLEN + sizeof(uint16_t) + sizeof(uint16_t))
#define TXN_KEY_MAXLEN (RDB_PREFIX_LEN + 1 + KNOT_DNAME_MAXLEN + sizeof(uint8_t))

#define foreach_in_zset_subset(key, min, max) \
	for (RedisModule_ZsetFirstInScoreRange(key, min, max, 0, 0); \
	     RedisModule_ZsetRangeEndReached(key) == 0; \
	     RedisModule_ZsetRangeNext(key))
#define foreach_in_zset(key) foreach_in_zset_subset(key, REDISMODULE_NEGATIVE_INFINITE, REDISMODULE_POSITIVE_INFINITE)

#define zone_meta_keyname_construct(...) meta_keyname_construct(ZONE_META, __VA_ARGS__)
#define upd_meta_keyname_construct(...)  meta_keyname_construct(UPD_META, __VA_ARGS__)

#define delete_zone_index(...)  delete_index(ZONE, __VA_ARGS__)
#define delete_upd_index(...)  delete_index(UPD_TMP, __VA_ARGS__)

#define knot_upd_add_txt(ctx, origin, txn, owner, ttl, rtype, rdataset) upd_add_rem((ctx), (origin), (txn), (owner), (ttl), (rtype), (rdataset), upd_add_txt_cb)
#define knot_upd_remove_txt(ctx, origin, txn, owner, ttl, rtype, rdataset) upd_add_rem((ctx), (origin), (txn), (owner), (ttl), (rtype), (rdataset), upd_remove_txt_cb)
#define knot_upd_add_bin(ctx, origin, txn, owner, ttl, rtype, rdataset) upd_add_rem((ctx), (origin), (txn), (owner), (ttl), (rtype), (rdataset), upd_add_bin_cb)
#define knot_upd_remove_bin(ctx, origin, txn, owner, ttl, rtype, rdataset) upd_add_rem((ctx), (origin), (txn), (owner), (ttl), (rtype), (rdataset), upd_remove_bin_cb)

typedef enum {
	EVENT     = 1, // Keep synchronized with RDB_EVENT_KEY!
	ZONE_META = 2,
	ZONE      = 3,
	RRSET     = 4,
	UPD_META  = 5,
	UPD_TMP   = 6,
	UPD       = 7,
	DIFF      = 8,
} rdb_type_t;

typedef struct {
	uint32_t ttl;
	knot_rdataset_t rrs;
} rrset_v;

typedef struct {
	knot_rdataset_t add_rrs;
	knot_rdataset_t remove_rrs;
	uint32_t dest_ttl;
} diff_v;

typedef struct {
	uint8_t active;
	uint8_t lock[TXN_MAX_COUNT];
} zone_meta_storage_t;

typedef struct {
	uint16_t counter;
	uint16_t lock[TXN_MAX_COUNT];
} upd_meta_storage_t;

typedef struct {
	RedisModuleCtx *ctx;
	rdb_txn_t *txn;
	bool replied;
	bool remove;
} scanner_ctx_t;

static uint32_t rdb_default_ttl = 600;
static uint32_t rdb_event_age = 1200;

static RedisModuleType *knot_zone_rrset_t;
static RedisModuleType *knot_diff_t;

static void *redismodule_alloc(void *ptr, size_t bytes);
static void redismodule_free(void *ptr);

static knot_mm_t mm = {
	.alloc = redismodule_alloc,
	.ctx = NULL,
	.free = redismodule_free
};

static RedisModuleString *meta_keyname_construct(const uint8_t prefix, RedisModuleCtx *ctx,
                                                 const arg_dname_t *origin, uint8_t instance)
{
	char buf[TXN_KEY_MAXLEN];

	wire_ctx_t w = wire_ctx_init((uint8_t *)buf, sizeof(buf));
	wire_ctx_write(&w, RDB_PREFIX, RDB_PREFIX_LEN);
	wire_ctx_write(&w, &prefix, sizeof(prefix));
	wire_ctx_write(&w, origin->data, origin->len);
	wire_ctx_write(&w, &instance, sizeof(instance));
	RedisModule_Assert(w.error == KNOT_EOK);

	return RedisModule_CreateString(ctx, buf, wire_ctx_offset(&w));
}

static bool zone_txn_get_when_open(RedisModuleCtx *ctx, const arg_dname_t *origin,
                                   const rdb_txn_t *txn, RedisModuleKey **key, int rights)
{
	RedisModule_Assert(key != NULL && *key == NULL);

	RedisModuleString *txn_k = zone_meta_keyname_construct(ctx, origin, txn->instance);
	*key = RedisModule_OpenKey(ctx, txn_k, rights);
	RedisModule_FreeString(ctx, txn_k);
	if (key == NULL || RedisModule_KeyType(*key) != REDISMODULE_KEYTYPE_STRING) {
		return false;
	}
	size_t len = 0;
	const zone_meta_storage_t *meta = (const zone_meta_storage_t *)RedisModule_StringDMA(*key, &len, REDISMODULE_READ);
	return txn->id != meta->active && meta->lock[txn->id] != 0;
}

static bool zone_txn_is_open(RedisModuleCtx *ctx, const arg_dname_t *origin, const rdb_txn_t *txn)
{
	RedisModuleKey *key = NULL;
	bool out = zone_txn_get_when_open(ctx, origin, txn, &key, REDISMODULE_READ);
	RedisModule_CloseKey(key);
	return out;
}

static void *rrset_load(RedisModuleIO *rdb, int encver)
{
	if (encver != RRSET_ENCODING_VERSION) {
		// TODO ignore or version compatibility layers
		return NULL;
	}

	rrset_v *rrset = RedisModule_Alloc(sizeof(rrset_v));
	if (rrset == NULL) {
		return NULL;
	}
	size_t len = 0;
	rrset->ttl = RedisModule_LoadUnsigned(rdb);
	rrset->rrs.count = RedisModule_LoadUnsigned(rdb);
	rrset->rrs.rdata = (knot_rdata_t *)RedisModule_LoadStringBuffer(rdb, &len);
	if (len > UINT32_MAX) {
		RedisModule_Free(rrset->rrs.rdata);
		RedisModule_Free(rrset);
		return NULL;
	}
	rrset->rrs.size = len;
	return rrset;
}

static void rrset_save(RedisModuleIO *rdb, void *value)
{
	rrset_v *rrset = (rrset_v *)value;
	RedisModule_SaveUnsigned(rdb, rrset->ttl);
	RedisModule_SaveUnsigned(rdb, rrset->rrs.count);
	RedisModule_SaveStringBuffer(rdb, (const char *)rrset->rrs.rdata, rrset->rrs.size);
}

static size_t rrset_mem_usage(const void *value)
{
	const rrset_v *rrset = (const rrset_v *)value;
	if (value == NULL) {
		return 0UL;
	}
	return sizeof(*rrset) + rrset->rrs.size;
}

static void rrset_rewrite(RedisModuleIO *aof, RedisModuleString *key, void *value)
{
	size_t key_strlen = 0;
	const rrset_v *rrset = (const rrset_v *)value;
	const uint8_t *key_str = (const uint8_t *)RedisModule_StringPtrLen(key, &key_strlen);
	RedisModule_EmitAOF(aof, "KNOT_BIN.AOF.RRSET", "bllb",
	                    key_str, key_strlen,
	                    (long long)rrset->ttl,
	                    (long long)rrset->rrs.count,
	                    rrset->rrs.rdata, rrset->rrs.size);
}

static void rrset_free(void *value)
{
	rrset_v *rrset = (rrset_v *)value;
	RedisModule_Free(rrset->rrs.rdata);
	RedisModule_Free(rrset);
}

static void *diff_load(RedisModuleIO *rdb, int encver)
{
	if (encver != RRSET_ENCODING_VERSION) {
		// TODO ignore or version compatibility layers
		return NULL;
	}

	diff_v *diff = RedisModule_Alloc(sizeof(diff_v));
	if (diff == NULL) {
		return NULL;
	}
	size_t len = 0;
	diff->add_rrs.count = RedisModule_LoadUnsigned(rdb);
	diff->add_rrs.rdata = (knot_rdata_t *)RedisModule_LoadStringBuffer(rdb, &len);
	if (len > UINT32_MAX) {
		RedisModule_Free(diff->add_rrs.rdata);
		RedisModule_Free(diff);
		return NULL;
	}
	diff->add_rrs.size = len;

	diff->remove_rrs.count = RedisModule_LoadUnsigned(rdb);
	diff->remove_rrs.rdata = (knot_rdata_t *)RedisModule_LoadStringBuffer(rdb, &len);
	if (len > UINT32_MAX) {
		RedisModule_Free(diff->add_rrs.rdata);
		RedisModule_Free(diff->remove_rrs.rdata);
		RedisModule_Free(diff);
		return NULL;
	}
	diff->remove_rrs.size = len;

	diff->dest_ttl = RedisModule_LoadUnsigned(rdb);

	return diff;
}

static void diff_save(RedisModuleIO *rdb, void *value)
{
	diff_v *diff = (diff_v *)value;

	RedisModule_SaveUnsigned(rdb, diff->add_rrs.count);
	RedisModule_SaveStringBuffer(rdb, (const char *)diff->add_rrs.rdata, diff->add_rrs.size);

	RedisModule_SaveUnsigned(rdb, diff->remove_rrs.count);
	RedisModule_SaveStringBuffer(rdb, (const char *)diff->remove_rrs.rdata, diff->remove_rrs.size);

	RedisModule_SaveUnsigned(rdb, diff->dest_ttl);
}

static size_t diff_mem_usage(const void *value)
{
	const diff_v *diff = (const diff_v *)value;
	if (value == NULL) {
		return 0UL;
	}
	return sizeof(*diff) + diff->add_rrs.size + diff->remove_rrs.size;
}

static void diff_rewrite(RedisModuleIO *aof, RedisModuleString *key, void *value)
{
	size_t key_strlen = 0;
	const diff_v *diff = (const diff_v *)value;
	const uint8_t *key_str = (const uint8_t *)RedisModule_StringPtrLen(key, &key_strlen);
	RedisModule_EmitAOF(aof, "KNOT_BIN.AOF.DIFF", "blblbl",
	                    key_str, key_strlen,
	                    (long long)diff->add_rrs.count,
	                    diff->add_rrs.rdata, (long long)diff->add_rrs.size,
	                    (long long)diff->remove_rrs.count,
	                    diff->remove_rrs.rdata, (long long)diff->remove_rrs.size,
	                    (long long)diff->dest_ttl);
}

static void diff_free(void *value)
{
	diff_v *diff = (diff_v *)value;
	RedisModule_Free(diff->add_rrs.rdata);
	RedisModule_Free(diff->remove_rrs.rdata);
	RedisModule_Free(diff);
}

static int commit_event(RedisModuleCtx *ctx, rdb_event_t type, const arg_dname_t *origin,
                        uint8_t instance, uint32_t serial)
{
	RedisModule_Assert(ctx != NULL);

	RedisModuleString *keyname = RedisModule_CreateString(ctx, RDB_EVENT_KEY, strlen(RDB_EVENT_KEY));
	RedisModuleKey *stream_key = RedisModule_OpenKey(ctx, keyname, REDISMODULE_READ | REDISMODULE_WRITE);
	RedisModule_FreeString(ctx, keyname);

	int zone_stream_type = RedisModule_KeyType(stream_key);
	if (zone_stream_type != REDISMODULE_KEYTYPE_EMPTY && zone_stream_type != REDISMODULE_KEYTYPE_STREAM) {
		RedisModule_CloseKey(stream_key);
		RedisModule_ReplyWithError(ctx, "ERR bad stream data");
		return KNOT_ERROR;
	}

	RedisModuleString *events[] = {
		RedisModule_CreateString(ctx, RDB_EVENT_ARG_EVENT, strlen(RDB_EVENT_ARG_EVENT)),
		RedisModule_CreateStringFromLongLong(ctx, type),
		RedisModule_CreateString(ctx, RDB_EVENT_ARG_ORIGIN, strlen(RDB_EVENT_ARG_ORIGIN)),
		RedisModule_CreateString(ctx, (const char *)origin->data, origin->len),
		RedisModule_CreateString(ctx, RDB_EVENT_ARG_INSTANCE, strlen(RDB_EVENT_ARG_INSTANCE)),
		RedisModule_CreateStringFromLongLong(ctx, instance),
		RedisModule_CreateString(ctx, RDB_EVENT_ARG_SERIAL, strlen(RDB_EVENT_ARG_SERIAL)),
		RedisModule_CreateStringFromLongLong(ctx, serial),
		NULL,
	};

	RedisModuleStreamID ts;
	int ret = RedisModule_StreamAdd(stream_key, REDISMODULE_STREAM_ADD_AUTOID, &ts, events, 4);

	RedisModule_CloseKey(stream_key);
	for (RedisModuleString **event = events; *event != NULL; event++) {
		RedisModule_FreeString(ctx, *event);
	}

	if (ret != REDISMODULE_OK) {
		RedisModule_ReplyWithError(ctx, "ERR failed to emit event");
		return KNOT_ERROR;
	}

	if (rdb_event_age == 0) {
		return KNOT_EOK;
	}

	ts.ms -= 1000LLU * rdb_event_age;
	ts.seq = 0;

	// NOTE Trimming with REDISMODULE_STREAM_TRIM_APPROX improves preformance
	long long removed_cnt = RedisModule_StreamTrimByID(stream_key, REDISMODULE_STREAM_TRIM_APPROX, &ts);
	if (removed_cnt) {
		RedisModule_Log(ctx, REDISMODULE_LOGLEVEL_NOTICE, "stream cleanup %lld old events", removed_cnt);
	}

	return KNOT_EOK;
}

static RedisModuleKey *find_zone_index(RedisModuleCtx *ctx, const arg_dname_t *origin, const rdb_txn_t *txn, int rights)
{
	static const uint8_t prefix = ZONE;
	RedisModule_Assert(ctx != NULL && txn != NULL);

	char buf[RDB_PREFIX_LEN + 1 + KNOT_DNAME_MAXLEN + 2];

	wire_ctx_t w = wire_ctx_init((uint8_t *)buf, sizeof(buf));
	wire_ctx_write(&w, RDB_PREFIX, RDB_PREFIX_LEN);
	wire_ctx_write(&w, &prefix, sizeof(prefix));
	wire_ctx_write(&w, origin->data, origin->len);
	wire_ctx_write(&w, txn, sizeof(*txn));
	RedisModule_Assert(w.error == KNOT_EOK);

	RedisModuleString *keyname = RedisModule_CreateString(ctx, buf, wire_ctx_offset(&w));

	RedisModuleKey *key = RedisModule_OpenKey(ctx, keyname, rights);
	RedisModule_FreeString(ctx, keyname);

	return key;
}

static RedisModuleKey *find_upd_index(RedisModuleCtx *ctx, const arg_dname_t *origin,
                                      const rdb_txn_t *txn, uint16_t id, int rights)
{
	static const uint8_t prefix = UPD_TMP;

	RedisModule_Assert(ctx != NULL && txn != NULL);

	char buf[RDB_PREFIX_LEN + 1 + KNOT_DNAME_MAXLEN + 2];

	wire_ctx_t w = wire_ctx_init((uint8_t *)buf, sizeof(buf));
	wire_ctx_write(&w, RDB_PREFIX, RDB_PREFIX_LEN);
	wire_ctx_write(&w, &prefix, sizeof(prefix));
	wire_ctx_write(&w, origin->data, origin->len);
	wire_ctx_write(&w, txn, sizeof(*txn));
	wire_ctx_write(&w, &id, sizeof(id));
	RedisModule_Assert(w.error == KNOT_EOK);

	RedisModuleString *keyname = RedisModule_CreateString(ctx, buf, wire_ctx_offset(&w));

	RedisModuleKey *key = RedisModule_OpenKey(ctx, keyname, rights);
	RedisModule_FreeString(ctx, keyname);

	return key;
}

static RedisModuleString *commited_upd_keyname_construct(RedisModuleCtx *ctx, const arg_dname_t *origin,
                                                         const uint8_t instance, uint32_t serial)
{
	RedisModule_Assert(ctx != NULL);

	uint8_t prefix = UPD;
	char buf[RRSET_KEY_MAXLEN];

	wire_ctx_t w = wire_ctx_init((uint8_t *)buf, sizeof(buf));
	wire_ctx_write(&w, RDB_PREFIX, RDB_PREFIX_LEN);
	wire_ctx_write(&w, &prefix, sizeof(prefix));
	wire_ctx_write(&w, origin->data, origin->len);
	wire_ctx_write_u8(&w, instance);
	wire_ctx_write(&w, &serial, sizeof(serial));
	RedisModule_Assert(w.error == KNOT_EOK);

	return RedisModule_CreateString(ctx, buf, wire_ctx_offset(&w));
}

static RedisModuleKey *find_commited_upd_index(RedisModuleCtx *ctx, const arg_dname_t *origin,
                                               const rdb_txn_t *txn, const uint32_t serial, int rights)
{
	RedisModule_Assert(ctx != NULL);

	RedisModuleString *keyname = commited_upd_keyname_construct(ctx, origin, txn->instance, serial);

	RedisModuleKey *key = RedisModule_OpenKey(ctx, keyname, rights);
	RedisModule_FreeString(ctx, keyname);

	return key;
}


static double evaluate_score(uint16_t rtype)
{
	switch (rtype) {
	case KNOT_RRTYPE_SOA:
		return SCORE_SOA;
	default:
		return SCORE_DEFAULT;
	}
}

static RedisModuleString *rrset_keyname_construct(RedisModuleCtx *ctx, const rdb_txn_t *txn,
                                                  const arg_dname_t *origin, const arg_dname_t *owner, uint16_t rtype)
{
	uint8_t buf[RRSET_KEY_MAXLEN];
	uint8_t prefix = RRSET;

	wire_ctx_t w = wire_ctx_init((uint8_t *)buf, sizeof(buf));
	wire_ctx_write(&w, RDB_PREFIX, RDB_PREFIX_LEN);
	wire_ctx_write(&w, &prefix, sizeof(prefix));
	wire_ctx_write(&w, origin->data, origin->len);
	wire_ctx_write(&w, owner->data, owner->len);
	wire_ctx_write_u16(&w, rtype);
	wire_ctx_write(&w, txn, sizeof(*txn));
	RedisModule_Assert(w.error == KNOT_EOK);

	return RedisModule_CreateString(ctx, (const char *)buf, wire_ctx_offset(&w));
}

static void *redismodule_alloc(void *ptr, size_t bytes)
{
	return RedisModule_Alloc(bytes);
}

static void redismodule_free(void *ptr)
{
	RedisModule_Free(ptr);
}

static RedisModuleKey *rrset_key_get(RedisModuleCtx *ctx, const rdb_txn_t *txn,
                                     const arg_dname_t *origin, const arg_dname_t *owner, int16_t rtype)
{
	RedisModuleKey *zone_key = find_zone_index(ctx, origin, txn, REDISMODULE_READ | REDISMODULE_WRITE);
	int zone_keytype = RedisModule_KeyType(zone_key);
	if (zone_keytype != REDISMODULE_KEYTYPE_EMPTY &&
	    zone_keytype != REDISMODULE_KEYTYPE_ZSET) {
		RedisModule_CloseKey(zone_key);
		RedisModule_ReplyWithError(ctx, "ERR Bad data");
		return NULL;
	}

	RedisModuleString *rrset_keystr = rrset_keyname_construct(ctx, txn, origin, owner, rtype);

	RedisModule_ZsetAdd(zone_key, evaluate_score(rtype), rrset_keystr, NULL);
	RedisModule_CloseKey(zone_key);

	RedisModuleKey *rrset_key = RedisModule_OpenKey(ctx, rrset_keystr, REDISMODULE_READ | REDISMODULE_WRITE);
	RedisModule_FreeString(ctx, rrset_keystr);
	return rrset_key;
}

static int rdata_add(RedisModuleCtx *ctx, const rdb_txn_t *txn,
                     const arg_dname_t *origin, const arg_dname_t *owner, int16_t rtype,
                     uint32_t ttl, const knot_rdata_t *rdata)
{
	RedisModuleKey *rrset_key = rrset_key_get(ctx, txn, origin, owner, rtype);
	if (rrset_key == NULL) {
		return -1;
	}

	rrset_v *rrset = NULL;
	if (RedisModule_KeyType(rrset_key) == REDISMODULE_KEYTYPE_EMPTY) {
		rrset = RedisModule_Calloc(1, sizeof(*rrset));
		if (rrset == NULL) {
			RedisModule_ReplyWithError(ctx, "ERR Cannot allocate memory");
			return -1;
		}
		int ret = RedisModule_ModuleTypeSetValue(rrset_key, knot_zone_rrset_t, rrset);
		if (ret != REDISMODULE_OK) {
			RedisModule_ReplyWithError(ctx, "ERR Unable to store module value");
			return -1;
		}
		rrset->ttl = (ttl == TTL_EMPTY) ? rdb_default_ttl : ttl;
	} else if (RedisModule_ModuleTypeGetType(rrset_key) == knot_zone_rrset_t) {
		rrset = RedisModule_ModuleTypeGetValue(rrset_key);
		if (ttl != TTL_EMPTY) {
			rrset->ttl = ttl;
		}
	} else {
		RedisModule_CloseKey(rrset_key);
		RedisModule_ReplyWithError(ctx, "ERR Bad data");
		return -1;
	}

	int ret = knot_rdataset_add(&rrset->rrs, rdata, &mm);
	if (ret != KNOT_EOK) {
		RedisModule_CloseKey(rrset_key);
		RedisModule_ReplyWithError(ctx, "ERR Unable to add");
		return -1;
	}

	RedisModule_CloseKey(rrset_key);

	return 0;
}

static int rdata_remove(RedisModuleCtx *ctx, const rdb_txn_t *txn,
                        const arg_dname_t *origin, const arg_dname_t *owner, int16_t rtype,
                        uint32_t ttl, const knot_rdata_t *rdata)
{
	RedisModuleKey *zone_key = find_zone_index(ctx, origin, txn, REDISMODULE_READ | REDISMODULE_WRITE);
	int zone_keytype = RedisModule_KeyType(zone_key);
	if (zone_keytype != REDISMODULE_KEYTYPE_EMPTY &&
	    zone_keytype != REDISMODULE_KEYTYPE_ZSET) {
		RedisModule_CloseKey(zone_key);
		RedisModule_ReplyWithError(ctx, "ERR Bad data");
		return -1;
	}

	RedisModuleString *rrset_keystr = rrset_keyname_construct(ctx, txn, origin, owner, rtype);

	RedisModuleKey *rrset_key = RedisModule_OpenKey(ctx, rrset_keystr, REDISMODULE_READ | REDISMODULE_WRITE);
	RedisModule_FreeString(ctx, rrset_keystr);

	rrset_v *rrset = NULL;
	if (RedisModule_KeyType(rrset_key) == REDISMODULE_KEYTYPE_EMPTY) {
		RedisModule_CloseKey(zone_key);
		return 0;
	} else if (RedisModule_ModuleTypeGetType(rrset_key) == knot_zone_rrset_t) {
		rrset = RedisModule_ModuleTypeGetValue(rrset_key);
	} else {
		RedisModule_CloseKey(zone_key);
		RedisModule_CloseKey(rrset_key);
		RedisModule_ReplyWithError(ctx, "ERR Bad data");
		return -1;
	}
	rrset->ttl = ttl;

	int ret = knot_rdataset_remove(&rrset->rrs, rdata, &mm);
	if (ret != KNOT_EOK) {
		RedisModule_CloseKey(zone_key);
		RedisModule_CloseKey(rrset_key);
		RedisModule_ReplyWithError(ctx, "ERR Unable to remove");
		return -1;
	}

	// if (rrset->rrs.count == 0) {
	// 	RedisModule_DeleteKey(rrset_key);
	// 	RedisModule_ZsetRem(zone_key, rrset_keystr, NULL);
	// }
	RedisModule_CloseKey(zone_key);

	RedisModule_CloseKey(rrset_key);

	return 0;
}

static void zone_meta_storage_init(zone_meta_storage_t *meta)
{
	meta->active = ZONE_META_INACTIVE;
	for (uint8_t *it = meta->lock; it != meta->lock + TXN_MAX_COUNT; ++it) {
		*it = 0;
	}
}

static RedisModuleKey *zone_meta_key_get(RedisModuleCtx *ctx, rdb_txn_t *txn, const arg_dname_t *origin, int rights)
{
	RedisModule_Assert(txn->instance != 0);

	RedisModuleString *keyname = zone_meta_keyname_construct(ctx, origin, txn->instance);
	if (keyname == NULL) {
		RedisModule_ReplyWithError(ctx, "ERR failed to initialize transaction");
		return NULL;
	}

	RedisModuleKey *key = RedisModule_OpenKey(ctx, keyname, rights);
	RedisModule_FreeString(ctx, keyname);

	int keytype = RedisModule_KeyType(key);
	if (keytype == REDISMODULE_KEYTYPE_EMPTY) {
		zone_meta_storage_t meta;
		zone_meta_storage_init(&meta);
		RedisModuleString *meta_str = RedisModule_CreateString(ctx, (const char *)&meta, sizeof(meta));
		RedisModule_StringSet(key, meta_str);
		RedisModule_FreeString(ctx, meta_str);
	} else if (keytype != REDISMODULE_KEYTYPE_STRING) {
		RedisModule_CloseKey(key);
		RedisModule_ReplyWithError(ctx, "ERR Bad data");
		return NULL;
	}

	return key;
}

static RedisModuleKey *upd_meta_key_get(RedisModuleCtx *ctx, rdb_txn_t *txn, const arg_dname_t *origin, int rights)
{
	RedisModule_Assert(txn->instance != 0);

	RedisModuleString *keyname = upd_meta_keyname_construct(ctx, origin, txn->instance);
	if (keyname == NULL) {
		RedisModule_ReplyWithError(ctx, "ERR failed to initialize transaction");
		return NULL;
	}

	RedisModuleKey *key = RedisModule_OpenKey(ctx, keyname, rights);
	RedisModule_FreeString(ctx, keyname);

	int keytype = RedisModule_KeyType(key);
	if (keytype == REDISMODULE_KEYTYPE_EMPTY) {
		upd_meta_storage_t meta = { 0 };
		RedisModuleString *meta_str = RedisModule_CreateString(ctx, (const char *)&meta, sizeof(meta));
		RedisModule_StringSet(key, meta_str);
		RedisModule_FreeString(ctx, meta_str);
	} else if (keytype != REDISMODULE_KEYTYPE_STRING) {
		RedisModule_CloseKey(key);
		RedisModule_ReplyWithError(ctx, "ERR Bad data");
		return NULL;
	}

	return key;
}

static int zone_txn_lock(RedisModuleCtx *ctx, RedisModuleKey *key, rdb_txn_t *txn)
{
	RedisModule_Assert(ctx != NULL && key != NULL && txn != NULL && txn->instance != 0);

	size_t len = 0;
	zone_meta_storage_t *meta = (zone_meta_storage_t *)RedisModule_StringDMA(key, &len, REDISMODULE_WRITE);
	if (meta == NULL || len != sizeof(zone_meta_storage_t)) {
		RedisModule_CloseKey(key);
		RedisModule_ReplyWithError(ctx, "ERR Bad data");
		return KNOT_EINVAL;
	}

	for (txn->id = TXN_MIN; txn->id <= TXN_MAX; ++txn->id) {
		if (meta->lock[txn->id] == 0) {
			meta->lock[txn->id] = 1;
			break;
		}
	}
	RedisModule_CloseKey(key);
	if (txn->id > TXN_MAX) {
		RedisModule_ReplyWithError(ctx, "ERR too many transactions");
		return KNOT_EBUSY;
	}

	return KNOT_EOK;
}

static int upd_txn_lock(RedisModuleCtx *ctx, RedisModuleKey *key, rdb_txn_t *txn)
{
	RedisModule_Assert(ctx != NULL && key != NULL && txn != NULL && txn->instance != 0);

	size_t len;
	upd_meta_storage_t *meta = (upd_meta_storage_t *)RedisModule_StringDMA(key, &len, REDISMODULE_WRITE);
	if (meta == NULL || len != sizeof(upd_meta_storage_t)) {
		RedisModule_CloseKey(key);
		RedisModule_ReplyWithError(ctx, "ERR Bad data");
		return KNOT_EINVAL;
	}

	for (txn->id = TXN_MIN; txn->id <= TXN_MAX; ++txn->id) {
		if (meta->lock[txn->id] == 0) {
			meta->counter = MAX(meta->counter + 1, 1);
			meta->lock[txn->id] = meta->counter;
			break;
		}
	}
	RedisModule_CloseKey(key);
	if (txn->id > TXN_MAX) {
		RedisModule_ReplyWithError(ctx, "ERR too many transactions");
		return KNOT_EBUSY;
	}

	return KNOT_EOK;
}

static int serialize_transaction(const rdb_txn_t *txn)
{
	return 10 * txn->instance + txn->id;
}

static int set_active_transaction(RedisModuleCtx *ctx, const arg_dname_t *origin, rdb_txn_t *txn)
{
	RedisModule_Assert(txn->instance > 0);

	RedisModuleString *txn_k = zone_meta_keyname_construct(ctx, origin, txn->instance);
	RedisModuleKey *key = RedisModule_OpenKey(ctx, txn_k, REDISMODULE_READ);
	RedisModule_FreeString(ctx, txn_k);
	if (key == NULL || RedisModule_KeyType(key) != REDISMODULE_KEYTYPE_STRING) {
		return KNOT_EMALF;
	}
	size_t len = 0;
	const zone_meta_storage_t *meta = (const zone_meta_storage_t *)RedisModule_StringDMA(key, &len, REDISMODULE_READ);
	if (meta->active != ZONE_META_INACTIVE) {
		txn->id = meta->active;
		return KNOT_EOK;
	}
	return KNOT_EEXIST;
}

static int get_id(RedisModuleCtx *ctx, const arg_dname_t *origin, const rdb_txn_t *txn)
{
	RedisModuleString *txn_k = upd_meta_keyname_construct(ctx, origin, txn->instance);
	if (txn_k == NULL) {
		return KNOT_EINVAL;
	}

	RedisModuleKey *meta_key = RedisModule_OpenKey(ctx, txn_k, REDISMODULE_READ);
	RedisModule_FreeString(ctx, txn_k);


	int keytype = RedisModule_KeyType(meta_key);
	if (keytype != REDISMODULE_KEYTYPE_STRING) {
		RedisModule_CloseKey(meta_key);
		return KNOT_EINVAL;
	}

	size_t meta_len = 0;
	upd_meta_storage_t *meta = (upd_meta_storage_t *)RedisModule_StringDMA(meta_key, &meta_len, REDISMODULE_READ);
	if (meta_len != sizeof(upd_meta_storage_t)) {
		RedisModule_CloseKey(meta_key);
		return KNOT_EINVAL;
	}

	uint16_t id = meta->lock[txn->id];
	if (id == 0) {
		RedisModule_CloseKey(meta_key);
		return KNOT_EEXIST;
	}

	RedisModule_CloseKey(meta_key);
	return id;
}

static void delete_index(const uint8_t prefix, RedisModuleCtx *ctx, const rdb_txn_t *txn, const arg_dname_t *origin)
{
	RedisModule_Assert(ctx != NULL && txn != NULL);

	RedisModuleKey *index_key = NULL;
	switch (prefix) {
	case ZONE:
		index_key = find_zone_index(ctx, origin, txn, REDISMODULE_READ | REDISMODULE_WRITE);
		break;
	case UPD_TMP:;
		int ret = get_id(ctx, origin, txn);
		if (ret < 0 || ret > UINT16_MAX) {
			RedisModule_ReplyWithError(ctx, "Unknown transaction ID");
			return;
		}
		uint16_t id = ret;
		index_key = find_upd_index(ctx, origin, txn, id, REDISMODULE_READ | REDISMODULE_WRITE);
		break;
	default:
		return;
	}
	if (index_key == NULL || RedisModule_KeyType(index_key) != REDISMODULE_KEYTYPE_ZSET) {
		RedisModule_CloseKey(index_key);
		return;
	}

	foreach_in_zset(index_key) {
		double score = 0.0;
		RedisModuleString *el = RedisModule_ZsetRangeCurrentElement(index_key, &score);
		if (el == NULL) {
			break;
		}

		RedisModuleKey *rrset_key = RedisModule_OpenKey(ctx, el, REDISMODULE_READ | REDISMODULE_WRITE);
		if (rrset_key != NULL) {
			RedisModule_DeleteKey(rrset_key);
			RedisModule_CloseKey(rrset_key);
		}
	}

	RedisModule_DeleteKey(index_key);
	RedisModule_CloseKey(index_key);
}

static int rrset_aof_rewrite(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 5) {
		return RedisModule_WrongArity(ctx);
	}

	rrset_v *rrset = RedisModule_Calloc(1, sizeof(rrset_v));
	if (rrset == NULL) {
		return RedisModule_ReplyWithError(ctx, "ERR Cannot allocate memory");
	}

	RedisModuleKey *rrset_key = RedisModule_OpenKey(ctx, argv[1], REDISMODULE_READ | REDISMODULE_WRITE);
	long long ttl_val = 0;
	int ret = RedisModule_StringToLongLong(argv[2], &ttl_val);
	if (ret != REDISMODULE_OK) {
		RedisModule_CloseKey(rrset_key);
		return RedisModule_ReplyWithError(ctx, "ERR Not a number");
	} else if (ttl_val < 0 || ttl_val > UINT32_MAX) {
		RedisModule_CloseKey(rrset_key);
		return RedisModule_ReplyWithError(ctx, "ERR Value out of range");
	}
	rrset->ttl = ttl_val;

	long long count_val = 0;
	ret = RedisModule_StringToLongLong(argv[3], &count_val);
	if (ret != REDISMODULE_OK) {
		RedisModule_CloseKey(rrset_key);
		return RedisModule_ReplyWithError(ctx, "ERR Not a number");
	} else if (count_val < 0 || count_val > UINT16_MAX) {
		RedisModule_CloseKey(rrset_key);
		return RedisModule_ReplyWithError(ctx, "ERR Value out of range");
	}
	rrset->rrs.count = count_val;

	size_t rdataset_strlen;
	const char *rdataset_str = RedisModule_StringPtrLen(argv[4], &rdataset_strlen);
	if (rdataset_strlen != 0) {
		rrset->rrs.rdata = RedisModule_Alloc(rdataset_strlen);
		rrset->rrs.size = rdataset_strlen;
		memcpy(rrset->rrs.rdata, rdataset_str, rdataset_strlen);
	} else {
		rrset->rrs.rdata = NULL;
		rrset->rrs.size = 0;
	}

	RedisModule_ModuleTypeSetValue(rrset_key, knot_zone_rrset_t, rrset);
	RedisModule_CloseKey(rrset_key);

	return RedisModule_ReplyWithNull(ctx);
}

static int diff_aof_rewrite(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 7) {
		return RedisModule_WrongArity(ctx);
	}

	diff_v *diff = RedisModule_Calloc(1, sizeof(diff_v));
	if (diff == NULL) {
		return RedisModule_ReplyWithError(ctx, "ERR Cannot allocate memory");
	}

	RedisModuleKey *diff_key = RedisModule_OpenKey(ctx, argv[1], REDISMODULE_READ | REDISMODULE_WRITE);

	long long add_rrs_count_val = 0;
	int ret = RedisModule_StringToLongLong(argv[2], &add_rrs_count_val);
	if (ret != REDISMODULE_OK) {
		RedisModule_CloseKey(diff_key);
		return RedisModule_ReplyWithError(ctx, "ERR Not a number");
	} else if (add_rrs_count_val < 0 || add_rrs_count_val > UINT16_MAX) {
		RedisModule_CloseKey(diff_key);
		return RedisModule_ReplyWithError(ctx, "ERR Value out of range");
	}
	diff->add_rrs.count = add_rrs_count_val;

	size_t add_rrs_len = 0;
	diff->add_rrs.rdata = (knot_rdata_t *)RedisModule_StringPtrLen(argv[3], &add_rrs_len);
	if (add_rrs_len > UINT32_MAX) {
		RedisModule_CloseKey(diff_key);
		return RedisModule_ReplyWithError(ctx, "ERR Add rrset is too long");
	}
	diff->add_rrs.size = add_rrs_len;

	long long remove_rrs_count_val = 0;
	ret = RedisModule_StringToLongLong(argv[4], &remove_rrs_count_val);
	if (ret != REDISMODULE_OK) {
		RedisModule_CloseKey(diff_key);
		return RedisModule_ReplyWithError(ctx, "ERR Not a number");
	} else if (remove_rrs_count_val < 0 || remove_rrs_count_val > UINT16_MAX) {
		RedisModule_CloseKey(diff_key);
		return RedisModule_ReplyWithError(ctx, "ERR Value out of range");
	}
	diff->remove_rrs.count = remove_rrs_count_val;

	size_t remove_rrs_len = 0;
	diff->remove_rrs.rdata = (knot_rdata_t *)RedisModule_StringPtrLen(argv[5], &remove_rrs_len);
	if (remove_rrs_len > UINT32_MAX) {
		RedisModule_CloseKey(diff_key);
		return RedisModule_ReplyWithError(ctx, "ERR Remove rrset is too long");
	}
	diff->remove_rrs.size = remove_rrs_len;

	long long ttl_val = 0;
	ret = RedisModule_StringToLongLong(argv[6], &ttl_val);
	if (ret != REDISMODULE_OK) {
		RedisModule_CloseKey(diff_key);
		return RedisModule_ReplyWithError(ctx, "ERR Not a number");
	} else if (ttl_val < 0 || ttl_val > UINT32_MAX) {
		RedisModule_CloseKey(diff_key);
		return RedisModule_ReplyWithError(ctx, "ERR Value out of range");
	}
	diff->dest_ttl = ttl_val;

	RedisModule_ModuleTypeSetValue(diff_key, knot_diff_t, diff);
	RedisModule_CloseKey(diff_key);

	return RedisModule_ReplyWithNull(ctx);
}

static int upd_begin(RedisModuleCtx *ctx, rdb_txn_t *txn, const arg_dname_t *origin)
{
	RedisModuleKey *key = upd_meta_key_get(ctx, txn, origin, REDISMODULE_WRITE);
	int ret = upd_txn_lock(ctx, key, txn);
	delete_upd_index(ctx, txn, origin);
	if (ret != KNOT_EOK) {
		return ret;
	}

	return KNOT_EOK;
}

static int zone_begin(RedisModuleCtx *ctx, rdb_txn_t *txn, const arg_dname_t *origin)
{
	RedisModuleKey *key = zone_meta_key_get(ctx, txn, origin, REDISMODULE_WRITE);
	int ret = zone_txn_lock(ctx, key, txn);
	delete_zone_index(ctx, txn, origin);
	if (ret != KNOT_EOK) {
		return ret;
	}

	return KNOT_EOK;
}

static int zone_begin_txt(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	rdb_txn_t txn = { .instance = 1 };
	arg_dname_t origin;

	switch (argc) {
	case 3:
		ARG_INST_TXT(argv[2], txn);
	case 2: // FALLTHROUGH
		ARG_DNAME_TXT(argv[1], origin, NULL, "origin");
		break;
	default:
		return RedisModule_WrongArity(ctx);
	}

	if (zone_begin(ctx, &txn, &origin) != KNOT_EOK) {
		return REDISMODULE_OK;
	}

	return RedisModule_ReplyWithLongLong(ctx, serialize_transaction(&txn));
}

static int zone_begin_bin(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	rdb_txn_t txn = { .instance = 1 };
	arg_dname_t origin;

	switch (argc) {
	case 3:
		ARG_INST(argv[2], txn);
	case 2: // FALLTHROUGH
		ARG_DNAME(argv[1], origin, "origin");
		break;
	default:
		return RedisModule_WrongArity(ctx);
	}

	if (zone_begin(ctx, &txn, &origin) != KNOT_EOK) {
		return REDISMODULE_OK;
	}

	return RedisModule_ReplyWithStringBuffer(ctx, (const char *)&txn, sizeof(txn));
}

static void scanner_data(zs_scanner_t *s)
{
	scanner_ctx_t *s_ctx = s->process.data;

	uint8_t buf[knot_rdata_size(s->r_data_length)];
	knot_rdata_t *rdata = (knot_rdata_t *)buf;
	knot_rdata_init(rdata, s->r_data_length, s->r_data);

	if (knot_rdata_to_canonical(rdata, s->r_type) != KNOT_EOK) {
		RedisModule_ReplyWithError(s_ctx->ctx, "ERR malformed record data");
		s_ctx->replied = true;
		s->state = ZS_STATE_STOP;
		return;
	}

	arg_dname_t origin = { .data = s->zone_origin, .len = s->zone_origin_length };
	arg_dname_t owner = { .data = s->r_owner, .len = s->r_owner_length };
	int ret = rdata_add(s_ctx->ctx, s_ctx->txn, &origin, &owner,
	                    s->r_type, s->r_ttl, rdata);
	if (ret != 0) {
		s_ctx->replied = true;
		s->state = ZS_STATE_STOP;
		return;
	}
}

static void scanner_error(zs_scanner_t *s)
{
	scanner_ctx_t *s_ctx = s->process.data;

	char msg[128];
	(void)snprintf(msg, sizeof(msg), "ERR parser failed (%s), line %"PRIu64,
	               zs_strerror(s->error.code), s->line_counter);
	RedisModule_ReplyWithError(s_ctx->ctx, msg);

	s_ctx->replied = true;
	s->state = ZS_STATE_STOP;
}

static int zone_store_txt(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 4) {
		return RedisModule_WrongArity(ctx);
	}

	arg_dname_t origin;
	ARG_DNAME_TXT(argv[1], origin, NULL, "origin");

	rdb_txn_t txn;
	ARG_TXN_TXT(argv[2], txn);

	void *zone_data;
	size_t data_len;
	ARG_DATA(argv[3], data_len, zone_data, "zone data");

	if (zone_txn_is_open(ctx, &origin, &txn) == false) {
		return RedisModule_ReplyWithError(ctx, "ERR non-existent transaction");
	}

	zs_scanner_t s;
	scanner_ctx_t s_ctx = { ctx, &txn };
	if (zs_init(&s, origin.txt, KNOT_CLASS_IN, rdb_default_ttl) != 0 ||
	    zs_set_input_string(&s, zone_data, data_len) != 0 ||
	    zs_set_processing(&s, scanner_data, scanner_error, &s_ctx) != 0 ||
	    zs_parse_all(&s) != 0) {
		zs_deinit(&s);
		if (!s_ctx.replied) {
			return RedisModule_ReplyWithError(ctx, "ERR parser failed");
		}
		return REDISMODULE_OK;
	}
	zs_deinit(&s);

	return RedisModule_ReplyWithSimpleString(ctx, RDB_RETURN_OK);
}

static int zone_store_bin(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 8) {
		return RedisModule_WrongArity(ctx);
	}

	arg_dname_t origin;
	ARG_DNAME(argv[1], origin, "origin");

	rdb_txn_t txn;
	ARG_TXN(argv[2], txn);

	arg_dname_t owner;
	ARG_DNAME(argv[3], owner, "owner");

	uint16_t rtype;
	ARG_NUM(argv[4], rtype, "record type");

	uint32_t ttl;
	ARG_NUM(argv[5], ttl, "TTL");

	uint16_t rcount;
	ARG_NUM(argv[6], rcount, "record count");

	uint8_t *rdataset;
	size_t rdataset_len;
	ARG_DATA(argv[7], rdataset_len, rdataset, "rdataset");

	RedisModuleKey *rrset_key = rrset_key_get(ctx, &txn, &origin, &owner, rtype);
	if (rrset_key == NULL) {
		return REDISMODULE_OK;
	}
	if (RedisModule_KeyType(rrset_key) != REDISMODULE_KEYTYPE_EMPTY) {
		RedisModule_CloseKey(rrset_key);
		return RedisModule_ReplyWithError(ctx, "ERR non-empty RRset");
	}

	rrset_v *rrset = RedisModule_Calloc(1, sizeof(*rrset));
	if (rrset == NULL) {
		RedisModule_CloseKey(rrset_key);
		return RedisModule_ReplyWithError(ctx, "ERR failed to allocate memory");
	}
	rrset->ttl = ttl;
	rrset->rrs.count = rcount;

	if (rdataset_len != 0) {
		rrset->rrs.rdata = RedisModule_Alloc(rdataset_len);
		if (rrset->rrs.rdata == NULL) {
			RedisModule_CloseKey(rrset_key);
			return RedisModule_ReplyWithError(ctx, "ERR failed to allocate memory");
		}
		rrset->rrs.size = rdataset_len;
		memcpy(rrset->rrs.rdata, rdataset, rdataset_len);
	} else {
		rrset->rrs.rdata = NULL;
		rrset->rrs.size = 0;
	}

	int ret = RedisModule_ModuleTypeSetValue(rrset_key, knot_zone_rrset_t, rrset);
	RedisModule_CloseKey(rrset_key);
	if (ret != REDISMODULE_OK) {
		return RedisModule_ReplyWithError(ctx, "ERR unable to store RRset");
	}

	return RedisModule_ReplyWithSimpleString(ctx, RDB_RETURN_OK);
}

static int zone_purge(RedisModuleCtx *ctx, const arg_dname_t *origin, rdb_txn_t *txn)
{
	if (set_active_transaction(ctx, origin, txn) != KNOT_EOK) {
		RedisModule_ReplyWithError(ctx, "ERR not active zone");
		return KNOT_EEXIST;
	}
	RedisModuleString *soa_rrset_keyname = rrset_keyname_construct(ctx, txn, origin, origin, KNOT_RRTYPE_SOA);
	RedisModuleKey *soa_rrset_key = RedisModule_OpenKey(ctx, soa_rrset_keyname, REDISMODULE_READ);
	RedisModule_FreeString(ctx, soa_rrset_keyname);
	rrset_v *rrset = RedisModule_ModuleTypeGetValue(soa_rrset_key);
	if (rrset == NULL) {
		RedisModule_CloseKey(soa_rrset_key);
		RedisModule_Log(ctx, REDISMODULE_LOGLEVEL_WARNING, "ERR missing SOA rrset");
		RedisModule_ReplyWithError(ctx, "ERR missing SOA rrset");
		return KNOT_EACCES;
	}
	uint32_t serial = knot_soa_serial(rrset->rrs.rdata);
	RedisModule_CloseKey(soa_rrset_key);

	delete_zone_index(ctx, txn, origin);

	RedisModuleKey *upd_index_key = find_commited_upd_index(ctx, origin, txn, serial, REDISMODULE_READ | REDISMODULE_WRITE);
	while (RedisModule_KeyType(upd_index_key) == REDISMODULE_KEYTYPE_ZSET) {
		size_t soa_count = 0;
		RedisModuleString *soa_diff_keyname = NULL;

		foreach_in_zset_subset(upd_index_key, SCORE_SOA, SCORE_SOA) {
			double score = 0.0;
			soa_diff_keyname = RedisModule_ZsetRangeCurrentElement(upd_index_key, &score);
			if (soa_diff_keyname == NULL) {
				break;
			}
			++soa_count;
		}
		if (soa_count != 1) {
			RedisModule_ReplyWithError(ctx, "ERR malformed SOA");
			return KNOT_EINVAL;
		}

		RedisModuleKey *soa_diff_key = RedisModule_OpenKey(ctx, soa_diff_keyname, REDISMODULE_READ);
		diff_v *diff = RedisModule_ModuleTypeGetValue(soa_diff_key);
		serial = knot_soa_serial(diff->remove_rrs.rdata);
		RedisModule_CloseKey(soa_diff_key);

		foreach_in_zset(upd_index_key) {
			double score = 0.0;
			RedisModuleString *el = RedisModule_ZsetRangeCurrentElement(upd_index_key, &score);
			if (el == NULL) {
				break;
			}

			RedisModuleKey *rrset_key = RedisModule_OpenKey(ctx, el, REDISMODULE_READ | REDISMODULE_WRITE);
			if (rrset_key != NULL) {
				RedisModule_DeleteKey(rrset_key);
				RedisModule_CloseKey(rrset_key);
			}
		}

		RedisModule_DeleteKey(upd_index_key);
		RedisModule_CloseKey(upd_index_key);

		upd_index_key = find_commited_upd_index(ctx, origin, txn, serial, REDISMODULE_READ | REDISMODULE_WRITE);
	}

	commit_event(ctx, RDB_EVENT_PURGE, origin, txn->instance, serial);

	return RedisModule_ReplyWithSimpleString(ctx, RDB_RETURN_OK);
}

static int zone_meta_active_exchange(RedisModuleCtx *ctx, RedisModuleKey *key, rdb_txn_t *txn, const arg_dname_t *origin)
{
	size_t len = 0;
	zone_meta_storage_t *meta = (zone_meta_storage_t *)RedisModule_StringDMA(key, &len, REDISMODULE_WRITE);
	if (len != sizeof(*meta)) {
		return KNOT_EINVAL;
	}
	uint8_t active_old = meta->active;
	if (active_old != ZONE_META_INACTIVE) {
		rdb_txn_t txn_old = {
			.instance = txn->instance,
			.id = active_old
		};
		zone_purge(ctx, origin, &txn_old);
		meta->lock[active_old] = 0;
	}
	meta->active = txn->id;
	return KNOT_EOK;
}

static int zone_commit(RedisModuleCtx *ctx, const arg_dname_t *origin, rdb_txn_t *txn)
{
	RedisModuleKey *meta_key = NULL;
	if (zone_txn_get_when_open(ctx, origin, txn, &meta_key, REDISMODULE_READ | REDISMODULE_WRITE) == false) {
		RedisModule_CloseKey(meta_key);
		RedisModule_ReplyWithError(ctx, "ERR Non-existent transaction");
		return KNOT_ENOENT;
	}

	RedisModuleKey *zone_key = find_zone_index(ctx, origin, txn, REDISMODULE_READ | REDISMODULE_WRITE);

	size_t soa_cnt = 0;
	RedisModuleString *soa_keyname = NULL;
	foreach_in_zset_subset(zone_key, SCORE_SOA, SCORE_SOA) {
		double score = 0.0;
		soa_keyname = RedisModule_ZsetRangeCurrentElement(zone_key, &score);
		if (soa_keyname == NULL) {
			break;
		}
		++soa_cnt;
	}
	RedisModule_CloseKey(zone_key);
	if (soa_cnt != 1) {
		RedisModule_CloseKey(meta_key);
		RedisModule_ReplyWithError(ctx, "ERR Missing SOA");
		return KNOT_ENOENT;
	}

	RedisModuleKey *soa_key = RedisModule_OpenKey(ctx, soa_keyname, REDISMODULE_READ);
	if (soa_key == NULL) {
		RedisModule_CloseKey(meta_key);
		RedisModule_ReplyWithError(ctx, "ERR Missing SOA");
		return KNOT_ENOENT;
	}
	rrset_v *rrset = RedisModule_ModuleTypeGetValue(soa_key);
	uint32_t serial = knot_soa_serial(rrset->rrs.rdata);
	RedisModule_CloseKey(soa_key);

	int ret = zone_meta_active_exchange(ctx, meta_key, txn, origin);
	RedisModule_CloseKey(meta_key);
	if (ret != KNOT_EOK) {
		RedisModule_ReplyWithError(ctx, "ERR Bad data");
		return ret;
	}

	return commit_event(ctx, RDB_EVENT_ZONE, origin, txn->instance, serial);
}

static int zone_commit_txt(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 3) {
		return RedisModule_WrongArity(ctx);
	}

	arg_dname_t origin;
	ARG_DNAME_TXT(argv[1], origin, NULL, "origin");

	rdb_txn_t txn;
	ARG_TXN_TXT(argv[2], txn);

	if (zone_commit(ctx, &origin, &txn) != KNOT_EOK) {
		return REDISMODULE_OK;
	}

	return RedisModule_ReplyWithSimpleString(ctx, RDB_RETURN_OK);
}

static int zone_commit_bin(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 3) {
		return RedisModule_WrongArity(ctx);
	}

	arg_dname_t origin;
	ARG_DNAME(argv[1], origin, "origin");

	rdb_txn_t txn;
	ARG_TXN(argv[2], txn);

	if (zone_commit(ctx, &origin, &txn) != KNOT_EOK) {
		return REDISMODULE_OK;
	}

	return RedisModule_ReplyWithSimpleString(ctx, RDB_RETURN_OK);
}

static int zone_abort(RedisModuleCtx *ctx, const arg_dname_t *origin, rdb_txn_t *txn)
{
	RedisModuleKey *meta_key = NULL;
	if (zone_txn_get_when_open(ctx, origin, txn, &meta_key, REDISMODULE_READ | REDISMODULE_WRITE) == false) {
		RedisModule_CloseKey(meta_key);
		RedisModule_ReplyWithError(ctx, "Non-existent transaction");
		return KNOT_ENOENT;
	}

	size_t len = 0;
	zone_meta_storage_t *meta = (zone_meta_storage_t *)RedisModule_StringDMA(meta_key, &len, REDISMODULE_WRITE);
	meta->lock[txn->id] = 0;

	RedisModule_CloseKey(meta_key);

	delete_zone_index(ctx, txn, origin);

	return KNOT_EOK;
}

static int zone_abort_txt(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 3) {
		return RedisModule_WrongArity(ctx);
	}

	arg_dname_t origin;
	ARG_DNAME_TXT(argv[1], origin, NULL, "origin");

	rdb_txn_t txn;
	ARG_TXN_TXT(argv[2], txn);

	if (zone_abort(ctx, &origin, &txn) != KNOT_EOK) {
		return REDISMODULE_OK;
	}

	return RedisModule_ReplyWithSimpleString(ctx, RDB_RETURN_OK);
}

static int zone_abort_bin(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 3) {
		return RedisModule_WrongArity(ctx);
	}

	arg_dname_t origin;
	ARG_DNAME(argv[1], origin, "origin");

	rdb_txn_t txn;
	ARG_TXN(argv[2], txn);

	if (zone_abort(ctx, &origin, &txn) != KNOT_EOK) {
		return REDISMODULE_OK;
	}

	return RedisModule_ReplyWithSimpleString(ctx, RDB_RETURN_OK);
}

static int zone_exists_bin(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 3) {
		return RedisModule_WrongArity(ctx);
	}

	arg_dname_t origin;
	ARG_DNAME(argv[1], origin, "origin");

	rdb_txn_t txn;
	ARG_INST(argv[2], txn);

	int ret = set_active_transaction(ctx, &origin, &txn);
	if (ret != KNOT_EOK) {
		return RedisModule_ReplyWithError(ctx, "ERR unknown instance");
	}

	RedisModuleKey *zone_key = find_zone_index(ctx, &origin, &txn, REDISMODULE_READ);
	if (zone_key == NULL) {
		return RedisModule_ReplyWithLongLong(ctx, -1);
	}
	int zone_keytype = RedisModule_KeyType(zone_key);
	if (zone_keytype == REDISMODULE_KEYTYPE_EMPTY) {
		RedisModule_CloseKey(zone_key);
		return RedisModule_ReplyWithError(ctx, "ERR Does not exist");
	} else if (zone_keytype != REDISMODULE_KEYTYPE_ZSET) {
		RedisModule_CloseKey(zone_key);
		return RedisModule_ReplyWithError(ctx, "ERR Bad data");
	}

	foreach_in_zset_subset(zone_key, SCORE_SOA, SCORE_SOA) {
		double score = 0.0;
		RedisModuleString *el = RedisModule_ZsetRangeCurrentElement(zone_key, &score);
		if (el == NULL) {
			break;
		}

		RedisModuleKey *rrset_key = RedisModule_OpenKey(ctx, el, REDISMODULE_READ);
		if (rrset_key == NULL) {
			continue;
		}

		rrset_v *rrset = RedisModule_ModuleTypeGetValue(rrset_key);
		uint32_t serial = knot_soa_serial(rrset->rrs.rdata);

		RedisModule_CloseKey(rrset_key);
		RedisModule_ZsetRangeStop(zone_key);
		RedisModule_CloseKey(zone_key);

		return RedisModule_ReplyWithLongLong(ctx, serial);
	}
	RedisModule_ZsetRangeStop(zone_key);
	RedisModule_CloseKey(zone_key);

	return RedisModule_ReplyWithLongLong(ctx, -1);
}

static int dump_rrset(RedisModuleCtx *ctx, knot_rrset_t *rrset, char *buf,
                      size_t buf_size, long *count, bool merge)
{
	const knot_dump_style_t style = KNOT_DUMP_STYLE_DEFAULT;

	knot_dname_txt_storage_t owner;
	(void)knot_dname_to_str(owner, rrset->owner, sizeof(owner));

	char rtype[16];
	(void)knot_rrtype_to_string(rrset->type, rtype, sizeof(rtype));

	char ttl[16];
	if (rrset->type != KNOT_RRTYPE_RRSIG) {
		(void)snprintf(ttl, sizeof(ttl), "%u", rrset->ttl);
	}

	knot_rdata_t *rr = rrset->rrs.rdata;
	for (uint16_t i = 0; i < rrset->rrs.count; i++) {
		if (rrset->type == KNOT_RRTYPE_RRSIG) {
			(void)snprintf(ttl, sizeof(ttl), "%u", knot_rrsig_original_ttl(rr));
		}

		int ret = knot_rrset_txt_dump_data(rrset, i, buf, buf_size, &style);
		if (ret == KNOT_ESPACE) {
			RedisModule_ReplyWithError(ctx, "ERR Not enough space");
			return -1;
		} else if (ret < 0) {
			RedisModule_ReplyWithError(ctx, "ERR Failed to convert rdata");
			return -1;
		}

		if (merge) {
			char *line = sprintf_alloc("%s %s %s %s", owner, ttl, rtype, *buf);
			if (line == NULL) {
				RedisModule_ReplyWithError(ctx, "ERR Failed to convert data");
				return -1;
			}
			RedisModule_ReplyWithStringBuffer(ctx, line, strlen(line));
			free(line);
		} else {
			RedisModule_ReplyWithArray(ctx, 4);
			RedisModule_ReplyWithStringBuffer(ctx, owner, strlen(owner));
			RedisModule_ReplyWithStringBuffer(ctx, ttl, strlen(ttl));
			RedisModule_ReplyWithStringBuffer(ctx, rtype, strlen(rtype));
			RedisModule_ReplyWithStringBuffer(ctx, buf, strlen(buf));
		}
		(*count)++;

		rr = knot_rdataset_next(rr);
	}

	return 0;
}

static int zone_load(RedisModuleCtx *ctx, const arg_dname_t *origin, rdb_txn_t *txn,
                     const arg_dname_t *opt_owner, uint16_t *opt_rtype, bool txt)
{
	if (txn->id == TXN_ID_ACTIVE) {
		int ret = set_active_transaction(ctx, origin, txn);
		if (ret != KNOT_EOK) {
			return RedisModule_ReplyWithError(ctx, "ERR unknown instance");
		}
	}

	RedisModuleKey *index_key = find_zone_index(ctx, origin, txn, REDISMODULE_READ);
	if (index_key == NULL) {
		return RedisModule_ReplyWithError(ctx, "ERR Unable find");
	}
	int zone_keytype = RedisModule_KeyType(index_key);
	if (zone_keytype == REDISMODULE_KEYTYPE_EMPTY) {
		RedisModule_CloseKey(index_key);
		return RedisModule_ReplyWithError(ctx, "ERR Does not exist");
	} else if (zone_keytype != REDISMODULE_KEYTYPE_ZSET) {
		RedisModule_CloseKey(index_key);
		return RedisModule_ReplyWithError(ctx, "ERR Bad data");
	}

	char buf[128 * 1024];

	long count = 0;
	RedisModule_ReplyWithArray(ctx, REDISMODULE_POSTPONED_ARRAY_LEN);
	foreach_in_zset (index_key) {
		double score = 0.0;
		RedisModuleString *el = RedisModule_ZsetRangeCurrentElement(index_key, &score);
		if (el == NULL) {
			break;
		}

		RedisModuleKey *rrset_key = RedisModule_OpenKey(ctx, el, REDISMODULE_READ);
		if (rrset_key == NULL) {
			continue;
		}

		size_t key_strlen = 0;
		const char *key_str = RedisModule_StringPtrLen(el, &key_strlen);
		wire_ctx_t w = wire_ctx_init((uint8_t *)key_str, key_strlen);
		wire_ctx_skip(&w, RDB_PREFIX_LEN + 1);
		wire_ctx_skip(&w, origin->len);
		knot_dname_t *owner = w.position;
		size_t owner_len = knot_dname_size(owner);
		wire_ctx_skip(&w, owner_len);
		uint16_t rtype = wire_ctx_read_u16(&w);
		RedisModule_Assert(w.error == KNOT_EOK);

		if (opt_owner != NULL &&
		    (opt_owner->len != owner_len || memcmp(owner, opt_owner->data, owner_len) != 0)) {
			RedisModule_CloseKey(rrset_key);
			continue;
		}
		if (opt_rtype != NULL && rtype != *opt_rtype) {
			RedisModule_CloseKey(rrset_key);
			continue;
		}

		rrset_v *rrset = RedisModule_ModuleTypeGetValue(rrset_key);

		if (txt) {
			knot_rrset_t rrset_out;
			knot_rrset_init(&rrset_out, owner, rtype, KNOT_CLASS_IN, rrset->ttl);
			rrset_out.rrs = rrset->rrs;
			if (dump_rrset(ctx, &rrset_out, buf, sizeof(buf), &count, false) != 0) {
				RedisModule_CloseKey(rrset_key);
				break;
			}
		} else {
			RedisModule_ReplyWithArray(ctx, 5);
			RedisModule_ReplyWithStringBuffer(ctx, (char *)owner, owner_len);
			RedisModule_ReplyWithLongLong(ctx, rtype);
			RedisModule_ReplyWithLongLong(ctx, rrset->ttl);
			RedisModule_ReplyWithLongLong(ctx, rrset->rrs.count);
			RedisModule_ReplyWithStringBuffer(ctx, (const char *)rrset->rrs.rdata, rrset->rrs.size);
			count++;
		}
		RedisModule_CloseKey(rrset_key);
	}
	RedisModule_ZsetRangeStop(index_key);
	RedisModule_CloseKey(index_key);
	RedisModule_ReplySetArrayLength(ctx, count);

	return REDISMODULE_OK;
}

static int zone_load_txt(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	rdb_txn_t txn = {
		.instance = 1,
		.id = TXN_ID_ACTIVE
	};
	arg_dname_t origin;
	arg_dname_t owner;
	uint16_t rtype;

	// Origin must be parsed before owner!
	if (argc > 1) {
		ARG_DNAME_TXT(argv[1], origin, NULL, "origin");
	}

	switch (argc) {
	case 5:
		ARG_RTYPE_TXT(argv[4], rtype);
	case 4: // FALLTHROUGH
		ARG_DNAME_TXT(argv[3], owner, &origin, "owner");
	case 3: // FALLTHROUGH
		ARG_INST_TXN_TXT(argv[2], txn);
	case 2: // FALLTHROUGH
		break;
	default:
		return RedisModule_WrongArity(ctx);
	}

	return zone_load(ctx, &origin, &txn,
	                 (argc >= 4) ? &owner : NULL,
	                 (argc >= 5) ? &rtype : NULL, true);
}

static int zone_load_bin(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	rdb_txn_t txn = {
		.instance = 1,
		.id = TXN_ID_ACTIVE
	};
	arg_dname_t origin;
	arg_dname_t owner;
	uint16_t rtype;

	switch (argc) {
	case 5:
		ARG_NUM(argv[4], rtype, "record type");
	case 4: // FALLTHROUGH
		ARG_DNAME(argv[1], owner, "owner");
	case 3:; // FALLTHROUGH
		ARG_INST_TXN(argv[2], txn);
	case 2: // FALLTHROUGH
		ARG_DNAME(argv[1], origin, "origin");
		break;
	default:
		return RedisModule_WrongArity(ctx);
	}

	return zone_load(ctx, &origin, &txn,
	                 (argc >= 4) ? &owner : NULL,
	                 (argc >= 5) ? &rtype : NULL, false);
}

static int zone_purge_txt(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 3) {
		return RedisModule_WrongArity(ctx);
	}

	rdb_txn_t txn = {
		.instance = 1,
		.id = TXN_ID_ACTIVE
	};
	arg_dname_t origin;

	ARG_DNAME_TXT(argv[1], origin, NULL, "origin");
	ARG_INST_TXT(argv[2], txn);

	return zone_purge(ctx, &origin, &txn);
}

static int zone_purge_bin(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 3) {
		return RedisModule_WrongArity(ctx);
	}
	rdb_txn_t txn = {
		.instance = 1,
		.id = TXN_ID_ACTIVE
	};
	arg_dname_t origin;

	ARG_DNAME(argv[1], origin, "origin");
	ARG_INST(argv[2], txn);

	return zone_purge(ctx, &origin, &txn);
}

static int upd_begin_txt(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	rdb_txn_t txn = { .instance = 1 };
	arg_dname_t origin;

	switch (argc) {
	case 3:
		ARG_INST_TXT(argv[2], txn);
	case 2: // FALLTHROUGH
		ARG_DNAME_TXT(argv[1], origin, NULL, "origin");
		break;
	default:
		return RedisModule_WrongArity(ctx);
	}

	if (upd_begin(ctx, &txn, &origin) != KNOT_EOK) {
		return REDISMODULE_OK;
	}

	return RedisModule_ReplyWithLongLong(ctx, serialize_transaction(&txn));
}

static int upd_begin_bin(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	rdb_txn_t txn = { .instance = 1 };
	arg_dname_t origin;

	switch (argc) {
	case 3:
		ARG_INST(argv[2], txn);
	case 2: // FALLTHROUGH
		ARG_DNAME(argv[1], origin, "origin");
		break;
	default:
		return RedisModule_WrongArity(ctx);
	}

	if (upd_begin(ctx, &txn, &origin) != KNOT_EOK) {
		return REDISMODULE_OK;
	}

	return RedisModule_ReplyWithStringBuffer(ctx, (const char *)&txn, sizeof(txn));
}

static bool upd_meta_get_when_open(RedisModuleCtx *ctx, const arg_dname_t *origin,
                                   const rdb_txn_t *txn, RedisModuleKey **key, int rights)
{
	RedisModule_Assert(key != NULL && *key == NULL);

	RedisModuleString *txn_k = upd_meta_keyname_construct(ctx, origin, txn->instance);
	*key = RedisModule_OpenKey(ctx, txn_k, rights);
	RedisModule_FreeString(ctx, txn_k);
	if (key == NULL || RedisModule_KeyType(*key) != REDISMODULE_KEYTYPE_STRING) {
		return false;
	}
	size_t len = 0;
	const upd_meta_storage_t *transaction = (const upd_meta_storage_t *)RedisModule_StringDMA(*key, &len, REDISMODULE_WRITE);
	return transaction->lock[txn->id] != 0;
}

static RedisModuleString *diff_keyname_construct(RedisModuleCtx *ctx, const arg_dname_t *origin,
                                                 const rdb_txn_t *txn, const arg_dname_t *owner,
                                                 uint16_t rtype, uint16_t id)
{
	RedisModule_Assert(ctx != NULL && txn != NULL);

	uint8_t prefix = DIFF;
	char buf[RRSET_KEY_MAXLEN];

	wire_ctx_t w = wire_ctx_init((uint8_t *)buf, sizeof(buf));
	wire_ctx_write(&w, RDB_PREFIX, RDB_PREFIX_LEN);
	wire_ctx_write(&w, &prefix, sizeof(prefix));
	wire_ctx_write(&w, origin->data, origin->len);
	wire_ctx_write(&w, owner->data, owner->len);
	wire_ctx_write_u16(&w, rtype);
	wire_ctx_write(&w, txn, sizeof(*txn));
	wire_ctx_write(&w, &id, sizeof(id));

	RedisModule_Assert(w.error == KNOT_EOK);

	return RedisModule_CreateString(ctx, buf, wire_ctx_offset(&w));
}

typedef int (*upd_callback)(diff_v *diff, const knot_rdata_t *rdataset);

static int upd_add_txt_cb(diff_v *diff, const knot_rdata_t *rdataset)
{
	knot_rdataset_remove(&diff->remove_rrs, rdataset, &mm);
	knot_rdataset_add(&diff->add_rrs, rdataset, &mm);
	return KNOT_EOK;
}

static int upd_remove_txt_cb(diff_v *diff, const knot_rdata_t *rdataset)
{
	knot_rdataset_remove(&diff->add_rrs, rdataset, &mm);
	knot_rdataset_add(&diff->remove_rrs, rdataset, &mm);
	return KNOT_EOK;
}

static int upd_add_bin_cb(diff_v *diff, const knot_rdata_t *rdataset)
{
	if (diff->add_rrs.count) {
		return KNOT_EBUSY;
	}
	knot_rdataset_add(&diff->add_rrs, rdataset, &mm);
	return KNOT_EOK;
}

static int upd_remove_bin_cb(diff_v *diff, const knot_rdata_t *rdataset)
{
	if (diff->remove_rrs.count) {
		return KNOT_EBUSY;
	}
	knot_rdataset_add(&diff->remove_rrs, rdataset, &mm);
	return KNOT_EOK;
}

static int upd_add_rem(RedisModuleCtx *ctx, const arg_dname_t *origin, const rdb_txn_t *txn,
                       const arg_dname_t *owner, const uint32_t ttl, const uint16_t rtype,
                       const knot_rdata_t *rdataset, upd_callback cb)
{
	assert(cb != NULL);

	int ret = get_id(ctx, origin, txn);
	if (ret < 0 || ret > UINT16_MAX) {
		RedisModule_ReplyWithError(ctx, "Unknown transaction ID");
		return KNOT_EACCES;
	}
	uint16_t id = ret;

	RedisModuleString *diff_keystr = diff_keyname_construct(ctx, origin, txn, owner, rtype, id);
	RedisModuleKey *diff_key = RedisModule_OpenKey(ctx, diff_keystr, REDISMODULE_READ | REDISMODULE_WRITE);

	diff_v *diff = NULL;
	int diff_keytype = RedisModule_KeyType(diff_key);
	if (diff_keytype == REDISMODULE_KEYTYPE_EMPTY) {
		diff = RedisModule_Calloc(1, sizeof(diff_v));
		if (diff == NULL) {
			RedisModule_CloseKey(diff_key);
			RedisModule_ReplyWithError(ctx, "ERR Cannot allocate memory");
			return KNOT_ENOMEM;
		}
		RedisModule_ModuleTypeSetValue(diff_key, knot_diff_t, diff);

		diff->dest_ttl = (ttl == TTL_EMPTY) ? rdb_default_ttl : ttl;

		RedisModuleKey *diff_index_key = find_upd_index(ctx, origin, txn, id, REDISMODULE_READ | REDISMODULE_WRITE);
		if (RedisModule_KeyType(diff_index_key) != REDISMODULE_KEYTYPE_EMPTY &&
		    RedisModule_KeyType(diff_index_key) != REDISMODULE_KEYTYPE_ZSET) {
			RedisModule_ReplyWithError(ctx, "ERR Bad data");
			return KNOT_EINVAL;
		}
		ret = RedisModule_ZsetAdd(diff_index_key, evaluate_score(rtype), diff_keystr, NULL);
		if (ret != REDISMODULE_OK) {
			RedisModule_ReplyWithError(ctx, "ERR Unable to add to zset");
			return KNOT_EINVAL;
		}
	} else if (diff_keytype == REDISMODULE_KEYTYPE_MODULE &&
	           RedisModule_ModuleTypeGetType(diff_key) == knot_diff_t) {
		diff = RedisModule_ModuleTypeGetValue(diff_key);
	} else {
		RedisModule_CloseKey(diff_key);
		RedisModule_ReplyWithError(ctx, "ERR Bad data");
		return KNOT_EINVAL;
	}

	ret = cb(diff, rdataset);
	if (ret == KNOT_EBUSY) {
		RedisModule_ReplyWithError(ctx, "ERR Already set");
	}

	RedisModule_CloseKey(diff_key);
	RedisModule_FreeString(ctx, diff_keystr);

	return ret;
}

static void scanner_upd_data(zs_scanner_t *s)
{
	scanner_ctx_t *s_ctx = s->process.data;

	uint8_t buf[knot_rdata_size(s->r_data_length)];
	knot_rdata_t *rdata = (knot_rdata_t *)buf;
	knot_rdata_init(rdata, s->r_data_length, s->r_data);

	if (knot_rdata_to_canonical(rdata, s->r_type) != KNOT_EOK) {
		RedisModule_ReplyWithError(s_ctx->ctx, "Malformed record data");
		s_ctx->replied = true;
		s->state = ZS_STATE_STOP;
		return;
	}

	arg_dname_t origin = { .data = s->zone_origin, .len = s->zone_origin_length };
	arg_dname_t owner = { .data = s->r_owner, .len = s->r_owner_length };
	int ret = KNOT_EOK;
	if (s_ctx->remove == false) {
		ret = knot_upd_add_txt(s_ctx->ctx, &origin, s_ctx->txn, &owner, s->r_ttl, s->r_type, rdata);
	} else {
		ret = knot_upd_remove_txt(s_ctx->ctx, &origin, s_ctx->txn, &owner, 0, s->r_type, rdata);
	}
	if (ret != 0) {
		s_ctx->replied = true;
		s->state = ZS_STATE_STOP;
		return;
	}
}

static int upd_add_txt(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 4) {
		return RedisModule_WrongArity(ctx);
	}

	arg_dname_t origin;
	ARG_DNAME_TXT(argv[1], origin, NULL, "origin");

	rdb_txn_t txn;
	ARG_TXN_TXT(argv[2], txn);

	size_t record_len;
	const char *record_str = RedisModule_StringPtrLen(argv[3], &record_len);

	zs_scanner_t s;
	scanner_ctx_t s_ctx = { ctx, &txn, false, false };
	if (zs_init(&s, origin.txt, KNOT_CLASS_IN, TTL_EMPTY) != 0 ||
	    zs_set_input_string(&s, record_str, record_len) != 0 ||
	    zs_set_processing(&s, scanner_upd_data, scanner_error, &s_ctx) != 0 ||
	    zs_parse_all(&s) != 0) {
		zs_deinit(&s);
		if (!s_ctx.replied) {
			RedisModule_ReplyWithError(ctx, "Parser failed");
			return KNOT_EMALF;
		}
		return KNOT_EMALF;
	}
	zs_deinit(&s);

	return RedisModule_ReplyWithSimpleString(ctx, RDB_RETURN_OK);
}

static int upd_add_bin(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 8) {
		return RedisModule_WrongArity(ctx);
	}

	arg_dname_t origin;
	ARG_DNAME(argv[1], origin, "origin");

	rdb_txn_t txn;
	ARG_TXN(argv[2], txn);

	arg_dname_t owner;
	ARG_DNAME(argv[3], owner, "owner");

	uint16_t rtype;
	ARG_NUM(argv[4], rtype, "record type");

	uint32_t ttl;
	ARG_NUM(argv[5], ttl, "TTL");

	uint16_t rcount;
	ARG_NUM(argv[6], rcount, "record count");

	uint8_t *rdataset;
	size_t rdataset_len;
	ARG_DATA(argv[7], rdataset_len, rdataset, "rdataset");

	uint8_t buf[knot_rdata_size(rdataset_len)];
	knot_rdata_init((knot_rdata_t *)buf, rdataset_len, rdataset);

	knot_upd_add_bin(ctx, &origin, &txn, &owner, ttl, rtype, (knot_rdata_t *)buf);

	return RedisModule_ReplyWithSimpleString(ctx, RDB_RETURN_OK);
}

static int upd_remove_txt(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 4) {
		return RedisModule_WrongArity(ctx);
	}

	arg_dname_t origin;
	ARG_DNAME_TXT(argv[1], origin, NULL, "origin");

	rdb_txn_t txn;
	ARG_TXN_TXT(argv[2], txn);

	size_t record_len;
	const char *record_str = RedisModule_StringPtrLen(argv[3], &record_len);

	zs_scanner_t s;
	scanner_ctx_t s_ctx = { ctx, &txn, false, true };
	if (zs_init(&s, origin.txt, KNOT_CLASS_IN, rdb_default_ttl) != 0 ||
	    zs_set_input_string(&s, record_str, record_len) != 0 ||
	    zs_set_processing(&s, scanner_upd_data, scanner_error, &s_ctx) != 0 ||
	    zs_parse_all(&s) != 0) {
		zs_deinit(&s);
		if (!s_ctx.replied) {
			RedisModule_ReplyWithError(ctx, "Parser failed");
			return KNOT_EMALF;
		}
		return KNOT_EMALF;
	}
	zs_deinit(&s);

	return RedisModule_ReplyWithSimpleString(ctx, RDB_RETURN_OK);
}

static int upd_remove_bin(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 7) {
		return RedisModule_WrongArity(ctx);
	}

	arg_dname_t origin;
	ARG_DNAME(argv[1], origin, "origin");

	rdb_txn_t txn;
	ARG_TXN(argv[2], txn);

	arg_dname_t owner;
	ARG_DNAME(argv[3], owner, "owner");

	uint16_t rtype;
	ARG_NUM(argv[4], rtype, "record type");

	uint16_t rcount;
	ARG_NUM(argv[5], rcount, "record count");

	uint8_t *rdataset;
	size_t rdataset_len;
	ARG_DATA(argv[6], rdataset_len, rdataset, "rdataset");

	uint8_t buf[knot_rdata_size(rdataset_len)];
	knot_rdata_init((knot_rdata_t *)buf, rdataset_len, rdataset);

	knot_upd_remove_bin(ctx, &origin, &txn, &owner, 0, rtype, (knot_rdata_t *)buf);

	return RedisModule_ReplyWithSimpleString(ctx, RDB_RETURN_OK);
}

static int upd_meta_unlock(RedisModuleCtx *ctx, RedisModuleKey *key, uint8_t id)
{
	size_t len = 0;
	upd_meta_storage_t *meta = (upd_meta_storage_t *)RedisModule_StringDMA(key, &len, REDISMODULE_WRITE);
	if (len != sizeof(*meta)) {
		RedisModule_CloseKey(key);
		RedisModule_ReplyWithError(ctx, "ERR Bad data");
		return KNOT_ENOENT;
	}
	meta->lock[id] = 0;
	return KNOT_EOK;
}

static int upd_commit(RedisModuleCtx *ctx, const arg_dname_t *origin, rdb_txn_t *txn)
{
	RedisModuleKey *meta_key = NULL;
	if (upd_meta_get_when_open(ctx, origin, txn, &meta_key, REDISMODULE_READ | REDISMODULE_WRITE) == false) {
		RedisModule_CloseKey(meta_key);
		RedisModule_ReplyWithError(ctx, "ERR Non-existent transaction");
		return KNOT_ENOENT;
	}

	int ret = get_id(ctx, origin, txn);
	if (ret <= KNOT_EOK || ret > UINT16_MAX) {
		RedisModule_CloseKey(meta_key);
		RedisModule_ReplyWithError(ctx, "ERR Non-existent transaction");
		return KNOT_ENOENT;
	}
	uint16_t id = ret;

	rdb_txn_t zone_txn = {
		.instance = txn->instance
	};
	ret = set_active_transaction(ctx, origin, &zone_txn);
	if (ret != KNOT_EOK) {
		RedisModule_ReplyWithError(ctx, "ERR None active zone");
		return KNOT_ENOENT;
	}

	RedisModuleKey *zone_key = find_zone_index(ctx, origin, &zone_txn, REDISMODULE_READ | REDISMODULE_WRITE);

	RedisModuleString *soa_keyname = NULL;
	size_t soa_cnt = 0;
	foreach_in_zset_subset(zone_key, SCORE_SOA, SCORE_SOA) {
		double score = 0.0;
		soa_keyname = RedisModule_ZsetRangeCurrentElement(zone_key, &score);
		if (soa_keyname == NULL) {
			break;
		}
		++soa_cnt;
	}
	RedisModule_CloseKey(zone_key);
	if (soa_cnt != 1) {
		RedisModule_CloseKey(meta_key);
		RedisModule_ReplyWithError(ctx, "ERR Missing SOA");
		return KNOT_ENOENT;
	}

	RedisModuleKey *soa_key = RedisModule_OpenKey(ctx, soa_keyname, REDISMODULE_WRITE);
	if (RedisModule_ModuleTypeGetType(soa_key) != knot_zone_rrset_t) {
		RedisModule_ReplyWithError(ctx, "ERR Bad data");
		return KNOT_ENOENT;
	}
	rrset_v *soa_rrset = RedisModule_ModuleTypeGetValue(soa_key);
	uint32_t new_serial = knot_soa_serial(soa_rrset->rrs.rdata);

	RedisModuleString *soa_diff_keyname = diff_keyname_construct(ctx, origin, txn, origin, KNOT_RRTYPE_SOA, id);
	RedisModuleKey *soa_diff_key = RedisModule_OpenKey(ctx, soa_diff_keyname, REDISMODULE_WRITE);
	if (RedisModule_KeyType(soa_diff_key) == REDISMODULE_KEYTYPE_EMPTY) {
		new_serial += 1;
	} else {
		diff_v *diff = RedisModule_ModuleTypeGetValue(soa_diff_key);
		if (diff->add_rrs.count == 1) {
			new_serial = knot_soa_serial(diff->add_rrs.rdata);
		} else {
			RedisModule_ReplyWithError(ctx, "ERR Bad data");
			RedisModule_CloseKey(soa_diff_key);
			return KNOT_ENOENT;
		}
	}

	RedisModuleKey *upd_key = find_upd_index(ctx, origin, txn, id, REDISMODULE_READ | REDISMODULE_WRITE);
	RedisModuleKey *new_upd_key = find_commited_upd_index(ctx, origin, txn, new_serial, REDISMODULE_READ | REDISMODULE_WRITE);
	foreach_in_zset(upd_key) {
		double score = 0.0;
		RedisModuleString *el = RedisModule_ZsetRangeCurrentElement(upd_key, &score);
		if (el == NULL) {
			break;
		}

		RedisModule_ZsetAdd(new_upd_key, score, el, NULL);

		size_t el_len = 0;
		const char *el_str = RedisModule_StringPtrLen(el, &el_len);
		wire_ctx_t w = wire_ctx_init((uint8_t *)el_str, el_len);

		wire_ctx_skip(&w, 3 + origin->len);
		arg_dname_t owner = {
			.data = w.position,
			.len = knot_dname_size(w.position)
		};
		wire_ctx_skip(&w, owner.len);
		uint16_t rtype = wire_ctx_read_u16(&w);

		RedisModuleKey *diff_key = RedisModule_OpenKey(ctx, el, REDISMODULE_READ);
		const diff_v *diff = RedisModule_ModuleTypeGetValue(diff_key);

		uint16_t rr_count = diff->remove_rrs.count;
		knot_rdata_t *rr = diff->remove_rrs.rdata;
		for (size_t i = 0; i < rr_count; ++i) {
			rdata_remove(ctx, &zone_txn, origin, &owner, rtype, 0, diff->remove_rrs.rdata);
			rr = knot_rdataset_next(rr);
		}

		rr_count = diff->add_rrs.count;
		rr = diff->add_rrs.rdata;
		for (size_t i = 0; i < rr_count; ++i) {
			rdata_add(ctx, &zone_txn, origin, &owner, rtype, diff->dest_ttl, diff->add_rrs.rdata);
			rr = knot_rdataset_next(rr);
		}

		RedisModule_CloseKey(diff_key);
	}

	RedisModule_DeleteKey(upd_key);
	RedisModule_CloseKey(upd_key);

	if (soa_rrset->rrs.count != 1) {
		RedisModule_CloseKey(soa_diff_key);
		RedisModule_FreeString(ctx, soa_diff_keyname);
		RedisModule_CloseKey(new_upd_key);
		RedisModule_CloseKey(soa_key);
		RedisModule_ReplyWithError(ctx, "ERR Only one SOA allowed in final RRSet");
		return KNOT_ENOMEM;
	}

	if (knot_soa_serial(soa_rrset->rrs.rdata) != new_serial) {
		// routine for add diffs of serial change
		if (RedisModule_KeyType(soa_diff_key) != REDISMODULE_KEYTYPE_EMPTY) {
			RedisModule_CloseKey(soa_diff_key);
			RedisModule_FreeString(ctx, soa_diff_keyname);
			RedisModule_CloseKey(new_upd_key);
			RedisModule_CloseKey(soa_key);
			RedisModule_ReplyWithError(ctx, "ERR Bad data");
			return KNOT_ENOMEM;
		}

		diff_v *diff = RedisModule_Calloc(1, sizeof(diff_v));
		diff->dest_ttl = soa_rrset->ttl;
		knot_rdataset_add(&diff->remove_rrs, soa_rrset->rrs.rdata, &mm);
		knot_soa_serial_set(soa_rrset->rrs.rdata, new_serial);
		knot_rdataset_add(&diff->add_rrs, soa_rrset->rrs.rdata, &mm);
		RedisModule_ModuleTypeSetValue(soa_diff_key, knot_diff_t, diff);

		RedisModule_ZsetAdd(new_upd_key, evaluate_score(KNOT_RRTYPE_SOA), soa_diff_keyname, NULL);
	}
	RedisModule_CloseKey(soa_diff_key);
	RedisModule_FreeString(ctx, soa_diff_keyname);
	RedisModule_CloseKey(new_upd_key);
	RedisModule_CloseKey(soa_key);

	if (upd_meta_unlock(ctx, meta_key, txn->id) != KNOT_EOK) {
		RedisModule_CloseKey(meta_key);
		return KNOT_ENOENT;
	}
	RedisModule_CloseKey(meta_key);

	return commit_event(ctx, RDB_EVENT_UPD, origin, txn->instance, new_serial);
}

static int upd_commit_txt(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 3) {
		return RedisModule_WrongArity(ctx);
	}

	arg_dname_t origin;
	ARG_DNAME_TXT(argv[1], origin, NULL, "origin");

	rdb_txn_t txn;
	ARG_TXN_TXT(argv[2], txn);

	if (upd_commit(ctx, &origin, &txn) != KNOT_EOK) {
		return REDISMODULE_OK;
	}

	return RedisModule_ReplyWithSimpleString(ctx, RDB_RETURN_OK);
}

static int upd_commit_bin(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 3) {
		return RedisModule_WrongArity(ctx);
	}

	arg_dname_t origin;
	ARG_DNAME(argv[1], origin, "origin");

	rdb_txn_t txn;
	ARG_TXN(argv[2], txn)

	if (upd_commit(ctx, &origin, &txn) != KNOT_EOK) {

		return REDISMODULE_OK;
	}

	return RedisModule_ReplyWithSimpleString(ctx, RDB_RETURN_OK);
}

static int upd_abort(RedisModuleCtx *ctx, const arg_dname_t *origin, rdb_txn_t *txn)
{
	RedisModuleKey *meta_key = NULL;
	if (upd_meta_get_when_open(ctx, origin, txn, &meta_key, REDISMODULE_READ | REDISMODULE_WRITE) == false) {
		RedisModule_CloseKey(meta_key);
		RedisModule_ReplyWithError(ctx, "Non-existent transaction");
		return KNOT_ENOENT;
	}

	delete_upd_index(ctx, txn, origin);

	if (upd_meta_unlock(ctx, meta_key, txn->id) != KNOT_EOK) {
		RedisModule_CloseKey(meta_key);
		return KNOT_ENOENT;
	}
	RedisModule_CloseKey(meta_key);

	return KNOT_EOK;
}

static int upd_abort_txt(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 3) {
		return RedisModule_WrongArity(ctx);
	}

	arg_dname_t origin;
	ARG_DNAME_TXT(argv[1], origin, NULL, "origin");

	rdb_txn_t txn;
	ARG_TXN_TXT(argv[2], txn);

	if (upd_abort(ctx, &origin, &txn) != KNOT_EOK) {
		return REDISMODULE_OK;
	}

	return RedisModule_ReplyWithSimpleString(ctx, RDB_RETURN_OK);
}

static int upd_abort_bin(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 3) {
		return RedisModule_WrongArity(ctx);
	}

	arg_dname_t origin;
	ARG_DNAME(argv[1], origin, "origin");

	rdb_txn_t txn;
	ARG_TXN(argv[2], txn)

	if (upd_abort(ctx, &origin, &txn) != KNOT_EOK) {
		return REDISMODULE_OK;
	}

	return RedisModule_ReplyWithSimpleString(ctx, RDB_RETURN_OK);
}

static int upd_dump(RedisModuleCtx *ctx, RedisModuleKey *index_key, const arg_dname_t *origin,
                    const arg_dname_t *opt_owner, const uint16_t *opt_rtype, bool txt)
{
	int zone_keytype = RedisModule_KeyType(index_key);
	if (zone_keytype == REDISMODULE_KEYTYPE_EMPTY) {
		RedisModule_CloseKey(index_key);
		return RedisModule_ReplyWithError(ctx, "ERR Does not exist");
	} else if (zone_keytype != REDISMODULE_KEYTYPE_ZSET) {
		RedisModule_CloseKey(index_key);
		return RedisModule_ReplyWithError(ctx, "ERR Bad data");
	}

	char buf[128 * 1024];

	long count = 0;
	RedisModule_ReplyWithArray(ctx, REDISMODULE_POSTPONED_ARRAY_LEN);
	foreach_in_zset (index_key) {
		double score = 0.0;
		RedisModuleString *el = RedisModule_ZsetRangeCurrentElement(index_key, &score);
		if (el == NULL) {
			break;
		}

		RedisModuleKey *diff_key = RedisModule_OpenKey(ctx, el, REDISMODULE_READ);
		if (diff_key == NULL) {
			continue;
		}

		size_t key_strlen = 0;
		const char *key_str = RedisModule_StringPtrLen(el, &key_strlen);
		wire_ctx_t w = wire_ctx_init((uint8_t *)key_str, key_strlen);

		wire_ctx_skip(&w, RDB_PREFIX_LEN + 1);
		wire_ctx_skip(&w, origin->len);
		knot_dname_t *owner = w.position;
		size_t owner_len = knot_dname_size(owner);

		wire_ctx_skip(&w, owner_len);
		uint16_t rtype = wire_ctx_read_u16(&w);

		RedisModule_Assert(w.error == KNOT_EOK);

		if (opt_owner != NULL &&
		    (opt_owner->len != owner_len || memcmp(owner, opt_owner->data, owner_len) != 0)) {
			RedisModule_CloseKey(diff_key);
			continue;
		}

		if (opt_rtype != NULL && rtype != *opt_rtype) {
			RedisModule_CloseKey(diff_key);
			continue;
		}

		diff_v *diff = RedisModule_ModuleTypeGetValue(diff_key);
		if (txt) {
			RedisModule_ReplyWithArray(ctx, 2);
			RedisModule_ReplyWithArray(ctx, REDISMODULE_POSTPONED_ARRAY_LEN);
			long count_sub = 0;
			knot_rrset_t rrset_out;
			knot_rrset_init(&rrset_out, owner, rtype, KNOT_CLASS_IN, 0);
			rrset_out.rrs = diff->remove_rrs;
			if (dump_rrset(ctx, &rrset_out, buf, sizeof(buf), &count_sub, false) != 0) {
				RedisModule_CloseKey(diff_key);
				break;
			}
			RedisModule_ReplySetArrayLength(ctx, count_sub);

			RedisModule_ReplyWithArray(ctx, REDISMODULE_POSTPONED_ARRAY_LEN);
			count_sub = 0;
			knot_rrset_init(&rrset_out, owner, rtype, KNOT_CLASS_IN, diff->dest_ttl);
			rrset_out.rrs = diff->add_rrs;
			if (dump_rrset(ctx, &rrset_out, buf, sizeof(buf), &count_sub, false) != 0) {
				RedisModule_CloseKey(diff_key);
				break;
			}
			RedisModule_ReplySetArrayLength(ctx, count_sub);
		} else {
			RedisModule_ReplyWithArray(ctx, 7);
			RedisModule_ReplyWithStringBuffer(ctx, (char *)owner, owner_len);
			RedisModule_ReplyWithLongLong(ctx, rtype);
			RedisModule_ReplyWithLongLong(ctx, diff->dest_ttl);
			RedisModule_ReplyWithLongLong(ctx, diff->remove_rrs.count);
			RedisModule_ReplyWithStringBuffer(ctx, (const char *)diff->remove_rrs.rdata, diff->remove_rrs.size);
			RedisModule_ReplyWithLongLong(ctx, diff->add_rrs.count);
			RedisModule_ReplyWithStringBuffer(ctx, (const char *)diff->add_rrs.rdata, diff->add_rrs.size);
		}
		count++;
		RedisModule_CloseKey(diff_key);
	}
	RedisModule_ZsetRangeStop(index_key);
	RedisModule_ReplySetArrayLength(ctx, count);

	return REDISMODULE_OK;
}

static int upd_diff(RedisModuleCtx *ctx, const arg_dname_t *origin, const rdb_txn_t *txn,
                    const arg_dname_t *opt_owner, uint16_t *opt_rtype, bool txt)
{
	int ret = get_id(ctx, origin, txn);
	if (ret < 0 || ret > UINT16_MAX) {
		RedisModule_ReplyWithError(ctx, "Unknown transaction ID");
		return ret;
	}
	uint16_t id = ret;
	RedisModuleKey *index_key = find_upd_index(ctx, origin, txn, id, REDISMODULE_READ | REDISMODULE_WRITE);
	if (index_key == NULL) {
		return RedisModule_ReplyWithError(ctx, "ERR Unable find");
	}

	upd_dump(ctx, index_key, origin, opt_owner, opt_rtype, txt);

	RedisModule_CloseKey(index_key);

	return REDISMODULE_OK;
}

static int upd_load_serial(RedisModuleCtx *ctx, size_t *counter, const arg_dname_t *origin,
                           const rdb_txn_t *txn, const uint32_t serial_final, const uint32_t serial,
                           const arg_dname_t *opt_owner, const uint16_t *opt_rtype, const bool txt)
{
	RedisModuleKey *upd_index_key = find_commited_upd_index(ctx, origin, txn, serial, REDISMODULE_READ);
	if (upd_index_key == NULL) {
		return KNOT_EOK;
	}
	RedisModuleString *soa_diff_keyname = NULL;
	size_t soa_count = 0;
	foreach_in_zset_subset(upd_index_key, SCORE_SOA, SCORE_SOA) {
		double score = 0.0;
		soa_diff_keyname = RedisModule_ZsetRangeCurrentElement(upd_index_key, &score);
		if (soa_diff_keyname == NULL) {
			break;
		}
		++soa_count;
	}
	if (soa_count != 1) {
		RedisModule_ReplyWithError(ctx, "ERR malformed SOA");
		return KNOT_EINVAL;
	}

	RedisModuleKey *soa_diff_key = RedisModule_OpenKey(ctx, soa_diff_keyname, REDISMODULE_READ);
	diff_v *diff = RedisModule_ModuleTypeGetValue(soa_diff_key);
	uint32_t serial_next = knot_soa_serial(diff->remove_rrs.rdata);

	if (serial_next != serial_final) {
		upd_load_serial(ctx, counter, origin, txn, serial_final, serial_next, opt_owner, opt_rtype, txt);
	}

	int ret = upd_dump(ctx, upd_index_key, origin, opt_owner, opt_rtype, txt);
	++(*counter);

	RedisModule_CloseKey(upd_index_key);

	return ret;
}

static int upd_load(RedisModuleCtx *ctx, const arg_dname_t *origin, rdb_txn_t *txn,
                    const uint32_t serial, const arg_dname_t *opt_owner, const uint16_t *opt_rtype, bool txt)
{
	if (set_active_transaction(ctx, origin, txn) != KNOT_EOK) {
		RedisModule_ReplyWithError(ctx, "ERR not active zone");
		return KNOT_EEXIST;
	}
	RedisModuleString *soa_rrset_keyname = rrset_keyname_construct(ctx, txn, origin, origin, KNOT_RRTYPE_SOA);
	RedisModuleKey *soa_rrset_key = RedisModule_OpenKey(ctx, soa_rrset_keyname, REDISMODULE_READ);
	RedisModule_FreeString(ctx, soa_rrset_keyname);
	rrset_v *rrset = RedisModule_ModuleTypeGetValue(soa_rrset_key);
	if (rrset == NULL) {
		RedisModule_CloseKey(soa_rrset_key);
		RedisModule_Log(ctx, REDISMODULE_LOGLEVEL_WARNING, "ERR missing SOA rrset");
		RedisModule_ReplyWithError(ctx, "ERR missing SOA rrset");
		return KNOT_EACCES;
	}
	uint32_t serial_it = knot_soa_serial(rrset->rrs.rdata);
	RedisModule_CloseKey(soa_rrset_key);

	size_t counter = 0;
	RedisModule_ReplyWithArray(ctx, REDISMODULE_POSTPONED_ARRAY_LEN);
	upd_load_serial(ctx, &counter, origin, txn, serial, serial_it, opt_owner, opt_rtype, txt);
	RedisModule_ReplySetArrayLength(ctx, counter);

	return REDISMODULE_OK;
}

static int upd_diff_txt(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	rdb_txn_t txn = {
		.instance = 1,
		.id = TXN_ID_ACTIVE
	};
	arg_dname_t origin;
	arg_dname_t owner;
	uint16_t rtype;

	// Origin must be parsed before owner!
	if (argc > 1) {
		ARG_DNAME_TXT(argv[1], origin, NULL, "origin");
	}

	switch (argc) {
	case 5:
		ARG_RTYPE_TXT(argv[4], rtype);
	case 4: // FALLTHROUGH
		ARG_DNAME_TXT(argv[3], owner, &origin, "owner");
	case 3: // FALLTHROUGH
		ARG_TXN_TXT(argv[2], txn);
		break;
	default:
		return RedisModule_WrongArity(ctx);
	}

	return upd_diff(ctx, &origin, &txn, (argc >= 4) ? &owner : NULL,
	                (argc >= 5) ? &rtype : NULL, true);
}

static int upd_diff_bin(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	rdb_txn_t txn = {
		.instance = 1,
		.id = TXN_ID_ACTIVE
	};
	arg_dname_t origin;
	arg_dname_t owner;
	uint16_t rtype;

	switch (argc) {
	case 5:
		ARG_NUM(argv[4], rtype, "record type");
	case 4: // FALLTHROUGH
		ARG_DNAME(argv[3], owner, "owner");
	case 3: // FALLTHROUGH
		ARG_TXN(argv[2], txn);
		ARG_DNAME(argv[1], origin, "origin");
		break;
	default:
		return RedisModule_WrongArity(ctx);
	}

	return upd_diff(ctx, &origin, &txn, (argc >= 4) ? &owner : NULL,
	                (argc >= 5) ? &rtype : NULL, false);
}

static int upd_load_txt(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	arg_dname_t origin;
	arg_dname_t owner;
	rdb_txn_t txn = {
		.instance = 1
	};
	uint32_t serial;
	uint16_t rtype;

	// Origin must be parsed before owner!
	if (argc > 1) {
		ARG_DNAME_TXT(argv[1], origin, NULL, "origin");
	}

	switch (argc) {
	case 6:
		ARG_RTYPE_TXT(argv[5], rtype);
	case 5: // FALLTHROUGH
		ARG_DNAME_TXT(argv[4], owner, &origin, "owner");
	case 4: // FALLTHROUGH
		ARG_NUM(argv[3], serial, "serial");
		ARG_INST_TXT(argv[2], txn);
		break;
	default:
		return RedisModule_WrongArity(ctx);
	}

	return upd_load(ctx, &origin, &txn, serial,
	                (argc >= 5) ? &owner : NULL,
	                (argc >= 6) ? &rtype : NULL, true);
}

static int upd_load_bin(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	arg_dname_t origin;
	arg_dname_t owner;
	rdb_txn_t txn = {
		.instance = 1
	};
	uint32_t serial;
	uint16_t rtype;

	switch (argc) {
	case 6:
		ARG_NUM(argv[5], rtype, "record type");
	case 5: // FALLTHROUGH
		ARG_DNAME(argv[4], owner, "owner");
	case 4: // FALLTHROUGH
		ARG_NUM(argv[3], serial, "serial");
		ARG_INST(argv[2], txn);
		ARG_DNAME(argv[1], origin, "origin");
		break;
	default:
		return RedisModule_WrongArity(ctx);
	}

	return upd_load(ctx, &origin, &txn, serial,
	                (argc >= 5) ? &owner : NULL,
	                (argc >= 6) ? &rtype : NULL, false);
}

#define LOAD_ERROR(ctx, msg) { \
	RedisModule_Log(ctx, REDISMODULE_LOGLEVEL_WARNING, "ERR " msg); \
	RedisModule_ReplyWithError(ctx, "ERR " msg); \
	return REDISMODULE_ERR; \
}

__attribute__((visibility("default")))
int RedisModule_OnLoad(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	RedisModuleTypeMethods rrset_tm = {
		.version = REDISMODULE_TYPE_METHOD_VERSION,
		.rdb_load = rrset_load,
		.rdb_save = rrset_save,
		.mem_usage = rrset_mem_usage,
		.aof_rewrite = rrset_rewrite,
		.free = rrset_free
	};

	RedisModuleTypeMethods diff_tm = {
		.version = REDISMODULE_TYPE_METHOD_VERSION,
		.rdb_load = diff_load,
		.rdb_save = diff_save,
		.mem_usage = diff_mem_usage,
		.aof_rewrite = diff_rewrite,
		.free = diff_free
	};

	if (RedisModule_Init(ctx, "knot", 1, REDISMODULE_APIVER_1) == REDISMODULE_ERR) {
		LOAD_ERROR(ctx, "module already loaded");
	}

	for (int i = 0; i < argc; i += 2) {
		long long num;
		size_t key_len;
		const char *key = RedisModule_StringPtrLen(argv[i], &key_len);
		if (i + 1 >= argc) {
			LOAD_ERROR(ctx, "missing configuration option value");
		}
		if (strncmp(key, RDB_PARAM_DFLT_TTL, key_len) == 0) {
			if (RedisModule_StringToLongLong(argv[i + 1], &num) == REDISMODULE_OK &&
			    num <= INT32_MAX) {
				rdb_default_ttl = num;
			} else {
				LOAD_ERROR(ctx, "invalid value of " RDB_PARAM_DFLT_TTL);
			}
		} else if (strncmp(key, RDB_PARAM_EVENT_AGE, key_len) == 0) {
			if (RedisModule_StringToLongLong(argv[i + 1], &num) == REDISMODULE_OK) {
				rdb_event_age = num;
			} else {
				LOAD_ERROR(ctx, "invalid value of " RDB_PARAM_EVENT_AGE);
			}
		} else {
			LOAD_ERROR(ctx, "unknown configuration option");
		}
	}

	knot_zone_rrset_t = RedisModule_CreateDataType(ctx, "KnotRRset", // Note: Name length has to be exactly 9
	                                               RRSET_ENCODING_VERSION,
	                                               &rrset_tm);
	if (knot_zone_rrset_t == NULL) {
		LOAD_ERROR(ctx, "failed to load");
	}

	knot_diff_t = RedisModule_CreateDataType(ctx, "KnotDiffT", // Note: Name length has to be exactly 9
	                                         RRSET_ENCODING_VERSION,
	                                         &diff_tm);
	if (knot_diff_t == NULL) {
		LOAD_ERROR(ctx, "failed to load");
	}

	if (RedisModule_CreateCommand(ctx, "KNOT.ZONE.BEGIN",        zone_begin_txt,    "write",    1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, "KNOT.ZONE.STORE",        zone_store_txt,    "write",    1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, "KNOT.ZONE.COMMIT",       zone_commit_txt,   "write",    1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, "KNOT.ZONE.ABORT",        zone_abort_txt,    "write",    1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, "KNOT.ZONE.LOAD",         zone_load_txt,     "readonly", 1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, "KNOT.ZONE.PURGE",        zone_purge_txt,    "write",    1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, "KNOT.UPD.BEGIN",         upd_begin_txt,     "write",    1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, "KNOT.UPD.ADD",           upd_add_txt,       "write",    1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, "KNOT.UPD.REMOVE",        upd_remove_txt,    "write",    1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, "KNOT.UPD.COMMIT",        upd_commit_txt,    "write",    1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, "KNOT.UPD.ABORT",         upd_abort_txt,     "write",    1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, "KNOT.UPD.DIFF",          upd_diff_txt,      "readonly", 1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, "KNOT.UPD.LOAD",          upd_load_txt,      "readonly", 1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, RDB_CMD_ZONE_EXISTS,      zone_exists_bin,   "readonly", 1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, RDB_CMD_ZONE_BEGIN,       zone_begin_bin,    "write",    1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, RDB_CMD_ZONE_STORE,       zone_store_bin,    "write",    1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, RDB_CMD_ZONE_COMMIT,      zone_commit_bin,   "write",    1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, RDB_CMD_ZONE_ABORT,       zone_abort_bin,    "write",    1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, RDB_CMD_ZONE_LOAD,        zone_load_bin,     "readonly", 1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, RDB_CMD_ZONE_PURGE,       zone_purge_bin,    "write",    1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, RDB_CMD_UPD_BEGIN,        upd_begin_bin,     "write",    1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, RDB_CMD_UPD_ADD,          upd_add_bin,       "write",    1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, RDB_CMD_UPD_REMOVE,       upd_remove_bin,    "write",    1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, RDB_CMD_UPD_COMMIT,       upd_commit_bin,    "write",    1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, RDB_CMD_UPD_ABORT,        upd_abort_bin,     "write",    1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, RDB_CMD_UPD_DIFF,         upd_diff_bin,      "readonly", 1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, RDB_CMD_UPD_LOAD,         upd_load_bin,      "readonly", 1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, "KNOT_BIN.AOF.RRSET",     rrset_aof_rewrite, "write",    1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, "KNOT_BIN.AOF.DIFF",      diff_aof_rewrite,  "write",    1, 1, 1) == REDISMODULE_ERR)
	{
		LOAD_ERROR(ctx, "failed to load");
	}

	RedisModule_Log(ctx, REDISMODULE_LOGLEVEL_NOTICE, "loaded with %s=%u %s=%u",
	                RDB_PARAM_DFLT_TTL, rdb_default_ttl, RDB_PARAM_EVENT_AGE, rdb_event_age);

	return REDISMODULE_OK;
}
