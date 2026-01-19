/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: LGPL-2.1-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#define SCORE_SOA		0.
#define SCORE_DEFAULT		1.

#define TXN_ID_ACTIVE		UINT8_MAX
#define ZONE_META_INACTIVE	UINT8_MAX
#define TTL_EMPTY		UINT32_MAX
#define TTL_EMPTY_STR		"NONE"

#define foreach_in_zset_subset(key, min, max) \
	for (RedisModule_ZsetFirstInScoreRange(key, min, max, 0, 0); \
	     RedisModule_ZsetRangeEndReached(key) == 0; \
	     RedisModule_ZsetRangeNext(key))
#define foreach_in_zset(key) foreach_in_zset_subset(key, REDISMODULE_NEGATIVE_INFINITE, REDISMODULE_POSITIVE_INFINITE)

#define zone_meta_keyname_construct(...) meta_keyname_construct(ZONE_META, __VA_ARGS__)
#define upd_meta_keyname_construct(...)  meta_keyname_construct(UPD_META, __VA_ARGS__)

#define delete_zone_index(...)  delete_index(ZONE, __VA_ARGS__)
#define delete_upd_index(...)  delete_index(UPD_TMP, __VA_ARGS__)

#define throw(_ret, _msg) return (exception_t){ .ret = _ret, .what = _msg }
#define raise(e)          return e
#define return_ok         throw(KNOT_EOK, NULL)

typedef enum {
	EVENT     = 1, // Keep synchronized with RDB_EVENT_KEY!
	ZONES     = 2,
	ZONE_META = 3,
	ZONE      = 4,
	RRSET     = 5,
	UPD_META  = 6,
	UPD_TMP   = 7,
	UPD       = 8,
	DIFF      = 9,
} rdb_type_t;

typedef struct {
	const char *what;
	int ret;
} exception_t;

typedef struct {
	uint8_t active;
	uint8_t lock[TXN_MAX_COUNT];
} zone_meta_storage_t;

typedef struct {
	uint16_t counter;
	uint16_t lock[TXN_MAX_COUNT];
	uint16_t depth;
} upd_meta_storage_t;

typedef struct {
	RedisModuleCtx *ctx;
	const rdb_txn_t *txn;
	uint32_t dflt_ttl;
	enum {
		STORE,
		ADD,
		REM,
	} mode;
	bool replied;
} scanner_ctx_t;

typedef int (*upd_callback)(diff_v *diff, const void *data, uint32_t ttl);

typedef RedisModuleKey *rrset_k;
typedef RedisModuleKey *diff_k;
typedef RedisModuleKey *upd_meta_k;
typedef RedisModuleKey *zone_meta_k;
typedef RedisModuleKey *index_k;

static void *redismodule_alloc(void *ptr, size_t bytes)
{
	return RedisModule_Alloc(bytes);
}

static void redismodule_free(void *ptr)
{
	RedisModule_Free(ptr);
}

static knot_mm_t mm = {
	.alloc = redismodule_alloc,
	.ctx = NULL,
	.free = redismodule_free
};

static double evaluate_score(uint16_t rtype)
{
	return (rtype == KNOT_RRTYPE_SOA) ? SCORE_SOA : SCORE_DEFAULT;
}

static RedisModuleString *meta_keyname_construct(const uint8_t prefix, RedisModuleCtx *ctx,
                                                 const arg_dname_t *origin, uint8_t instance)
{
	char buf[RDB_PREFIX_LEN + 1 + 1 + KNOT_DNAME_MAXLEN + 1];

	wire_ctx_t w = wire_ctx_init((uint8_t *)buf, sizeof(buf));
	wire_ctx_write(&w, RDB_PREFIX, RDB_PREFIX_LEN);
	wire_ctx_write_u8(&w, prefix);
	wire_ctx_write_u8(&w, origin->len);
	wire_ctx_write(&w, origin->data, origin->len);
	wire_ctx_write_u8(&w, instance);
	RedisModule_Assert(w.error == KNOT_EOK);

	return RedisModule_CreateString(ctx, buf, wire_ctx_offset(&w));
}

static RedisModuleString *rrset_keyname_construct(RedisModuleCtx *ctx, const arg_dname_t *origin,
                                                  const rdb_txn_t *txn, const arg_dname_t *owner,
                                                  uint16_t rtype)
{
	static const uint8_t prefix = RRSET;

	char buf[RDB_PREFIX_LEN + 1 + 1 + KNOT_DNAME_MAXLEN + 1 + KNOT_DNAME_MAXLEN + 2 + 2];

	wire_ctx_t w = wire_ctx_init((uint8_t *)buf, sizeof(buf));
	wire_ctx_write(&w, RDB_PREFIX, RDB_PREFIX_LEN);
	wire_ctx_write_u8(&w, prefix);
	wire_ctx_write_u8(&w, origin->len);
	wire_ctx_write(&w, origin->data, origin->len);
	wire_ctx_write_u8(&w, owner->len);
	wire_ctx_write(&w, owner->data, owner->len);
	wire_ctx_write_u16(&w, rtype);
	wire_ctx_write(&w, txn, sizeof(*txn));
	RedisModule_Assert(w.error == KNOT_EOK);

	return RedisModule_CreateString(ctx, buf, wire_ctx_offset(&w));
}

static RedisModuleString *diff_keyname_construct(RedisModuleCtx *ctx, const arg_dname_t *origin,
                                                 const rdb_txn_t *txn, const arg_dname_t *owner,
                                                 uint16_t rtype, uint16_t id)
{
	static const uint8_t prefix = DIFF;

	char buf[RDB_PREFIX_LEN + 1 + 1 + KNOT_DNAME_MAXLEN + 1 + KNOT_DNAME_MAXLEN + 2 + 2 + 2];

	wire_ctx_t w = wire_ctx_init((uint8_t *)buf, sizeof(buf));
	wire_ctx_write(&w, RDB_PREFIX, RDB_PREFIX_LEN);
	wire_ctx_write_u8(&w, prefix);
	wire_ctx_write_u8(&w, origin->len);
	wire_ctx_write(&w, origin->data, origin->len);
	wire_ctx_write_u8(&w, owner->len);
	wire_ctx_write(&w, owner->data, owner->len);
	wire_ctx_write_u16(&w, rtype);
	wire_ctx_write(&w, txn, sizeof(*txn));
	wire_ctx_write_u16(&w, id);
	RedisModule_Assert(w.error == KNOT_EOK);

	return RedisModule_CreateString(ctx, buf, wire_ctx_offset(&w));
}

static zone_meta_k zone_meta_get_when_open(RedisModuleCtx *ctx, const arg_dname_t *origin,
                                           const rdb_txn_t *txn, int rights)
{
	RedisModuleString *txn_k = zone_meta_keyname_construct(ctx, origin, txn->instance);
	zone_meta_k key = RedisModule_OpenKey(ctx, txn_k, rights);
	RedisModule_FreeString(ctx, txn_k);
	if (key == NULL || RedisModule_KeyType(key) != REDISMODULE_KEYTYPE_STRING) {
		RedisModule_CloseKey(key);
		return NULL;
	}

	size_t len = 0;
	const zone_meta_storage_t *meta = (const zone_meta_storage_t *)RedisModule_StringDMA(key, &len, REDISMODULE_READ);
	if (txn->id != meta->active && meta->lock[txn->id] != 0) {
		return key;
	}
	RedisModule_CloseKey(key);
	return NULL;
}

static bool zone_txn_is_open(RedisModuleCtx *ctx, const arg_dname_t *origin, const rdb_txn_t *txn)
{
	zone_meta_k key = zone_meta_get_when_open(ctx, origin, txn, REDISMODULE_READ);
	bool out = (key != NULL);
	RedisModule_CloseKey(key);
	return out;
}

static void commit_event(RedisModuleCtx *ctx, rdb_event_t type, const arg_dname_t *origin,
                         uint8_t instance, uint32_t serial, RedisModuleStreamID *stream_id)
{
	RedisModuleString *keyname = RedisModule_CreateString(ctx, RDB_EVENT_KEY, strlen(RDB_EVENT_KEY));
	RedisModuleKey *stream_key = RedisModule_OpenKey(ctx, keyname, REDISMODULE_READ | REDISMODULE_WRITE);
	RedisModule_FreeString(ctx, keyname);

	int zone_stream_type = RedisModule_KeyType(stream_key);
	if (zone_stream_type != REDISMODULE_KEYTYPE_EMPTY && zone_stream_type != REDISMODULE_KEYTYPE_STREAM) {
		RedisModule_Log(ctx, REDISMODULE_LOGLEVEL_WARNING, RDB_EEVENT);
		RedisModule_CloseKey(stream_key);
		return;
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

	int flags = 0;
	if (stream_id->ms == 0) {
		flags = REDISMODULE_STREAM_ADD_AUTOID;
	}
	int ret = RedisModule_StreamAdd(stream_key, flags, stream_id, events, 4);

	for (RedisModuleString **event = events; *event != NULL; event++) {
		RedisModule_FreeString(ctx, *event);
	}

	if (ret != REDISMODULE_OK) {
		RedisModule_Log(ctx, REDISMODULE_LOGLEVEL_WARNING, RDB_EEVENT);
		RedisModule_CloseKey(stream_key);
		return;
	}

	if (rdb_event_age == 0) {
		RedisModule_CloseKey(stream_key);
		return;
	}

	RedisModuleStreamID trim_id = {
		.ms = stream_id->ms - 1000LLU * rdb_event_age
	};

	// NOTE Trimming with REDISMODULE_STREAM_TRIM_APPROX improves preformance
	long long removed_cnt = RedisModule_StreamTrimByID(stream_key, REDISMODULE_STREAM_TRIM_APPROX, &trim_id);
	if (removed_cnt) {
		RedisModule_Log(ctx, REDISMODULE_LOGLEVEL_NOTICE, "stream cleanup %lld old events", removed_cnt);
	}
	RedisModule_CloseKey(stream_key);
}

static RedisModuleKey *get_zones_index(RedisModuleCtx *ctx, int rights)
{
	static const uint8_t prefix = ZONES;

	char buf[RDB_PREFIX_LEN + 1 + 1];

	wire_ctx_t w = wire_ctx_init((uint8_t *)buf, sizeof(buf));
	wire_ctx_write(&w, RDB_PREFIX, RDB_PREFIX_LEN);
	wire_ctx_write_u8(&w, prefix);
	RedisModule_Assert(w.error == KNOT_EOK);

	RedisModuleString *keyname = RedisModule_CreateString(ctx, buf, wire_ctx_offset(&w));
	RedisModuleKey *key = RedisModule_OpenKey(ctx, keyname, rights);
	RedisModule_FreeString(ctx, keyname);

	return key;
}

static index_k get_zone_index(RedisModuleCtx *ctx, const arg_dname_t *origin,
                              const rdb_txn_t *txn, int rights)
{
	static const uint8_t prefix = ZONE;

	char buf[RDB_PREFIX_LEN + 1 + 1 + KNOT_DNAME_MAXLEN + 2];

	wire_ctx_t w = wire_ctx_init((uint8_t *)buf, sizeof(buf));
	wire_ctx_write(&w, RDB_PREFIX, RDB_PREFIX_LEN);
	wire_ctx_write_u8(&w, prefix);
	wire_ctx_write_u8(&w, origin->len);
	wire_ctx_write(&w, origin->data, origin->len);
	wire_ctx_write(&w, txn, sizeof(*txn));
	RedisModule_Assert(w.error == KNOT_EOK);

	RedisModuleString *keyname = RedisModule_CreateString(ctx, buf, wire_ctx_offset(&w));
	index_k key = RedisModule_OpenKey(ctx, keyname, rights);
	RedisModule_FreeString(ctx, keyname);

	return key;
}

static index_k get_upd_index(RedisModuleCtx *ctx, const arg_dname_t *origin,
                             const rdb_txn_t *txn, uint16_t id, int rights)
{
	static const uint8_t prefix = UPD_TMP;

	char buf[RDB_PREFIX_LEN + 1 + 1 + KNOT_DNAME_MAXLEN + 2 + 2];

	wire_ctx_t w = wire_ctx_init((uint8_t *)buf, sizeof(buf));
	wire_ctx_write(&w, RDB_PREFIX, RDB_PREFIX_LEN);
	wire_ctx_write_u8(&w, prefix);
	wire_ctx_write_u8(&w, origin->len);
	wire_ctx_write(&w, origin->data, origin->len);
	wire_ctx_write(&w, txn, sizeof(*txn));
	wire_ctx_write_u16(&w, id);
	RedisModule_Assert(w.error == KNOT_EOK);

	RedisModuleString *keyname = RedisModule_CreateString(ctx, buf, wire_ctx_offset(&w));
	index_k key = RedisModule_OpenKey(ctx, keyname, rights);
	RedisModule_FreeString(ctx, keyname);

	return key;
}

static index_k get_commited_upd_index(RedisModuleCtx *ctx, const arg_dname_t *origin,
                                      const rdb_txn_t *txn, const uint32_t serial, int rights)
{
	static const uint8_t prefix = UPD;

	char buf[RDB_PREFIX_LEN + 1 + 1 + KNOT_DNAME_MAXLEN + 1 + 4];

	wire_ctx_t w = wire_ctx_init((uint8_t *)buf, sizeof(buf));
	wire_ctx_write(&w, RDB_PREFIX, RDB_PREFIX_LEN);
	wire_ctx_write_u8(&w, prefix);
	wire_ctx_write_u8(&w, origin->len);
	wire_ctx_write(&w, origin->data, origin->len);
	wire_ctx_write_u8(&w, txn->instance);
	wire_ctx_write_u32(&w, serial);
	RedisModule_Assert(w.error == KNOT_EOK);

	RedisModuleString *keyname = RedisModule_CreateString(ctx, buf, wire_ctx_offset(&w));
	index_k key = RedisModule_OpenKey(ctx, keyname, rights);
	RedisModule_FreeString(ctx, keyname);

	return key;
}

static int rrset_key_set(RedisModuleCtx *ctx, rrset_k key, RedisModuleString *keyname,
                         const arg_dname_t *origin, const rdb_txn_t *txn, uint16_t rtype, rrset_v *val)
{
	RedisModule_Assert(RedisModule_ModuleTypeSetValue(key, rdb_rrset_t, val) == REDISMODULE_OK);

	index_k zone_index_key = get_zone_index(ctx, origin, txn, REDISMODULE_READ | REDISMODULE_WRITE);
	int zone_keytype = RedisModule_KeyType(zone_index_key);
	if (zone_keytype != REDISMODULE_KEYTYPE_EMPTY &&
	    zone_keytype != REDISMODULE_KEYTYPE_ZSET) {
		RedisModule_CloseKey(zone_index_key);
		return KNOT_EMALF;
	}
	int ret = RedisModule_ZsetAdd(zone_index_key, evaluate_score(rtype), keyname, NULL);
	if (ret != REDISMODULE_OK) {
		RedisModule_CloseKey(zone_index_key);
		return KNOT_ENOMEM;
	}
	RedisModule_CloseKey(zone_index_key);

	return KNOT_EOK;
}

static exception_t rdata_add(RedisModuleCtx *ctx, const arg_dname_t *origin,
                             const rdb_txn_t *txn, const arg_dname_t *owner,
                             uint32_t ttl, uint16_t rtype, const knot_rdata_t *rdata)
{
	RedisModuleString *rrset_keystr = rrset_keyname_construct(ctx, origin, txn, owner, rtype);
	rrset_k rrset_key = RedisModule_OpenKey(ctx, rrset_keystr, REDISMODULE_READ | REDISMODULE_WRITE);
	rrset_v *rrset = RedisModule_ModuleTypeGetValue(rrset_key);
	if (rrset == NULL) {
		rrset = RedisModule_Calloc(1, sizeof(*rrset));
		if (rrset == NULL) {
			RedisModule_CloseKey(rrset_key);
			RedisModule_FreeString(ctx, rrset_keystr);
			throw(KNOT_ENOMEM, RDB_EALLOC);
		}
		int ret = rrset_key_set(ctx, rrset_key, rrset_keystr, origin, txn, rtype, rrset);
		if (ret != KNOT_EOK) {
			RedisModule_CloseKey(rrset_key);
			RedisModule_FreeString(ctx, rrset_keystr);
			throw(ret, RDB_ESTORE);
		}
		rrset->ttl = (ttl == TTL_EMPTY) ? rdb_default_ttl : ttl;
	} else {
		RedisModule_Assert(RedisModule_ModuleTypeGetType(rrset_key) == rdb_rrset_t);
		if (ttl != TTL_EMPTY) {
			rrset->ttl = ttl;
		}
	}
	RedisModule_FreeString(ctx, rrset_keystr);

	int ret = knot_rdataset_add(&rrset->rrs, rdata, &mm);
	RedisModule_CloseKey(rrset_key);
	if (ret != KNOT_EOK) {
		throw(ret, RDB_ESTORE);
	}
	return_ok;
}

static int rdata_add_format(RedisModuleCtx *ctx, const arg_dname_t *origin,
                            const rdb_txn_t *txn, const arg_dname_t *owner,
                            uint32_t ttl, uint16_t rtype, const knot_rdata_t *rdata)
{
	exception_t e = rdata_add(ctx, origin, txn, owner, ttl, rtype, rdata);
	if (e.ret != KNOT_EOK) {
		RedisModule_ReplyWithError(ctx, e.what);
	}
	return e.ret;
}

static exception_t rdata_remove(RedisModuleCtx *ctx, const arg_dname_t *origin,
                                const rdb_txn_t *txn, const arg_dname_t *owner,
                                uint32_t *ttl, uint16_t rtype, const knot_rdata_t *rdata)
{
	// Existence of the rrset is ensured by the previous check.
	RedisModuleString *rrset_keystr = rrset_keyname_construct(ctx, origin, txn, owner, rtype);
	rrset_k rrset_key = RedisModule_OpenKey(ctx, rrset_keystr, REDISMODULE_READ | REDISMODULE_WRITE);
	RedisModule_Assert(RedisModule_ModuleTypeGetType(rrset_key) == rdb_rrset_t);
	rrset_v *rrset = RedisModule_ModuleTypeGetValue(rrset_key);
	RedisModule_Assert(rrset != NULL);

	if (*ttl == TTL_EMPTY) {
		*ttl = rrset->ttl;
	}

	int ret = knot_rdataset_remove(&rrset->rrs, rdata, &mm);
	if (ret != KNOT_EOK) {
		RedisModule_FreeString(ctx, rrset_keystr);
		RedisModule_CloseKey(rrset_key);
		throw(ret, RDB_ESTORE);
	}

	if (rrset->rrs.count == 0 && rtype != KNOT_RRTYPE_SOA) {
		RedisModule_DeleteKey(rrset_key);

		index_k zone_index = get_zone_index(ctx, origin, txn, REDISMODULE_READ | REDISMODULE_WRITE);
		RedisModule_Assert(RedisModule_KeyType(zone_index) == REDISMODULE_KEYTYPE_ZSET);
		RedisModule_ZsetRem(zone_index, rrset_keystr, NULL);
		RedisModule_CloseKey(zone_index);
	}

	RedisModule_FreeString(ctx, rrset_keystr);
	RedisModule_CloseKey(rrset_key);
	return_ok;
}

static void zone_meta_storage_init(zone_meta_storage_t *meta)
{
	meta->active = ZONE_META_INACTIVE;
	memset(meta->lock, 0, sizeof(meta->lock));
}

static zone_meta_k zone_meta_key_get(RedisModuleCtx *ctx, const arg_dname_t *origin,
                                     rdb_txn_t *txn, int rights)
{
	RedisModule_Assert(txn->instance > 0);

	RedisModuleString *txn_k = zone_meta_keyname_construct(ctx, origin, txn->instance);
	zone_meta_k key = RedisModule_OpenKey(ctx, txn_k, rights);
	RedisModule_FreeString(ctx, txn_k);

	int keytype = RedisModule_KeyType(key);
	if (keytype == REDISMODULE_KEYTYPE_EMPTY) {
		zone_meta_storage_t meta;
		zone_meta_storage_init(&meta);
		RedisModuleString *meta_str = RedisModule_CreateString(ctx, (const char *)&meta, sizeof(meta));
		RedisModule_StringSet(key, meta_str);
		RedisModule_FreeString(ctx, meta_str);
	} else if (keytype != REDISMODULE_KEYTYPE_STRING) {
		RedisModule_CloseKey(key);
		return NULL;
	}

	return key;
}

static upd_meta_k upd_meta_key_get(RedisModuleCtx *ctx, const arg_dname_t *origin,
                                   rdb_txn_t *txn, int rights)
{
	RedisModule_Assert(txn->instance > 0);

	RedisModuleString *txn_k = upd_meta_keyname_construct(ctx, origin, txn->instance);
	upd_meta_k key = RedisModule_OpenKey(ctx, txn_k, rights);
	RedisModule_FreeString(ctx, txn_k);

	int keytype = RedisModule_KeyType(key);
	if (keytype == REDISMODULE_KEYTYPE_EMPTY) {
		upd_meta_storage_t meta = { 0 };
		RedisModuleString *meta_str = RedisModule_CreateString(ctx, (const char *)&meta, sizeof(meta));
		RedisModule_StringSet(key, meta_str);
		RedisModule_FreeString(ctx, meta_str);
	} else if (keytype != REDISMODULE_KEYTYPE_STRING) {
		RedisModule_CloseKey(key);
		RedisModule_ReplyWithError(ctx, RDB_EMALF);
		return NULL;
	}

	return key;
}

static int zone_txn_lock(zone_meta_k key, rdb_txn_t *txn)
{
	RedisModule_Assert(txn->instance > 0);

	size_t len = 0;
	zone_meta_storage_t *meta = (zone_meta_storage_t *)RedisModule_StringDMA(key, &len, REDISMODULE_WRITE);
	if (meta == NULL || len != sizeof(zone_meta_storage_t)) {
		return KNOT_EINVAL;
	}

	for (txn->id = TXN_MIN; txn->id <= TXN_MAX; ++txn->id) {
		if (meta->lock[txn->id] == 0) {
			meta->lock[txn->id] = 1;
			break;
		}
	}
	if (txn->id > TXN_MAX) {
		return KNOT_EBUSY;
	}

	return KNOT_EOK;
}

static exception_t upd_txn_lock(upd_meta_k key, rdb_txn_t *txn)
{
	RedisModule_Assert(txn->instance > 0);

	size_t len;
	upd_meta_storage_t *meta = (upd_meta_storage_t *)RedisModule_StringDMA(key, &len, REDISMODULE_WRITE);
	if (meta == NULL || len != sizeof(upd_meta_storage_t)) {
		throw(KNOT_EINVAL, RDB_EMALF);
	}

	uint16_t counter = knot_wire_read_u16((uint8_t *)meta + offsetof(upd_meta_storage_t, counter));
	for (txn->id = TXN_MIN; txn->id <= TXN_MAX; ++txn->id) {
		uint16_t lock = knot_wire_read_u16((uint8_t *)meta + offsetof(upd_meta_storage_t, lock[txn->id]));
		if (lock == 0) {
			counter = MAX((uint16_t)(counter + 1), (uint16_t)1);
			knot_wire_write_u16((uint8_t *)meta + offsetof(upd_meta_storage_t, counter), counter);
			knot_wire_write_u16((uint8_t *)meta + offsetof(upd_meta_storage_t, lock[txn->id]), counter);
			break;
		}
	}
	if (txn->id > TXN_MAX) {
		throw(KNOT_EBUSY, RDB_ETXN_MANY);
	}

	return_ok;
}

static int serialize_transaction(const rdb_txn_t *txn)
{
	return 10 * txn->instance + txn->id;
}

static int set_active_transaction(RedisModuleCtx *ctx, const arg_dname_t *origin, rdb_txn_t *txn)
{
	RedisModule_Assert(txn->instance > 0);

	RedisModuleString *txn_k = zone_meta_keyname_construct(ctx, origin, txn->instance);
	zone_meta_k key = RedisModule_OpenKey(ctx, txn_k, REDISMODULE_READ);
	RedisModule_FreeString(ctx, txn_k);
	if (key == NULL) {
		return KNOT_EEXIST;
	} else if (RedisModule_KeyType(key) != REDISMODULE_KEYTYPE_STRING) {
		RedisModule_CloseKey(key);
		return KNOT_EMALF;
	}
	size_t len = 0;
	const zone_meta_storage_t *meta = (const zone_meta_storage_t *)RedisModule_StringDMA(key, &len, REDISMODULE_READ);
	if (meta->active != ZONE_META_INACTIVE) {
		txn->id = meta->active;
		RedisModule_CloseKey(key);
		return KNOT_EOK;
	}
	RedisModule_CloseKey(key);
	return KNOT_EEXIST;
}

static int get_id(RedisModuleCtx *ctx, const arg_dname_t *origin, const rdb_txn_t *txn)
{
	RedisModuleString *txn_k = upd_meta_keyname_construct(ctx, origin, txn->instance);
	upd_meta_k meta_key = RedisModule_OpenKey(ctx, txn_k, REDISMODULE_READ);
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

	uint16_t id = knot_wire_read_u16((uint8_t *)meta + offsetof(upd_meta_storage_t, lock[txn->id]));
	if (id == 0) {
		RedisModule_CloseKey(meta_key);
		return KNOT_EEXIST;
	}

	RedisModule_CloseKey(meta_key);
	return id;
}

static int delete_index(const uint8_t prefix, RedisModuleCtx *ctx, const arg_dname_t *origin,
                        const rdb_txn_t *txn)
{
	index_k index_key = NULL;
	switch (prefix) {
	case ZONE:
		index_key = get_zone_index(ctx, origin, txn, REDISMODULE_READ | REDISMODULE_WRITE);
		break;
	case UPD_TMP:;
		int ret = get_id(ctx, origin, txn);
		if (ret < 0 || ret > UINT16_MAX) {
			return KNOT_EEXIST;
		}
		uint16_t id = ret;
		index_key = get_upd_index(ctx, origin, txn, id, REDISMODULE_READ | REDISMODULE_WRITE);
		break;
	default:
		return KNOT_ENOTSUP;
	}

	if (RedisModule_KeyType(index_key) == REDISMODULE_KEYTYPE_EMPTY) {
		RedisModule_CloseKey(index_key);
		return KNOT_EOK;
	} else if (RedisModule_KeyType(index_key) != REDISMODULE_KEYTYPE_ZSET) {
		RedisModule_CloseKey(index_key);
		return KNOT_EINVAL;
	}
	foreach_in_zset(index_key) {
		RedisModuleString *el = RedisModule_ZsetRangeCurrentElement(index_key, NULL);
		RedisModuleKey *el_key = RedisModule_OpenKey(ctx, el, REDISMODULE_READ | REDISMODULE_WRITE);
		if (el_key != NULL) {
			RedisModule_DeleteKey(el_key);
			RedisModule_CloseKey(el_key);
		}
		RedisModule_FreeString(ctx, el);
	}

	RedisModule_DeleteKey(index_key);
	RedisModule_CloseKey(index_key);

	return KNOT_EOK;
}

static exception_t zone_begin(RedisModuleCtx *ctx, const arg_dname_t *origin, rdb_txn_t *txn)
{
	zone_meta_k key = zone_meta_key_get(ctx, origin, txn, REDISMODULE_WRITE);
	if (key == NULL) {
		throw(KNOT_EMALF, RDB_ECORRUPTED);
	}

	int ret = zone_txn_lock(key, txn);
	RedisModule_CloseKey(key);
	if (ret == KNOT_EBUSY) {
		throw(KNOT_EBUSY, RDB_ETXN_MANY);
	} else if (ret != KNOT_EOK) {
		throw(ret, RDB_ECORRUPTED);
	}

	ret = delete_upd_index(ctx, origin, txn);
	if (ret != KNOT_EOK && ret != KNOT_EEXIST) {
		throw(ret, RDB_ECORRUPTED);
	}

	return_ok;
}

static void zone_begin_txt_format(RedisModuleCtx *ctx, const arg_dname_t *origin, rdb_txn_t *txn)
{
	exception_t e = zone_begin(ctx, origin, txn);
	if (e.ret != KNOT_EOK) {
		RedisModule_ReplyWithError(ctx, e.what);
	} else {
		RedisModule_ReplicateVerbatim(ctx);
		RedisModule_ReplyWithLongLong(ctx, serialize_transaction(txn));
	}
}

static void zone_begin_bin_format(RedisModuleCtx *ctx, const arg_dname_t *origin, rdb_txn_t *txn)
{
	exception_t e = zone_begin(ctx, origin, txn);
	if (e.ret != KNOT_EOK) {
		RedisModule_ReplyWithError(ctx, e.what);
	} else {
		RedisModule_ReplicateVerbatim(ctx);
		RedisModule_ReplyWithStringBuffer(ctx, (const char *)txn, sizeof(*txn));
	}
}

static exception_t upd_begin(RedisModuleCtx *ctx, const arg_dname_t *origin, rdb_txn_t *txn)
{
	rdb_txn_t zone_txn = {
		.instance = txn->instance,
		.id = TXN_ID_ACTIVE
	};
	if (set_active_transaction(ctx, origin, &zone_txn) == KNOT_EEXIST) {
		throw(KNOT_EINVAL, RDB_EZONE);
	}

	upd_meta_k key = upd_meta_key_get(ctx, origin, txn, REDISMODULE_WRITE);
	if (key == NULL) {
		throw(KNOT_EMALF, RDB_ECORRUPTED);
	}

	exception_t e = upd_txn_lock(key, txn);
	RedisModule_CloseKey(key);
	if (e.ret != KNOT_EOK) {
		raise(e);
	}

	int ret = delete_upd_index(ctx, origin, txn);
	if (ret != KNOT_EOK && ret != KNOT_EEXIST) {
		throw(ret, RDB_ECORRUPTED);
	}

	return_ok;
}

static void upd_begin_txt_format(RedisModuleCtx *ctx, const arg_dname_t *origin, rdb_txn_t *txn)
{
	exception_t e = upd_begin(ctx, origin, txn);
	if (e.ret != KNOT_EOK) {
		RedisModule_ReplyWithError(ctx, e.what);
	} else {
		RedisModule_ReplicateVerbatim(ctx);
		RedisModule_ReplyWithLongLong(ctx, serialize_transaction(txn));
	}
}

static void upd_begin_bin_format(RedisModuleCtx *ctx, const arg_dname_t *origin, rdb_txn_t *txn)
{
	exception_t e = upd_begin(ctx, origin, txn);
	if (e.ret != KNOT_EOK) {
		RedisModule_ReplyWithError(ctx, e.what);
	} else {
		RedisModule_ReplicateVerbatim(ctx);
		RedisModule_ReplyWithStringBuffer(ctx, (const char *)txn, sizeof(*txn));
	}
}

static upd_meta_k upd_meta_get_when_open(RedisModuleCtx *ctx, const arg_dname_t *origin,
                                         const rdb_txn_t *txn, int rights)
{
	RedisModuleString *txn_k = upd_meta_keyname_construct(ctx, origin, txn->instance);
	upd_meta_k key = RedisModule_OpenKey(ctx, txn_k, rights);
	RedisModule_FreeString(ctx, txn_k);
	if (key == NULL) {
		return NULL;
	} else if (RedisModule_KeyType(key) != REDISMODULE_KEYTYPE_STRING) {
		RedisModule_CloseKey(key);
		return NULL;
	}
	size_t len = 0;
	const upd_meta_storage_t *transaction = (const upd_meta_storage_t *)RedisModule_StringDMA(key, &len, REDISMODULE_WRITE);
	uint16_t lock = knot_wire_read_u16((uint8_t *)transaction + offsetof(upd_meta_storage_t, lock[txn->id]));
	if (lock == 0) {
		RedisModule_CloseKey(key);
		return NULL;
	}
	return key;
}

static int upd_add_txt_cb(diff_v *diff, const void *data, uint32_t ttl)
{
	const knot_rdata_t *rdata = data;

	if (knot_rdataset_member(&diff->rem_rrs, rdata)) {
		return knot_rdataset_remove(&diff->rem_rrs, rdata, &mm);
	} else {
		diff->add_ttl = (ttl == TTL_EMPTY) ? rdb_default_ttl : ttl;
		return knot_rdataset_add(&diff->add_rrs, rdata, &mm);
	}
}

static int upd_remove_txt_cb(diff_v *diff, const void *data, uint32_t ttl)
{
	const knot_rdata_t *rdata = data;

	if (knot_rdataset_member(&diff->add_rrs, rdata)) {
		return knot_rdataset_remove(&diff->add_rrs, rdata, &mm);
	} else {
		diff->rem_ttl = ttl;
		return knot_rdataset_add(&diff->rem_rrs, rdata, &mm);
	}
}

static int upd_add_bin_cb(diff_v *diff, const void *data, uint32_t ttl)
{
	const knot_rdataset_t *rdataset = data;

	if (diff->add_rrs.count > 0) {
		return KNOT_EEXIST;
	}
	int ret = knot_rdataset_copy(&diff->add_rrs, rdataset, &mm);
	diff->add_ttl = ttl;

	return ret;
}

static int upd_merge_bin_cb(diff_v *diff, const void *data, uint32_t ttl)
{
	const knot_rdataset_t *rdataset = data;

	int ret = KNOT_EOK;

	knot_rdata_t *rr = rdataset->rdata;
	for (uint16_t i = 0; i < rdataset->count && ret == KNOT_EOK; i++) {
		if (knot_rdataset_member(&diff->rem_rrs, rr)) {
			ret = knot_rdataset_remove(&diff->rem_rrs, rr, &mm);
		} else {
			ret = knot_rdataset_add(&diff->add_rrs, rr, &mm);
			diff->add_ttl = ttl;
		}

		rr = knot_rdataset_next(rr);
	}

	return ret;
}

static int upd_remove_bin_cb(diff_v *diff, const void *data, uint32_t ttl)
{
	const knot_rdataset_t *rdataset = data;

	if (diff->rem_rrs.count > 0) {
		return KNOT_EEXIST;
	}
	int ret = knot_rdataset_copy(&diff->rem_rrs, rdataset, &mm);
	diff->rem_ttl = ttl;

	return ret;
}

static exception_t upd_add_rem(RedisModuleCtx *ctx, const arg_dname_t *origin,
                               const rdb_txn_t *txn, const arg_dname_t *owner,
                               const uint32_t ttl, const uint16_t rtype,
                               void *data, upd_callback cb)
{
	int ret = get_id(ctx, origin, txn);
	if (ret < 0 || ret > UINT16_MAX) {
		throw(ret, RDB_ETXN);
	}
	uint16_t id = ret;

	RedisModuleString *diff_keystr = diff_keyname_construct(ctx, origin, txn, owner, rtype, id);
	diff_k diff_key = RedisModule_OpenKey(ctx, diff_keystr, REDISMODULE_READ | REDISMODULE_WRITE);
	diff_v *diff = RedisModule_ModuleTypeGetValue(diff_key);
	if (diff == NULL) {
		diff = RedisModule_Calloc(1, sizeof(diff_v));
		if (diff == NULL) {
			RedisModule_CloseKey(diff_key);
			RedisModule_FreeString(ctx, diff_keystr);
			throw(KNOT_ENOMEM, RDB_EALLOC);
		}
		RedisModule_Assert(RedisModule_ModuleTypeSetValue(diff_key, rdb_diff_t, diff) == REDISMODULE_OK);

		index_k diff_index_key = get_upd_index(ctx, origin, txn, id, REDISMODULE_READ | REDISMODULE_WRITE);
		int diff_keytype = RedisModule_KeyType(diff_index_key);
		if (diff_keytype != REDISMODULE_KEYTYPE_EMPTY &&
		    diff_keytype != REDISMODULE_KEYTYPE_ZSET) {
			RedisModule_FreeString(ctx, diff_keystr);
			RedisModule_CloseKey(diff_key);
			RedisModule_CloseKey(diff_index_key);
			throw(KNOT_EMALF, RDB_EMALF);
		}
		ret = RedisModule_ZsetAdd(diff_index_key, evaluate_score(rtype), diff_keystr, NULL);
		RedisModule_CloseKey(diff_index_key);
		if (ret != REDISMODULE_OK) {
			RedisModule_FreeString(ctx, diff_keystr);
			RedisModule_CloseKey(diff_key);
			throw(KNOT_ENOMEM, RDB_ESTORE);
		}
	} else {
		RedisModule_Assert(RedisModule_ModuleTypeGetType(diff_key) == rdb_diff_t);
	}
	RedisModule_FreeString(ctx, diff_keystr);

	ret = cb(diff, data, ttl);
	if (ret == KNOT_EEXIST) {
		RedisModule_CloseKey(diff_key);
		throw(KNOT_EEXIST, RDB_EEXIST);
	}

	RedisModule_CloseKey(diff_key);
	return_ok;
}

static int upd_add_txt_format(RedisModuleCtx *ctx, const arg_dname_t *origin,
                              const rdb_txn_t *txn, const arg_dname_t *owner,
                              const uint32_t ttl, const uint16_t rtype,
                              const knot_rdata_t *data)
{
	exception_t e = upd_add_rem(ctx, origin, txn, owner, ttl, rtype, (void *)data, upd_add_txt_cb);
	if (e.ret != KNOT_EOK) {
		RedisModule_ReplyWithError(ctx, e.what);
	}
	return e.ret;
}

static int upd_remove_txt_format(RedisModuleCtx *ctx, const arg_dname_t *origin,
                                 const rdb_txn_t *txn, const arg_dname_t *owner,
                                 const uint32_t ttl, const uint16_t rtype,
                                 const knot_rdata_t *data)
{
	exception_t e = upd_add_rem(ctx, origin, txn, owner, ttl, rtype, (void *)data, upd_remove_txt_cb);
	if (e.ret != KNOT_EOK) {
		RedisModule_ReplyWithError(ctx, e.what);
	}
	return e.ret;
}

static void upd_add_bin_format(RedisModuleCtx *ctx, const arg_dname_t *origin,
                               const rdb_txn_t *txn, const arg_dname_t *owner,
                               const uint32_t ttl, const uint16_t rtype,
                               const knot_rdataset_t *data, bool merge)
{
	exception_t e = upd_add_rem(ctx, origin, txn, owner, ttl, rtype, (void *)data,
	                            merge ? upd_merge_bin_cb : upd_add_bin_cb);
	if (e.ret != KNOT_EOK) {
		RedisModule_ReplyWithError(ctx, e.what);
	} else {
		RedisModule_ReplicateVerbatim(ctx);
		RedisModule_ReplyWithSimpleString(ctx, RDB_RETURN_OK);
	}
}

static void upd_remove_bin_format(RedisModuleCtx *ctx, const arg_dname_t *origin,
                                  const rdb_txn_t *txn, const arg_dname_t *owner,
                                  const uint32_t ttl, const uint16_t rtype,
                                  const knot_rdataset_t *data)
{
	exception_t e = upd_add_rem(ctx, origin, txn, owner, ttl, rtype, (void *)data, upd_remove_bin_cb);
	if (e.ret != KNOT_EOK) {
		RedisModule_ReplyWithError(ctx, e.what);
	} else {
		RedisModule_ReplicateVerbatim(ctx);
		RedisModule_ReplyWithSimpleString(ctx, RDB_RETURN_OK);
	}
}

static void scanner_data(zs_scanner_t *s)
{
	scanner_ctx_t *s_ctx = s->process.data;

	arg_dname_t origin = {
		.data = s->zone_origin,
		.len = s->zone_origin_length
	};
	arg_dname_t owner = {
		.data = s->r_owner,
		.len = s->r_owner_length
	};

	uint8_t buf[knot_rdata_size(s->r_data_length)];
	knot_rdata_t *rdata = (knot_rdata_t *)buf;
	knot_rdata_init(rdata, s->r_data_length, s->r_data);
	if (knot_rdata_to_canonical(rdata, s->r_type) != KNOT_EOK) {
		RedisModule_ReplyWithError(s_ctx->ctx, RDB_EMALF);
		s_ctx->replied = true;
		s->error.fatal = true;
		s->state = ZS_STATE_STOP;
		return;
	}

	int ret = KNOT_EOK;
	switch (s_ctx->mode) {
	case STORE:
		ret = rdata_add_format(s_ctx->ctx, &origin, s_ctx->txn, &owner,
		                       s->r_ttl, s->r_type, rdata);
		break;
	case ADD:
		ret = upd_add_txt_format(s_ctx->ctx, &origin, s_ctx->txn, &owner,
		                         s->r_ttl, s->r_type, rdata);
		break;
	case REM:
		ret = upd_remove_txt_format(s_ctx->ctx, &origin, s_ctx->txn, &owner,
		                            s->r_ttl, s->r_type, rdata);
		break;
	default:
		RedisModule_Assert(0);
	}
	if (ret != KNOT_EOK) {
		s_ctx->replied = true;
		s->error.fatal = true;
		s->state = ZS_STATE_STOP;
	}
}

static void scanner_error(zs_scanner_t *s)
{
	scanner_ctx_t *s_ctx = s->process.data;

	char msg[128];
	(void)snprintf(msg, sizeof(msg), RDB_E("parser failed (%s), line %"PRIu64),
	               zs_strerror(s->error.code), s->line_counter);
	RedisModule_ReplyWithError(s_ctx->ctx, msg);

	s_ctx->replied = true;
	s->state = ZS_STATE_STOP;
}

static void zone_store_bin_format(RedisModuleCtx *ctx, const arg_dname_t *origin,
                                  const rdb_txn_t *txn, const arg_dname_t *owner,
                                  uint16_t rtype, uint32_t ttl, uint16_t rcount,
                                  const uint8_t *zone_data, const size_t zone_data_len,
                                  bool merge)
{
	if (zone_txn_is_open(ctx, origin, txn) == false) {
		RedisModule_ReplyWithError(ctx, RDB_ETXN);
		return;
	}

	RedisModuleString *rrset_keyname = rrset_keyname_construct(ctx, origin, txn, owner, rtype);
	rrset_k rrset_key = RedisModule_OpenKey(ctx, rrset_keyname, REDISMODULE_READ | REDISMODULE_WRITE);
	if (RedisModule_KeyType(rrset_key) == REDISMODULE_KEYTYPE_EMPTY) {
		rrset_v *rrset = RedisModule_Calloc(1, sizeof(*rrset));
		if (rrset == NULL) {
			RedisModule_FreeString(ctx, rrset_keyname);
			RedisModule_CloseKey(rrset_key);
			RedisModule_ReplyWithError(ctx, RDB_EALLOC);
			return;
		}

		rrset->ttl = ttl;
		rrset->rrs.count = rcount;
		if (zone_data_len != 0) {
			rrset->rrs.rdata = RedisModule_Alloc(zone_data_len);
			if (rrset->rrs.rdata == NULL) {
				RedisModule_Free(rrset);
				RedisModule_FreeString(ctx, rrset_keyname);
				RedisModule_CloseKey(rrset_key);
				RedisModule_ReplyWithError(ctx, RDB_EALLOC);
				return;
			}
			rrset->rrs.size = zone_data_len;
			memcpy(rrset->rrs.rdata, zone_data, zone_data_len);
		} else {
			rrset->rrs.rdata = NULL;
			rrset->rrs.size = 0;
		}

		int ret = rrset_key_set(ctx, rrset_key, rrset_keyname, origin, txn, rtype, rrset);
		RedisModule_FreeString(ctx, rrset_keyname);
		RedisModule_CloseKey(rrset_key);
		if (ret != KNOT_EOK) {
			RedisModule_Free(rrset);
			RedisModule_ReplyWithError(ctx, RDB_ESTORE);
			return;
		}
	} else if (merge) {
		rrset_v *rrset = RedisModule_ModuleTypeGetValue(rrset_key);
		RedisModule_Assert(rrset != NULL);

		knot_rdataset_t new_rdataset = {
			.count = rcount,
			.size = zone_data_len,
			.rdata = (knot_rdata_t *)zone_data
		};
		if (knot_rdataset_merge(&rrset->rrs, &new_rdataset, &mm) != KNOT_EOK) {
			RedisModule_FreeString(ctx, rrset_keyname);
			RedisModule_CloseKey(rrset_key);
			RedisModule_ReplyWithError(ctx, RDB_EALLOC);
		}
		rrset->ttl = ttl;

		RedisModule_FreeString(ctx, rrset_keyname);
		RedisModule_CloseKey(rrset_key);
	} else {
		RedisModule_FreeString(ctx, rrset_keyname);
		RedisModule_CloseKey(rrset_key);
		RedisModule_ReplyWithError(ctx, RDB_EEXIST);
		return;
	}

	RedisModule_ReplicateVerbatim(ctx);
	RedisModule_ReplyWithSimpleString(ctx, RDB_RETURN_OK);
}

static void run_scanner(scanner_ctx_t *s_ctx, const arg_dname_t *origin,
                        const char *data, size_t data_len)
{
	zs_scanner_t s;
	if (zs_init(&s, origin->txt, KNOT_CLASS_IN, s_ctx->dflt_ttl) != 0 ||
	    zs_set_input_string(&s, data, data_len) != 0 ||
	    zs_set_processing(&s, scanner_data, scanner_error, s_ctx) != 0 ||
	    zs_parse_all(&s) != 0 || s.error.fatal) {
		if (!s_ctx->replied) {
			RedisModule_ReplyWithError(s_ctx->ctx, RDB_EPARSE);
		}
		zs_deinit(&s);
		return;
	}
	zs_deinit(&s);

	RedisModule_ReplicateVerbatim(s_ctx->ctx);
	RedisModule_ReplyWithSimpleString(s_ctx->ctx, RDB_RETURN_OK);
}

static void zone_store_txt_format(RedisModuleCtx *ctx, const arg_dname_t *origin,
                                  const rdb_txn_t *txn, const char *zone_data,
                                  const size_t zone_data_len)
{
	if (zone_txn_is_open(ctx, origin, txn) == false) {
		RedisModule_ReplyWithError(ctx, RDB_ETXN);
		return;
	}

	scanner_ctx_t s_ctx = {
		.ctx = ctx,
		.txn = txn,
		.dflt_ttl = rdb_default_ttl,
		.mode = STORE
	};

	run_scanner(&s_ctx, origin, zone_data, zone_data_len);
}

static int zone_meta_release(RedisModuleCtx *ctx, const arg_dname_t *origin, rdb_txn_t *txn)
{
	RedisModuleString *txn_k = zone_meta_keyname_construct(ctx, origin, txn->instance);
	zone_meta_k key = RedisModule_OpenKey(ctx, txn_k, REDISMODULE_READ | REDISMODULE_WRITE);
	RedisModule_FreeString(ctx, txn_k);
	if (key == NULL || RedisModule_KeyType(key) != REDISMODULE_KEYTYPE_STRING) {
		RedisModule_CloseKey(key);
		return KNOT_EEXIST;
	}

	size_t len = 0;
	zone_meta_storage_t *meta = (zone_meta_storage_t *)RedisModule_StringDMA(key, &len, REDISMODULE_READ | REDISMODULE_WRITE);
	if (len != sizeof(*meta)) {
		RedisModule_CloseKey(key);
		RedisModule_ReplyWithError(ctx, RDB_ECORRUPTED);
		return KNOT_EINVAL;
	}
	if (meta->active == txn->id) {
		meta->active = ZONE_META_INACTIVE;
	}
	meta->lock[txn->id] = 0;
	RedisModule_CloseKey(key);

	return KNOT_EOK;
}

static RedisModuleString *index_soa_keyname(RedisModuleCtx *ctx, index_k index)
{
	size_t key_strlen = 0;
	const RedisModuleString *index_keyname = RedisModule_GetKeyNameFromModuleKey(index);
	uint8_t *key_str = (uint8_t *)RedisModule_StringPtrLen(index_keyname, &key_strlen);

	wire_ctx_t index_w = wire_ctx_init(key_str, key_strlen);
	wire_ctx_skip(&index_w, RDB_PREFIX_LEN + 1);
	uint8_t origin_len = wire_ctx_read_u8(&index_w);

	foreach_in_zset_subset(index, SCORE_SOA, SCORE_SOA) {
		RedisModuleString *soa_keyname = RedisModule_ZsetRangeCurrentElement(index, NULL);
		key_str = (uint8_t *)RedisModule_StringPtrLen(soa_keyname, &key_strlen);

		wire_ctx_t soa_w = wire_ctx_init((uint8_t *)key_str, key_strlen);
		wire_ctx_skip(&soa_w, RDB_PREFIX_LEN + 2 + origin_len);
		uint8_t owner_len = wire_ctx_read_u8(&soa_w);

		if (origin_len == owner_len && memcmp(index_w.position, soa_w.position, origin_len) == 0) {
			RedisModule_ZsetRangeStop(index);
			return soa_keyname;
		}
		RedisModule_FreeString(ctx, soa_keyname);
	}
	RedisModule_ZsetRangeStop(index);
	return NULL;
}

static exception_t index_soa_serial(RedisModuleCtx *ctx, index_k index, bool incremental, uint32_t *out_serial)
{
	RedisModuleString *keyname = index_soa_keyname(ctx, index);
	if (keyname == NULL) {
		throw(KNOT_EINVAL, RDB_ENOSOA);
	}

	RedisModuleKey *key = RedisModule_OpenKey(ctx, keyname, REDISMODULE_READ);
	RedisModule_FreeString(ctx, keyname);
	if (key == NULL) {
		throw(KNOT_EINVAL, RDB_ECORRUPTED);
	}

	void *val = RedisModule_ModuleTypeGetValue(key);
	if (val == NULL) {
		RedisModule_CloseKey(key);
		throw(KNOT_EINVAL, RDB_ECORRUPTED);
	}

	const knot_rdataset_t *rd = incremental ? &((diff_v *)val)->rem_rrs : &((rrset_v *)val)->rrs;
	if (rd->count != 1) {
		RedisModule_CloseKey(key);
		throw(KNOT_EINVAL, RDB_ECORRUPTED);
	}

	*out_serial = knot_soa_serial(rd->rdata);
	RedisModule_CloseKey(key);

	return_ok;
}

static exception_t upd_deep_delete(RedisModuleCtx *ctx, const arg_dname_t *origin,
                                   const rdb_txn_t *txn, const uint32_t serial,
                                   size_t *counter)
{
	index_k upd_index_key = get_commited_upd_index(ctx, origin, txn, serial, REDISMODULE_READ | REDISMODULE_WRITE);
	int upd_index_type = RedisModule_KeyType(upd_index_key);
	if (upd_index_type == REDISMODULE_KEYTYPE_EMPTY) {
		RedisModule_CloseKey(upd_index_key);
		return_ok;
	} else if (upd_index_type != REDISMODULE_KEYTYPE_ZSET) {
		RedisModule_CloseKey(upd_index_key);
		throw(KNOT_EINVAL, RDB_ECORRUPTED);
	}

	uint32_t serial_prev = 0;
	exception_t e = index_soa_serial(ctx, upd_index_key, true, &serial_prev);
	if (e.ret != KNOT_EOK) {
		RedisModule_CloseKey(upd_index_key);
		throw(KNOT_EINVAL, e.what);
	}

	*counter += 1;

	foreach_in_zset(upd_index_key) {
		RedisModuleString *el = RedisModule_ZsetRangeCurrentElement(upd_index_key, NULL);
		diff_k diff_key = RedisModule_OpenKey(ctx, el, REDISMODULE_READ | REDISMODULE_WRITE);
		RedisModule_FreeString(ctx, el);
		RedisModule_DeleteKey(diff_key);
		RedisModule_CloseKey(diff_key);
	}

	RedisModule_DeleteKey(upd_index_key);
	RedisModule_CloseKey(upd_index_key);

	raise(upd_deep_delete(ctx, origin, txn, serial_prev, counter));
}

static uint8_t change_bit(uint8_t val, int idx, bool bitval)
{
	return (val & ~(1 << idx)) | (bitval << idx);
}

static exception_t zone_purge(RedisModuleCtx *ctx, const arg_dname_t *origin, rdb_txn_t *txn)
{
	if (set_active_transaction(ctx, origin, txn) != KNOT_EOK) {
		throw(KNOT_EINVAL, RDB_EZONE);
	}

	RedisModuleString *soa_rrset_keyname = rrset_keyname_construct(ctx, origin, txn, origin, KNOT_RRTYPE_SOA);
	rrset_k soa_rrset_key = RedisModule_OpenKey(ctx, soa_rrset_keyname, REDISMODULE_READ);
	RedisModule_FreeString(ctx, soa_rrset_keyname);
	if (soa_rrset_key == NULL) {
		throw(KNOT_ESOAINVAL, RDB_ENOSOA);
	}
	rrset_v *rrset = RedisModule_ModuleTypeGetValue(soa_rrset_key);
	if (rrset == NULL) {
		RedisModule_CloseKey(soa_rrset_key);
		throw(KNOT_ESOAINVAL, RDB_ENOSOA);
	}
	uint32_t serial = knot_soa_serial(rrset->rrs.rdata);
	RedisModule_CloseKey(soa_rrset_key);

	delete_zone_index(ctx, origin, txn);

	size_t counter;
	upd_deep_delete(ctx, origin, txn, serial, &counter);

	RedisModuleString *meta_k = upd_meta_keyname_construct(ctx, origin, txn->instance);
	upd_meta_k meta_key = RedisModule_OpenKey(ctx, meta_k, REDISMODULE_READ | REDISMODULE_WRITE);
	RedisModule_FreeString(ctx, meta_k);
	if (RedisModule_KeyType(meta_key) == REDISMODULE_KEYTYPE_STRING) {
		size_t len = 0;
		upd_meta_storage_t *meta = (upd_meta_storage_t *)RedisModule_StringDMA(meta_key, &len, REDISMODULE_WRITE);
		RedisModule_Assert(len == sizeof(*meta));
		knot_wire_write_u16((uint8_t *)meta + offsetof(upd_meta_storage_t, depth), 0);
	}
	RedisModule_CloseKey(meta_key);

	if (zone_meta_release(ctx, origin, txn) != KNOT_EOK) {
		throw(KNOT_EDENIED, RDB_ECORRUPTED);
	}

	RedisModuleKey *zones_index = get_zones_index(ctx, REDISMODULE_READ | REDISMODULE_WRITE);
	if (RedisModule_KeyType(zones_index) == REDISMODULE_KEYTYPE_EMPTY) {
		RedisModule_CloseKey(zones_index);
		return_ok;
	}

	RedisModuleString *origin_str = RedisModule_CreateString(ctx, (const char *)origin->data, origin->len);
	if (origin_str == NULL) {
		RedisModule_CloseKey(zones_index);
		throw(KNOT_ENOMEM, RDB_EALLOC);
	}
	RedisModuleString *value = NULL;
	if (RedisModule_HashGet(zones_index, REDISMODULE_HASH_NONE, origin_str, &value, NULL) != REDISMODULE_OK) {
		RedisModule_FreeString(ctx, origin_str);
		RedisModule_CloseKey(zones_index);
		throw(KNOT_EMALF, RDB_ECORRUPTED);
	}
	if (value == NULL) {
		RedisModule_FreeString(ctx, origin_str);
		RedisModule_CloseKey(zones_index);
		return_ok;
	}

	size_t value_len = 0;
	uint8_t val;
	const char *val_ptr = RedisModule_StringPtrLen(value, &value_len);
	if (value_len != sizeof(val)) {
		RedisModule_CloseKey(zones_index);
		throw(KNOT_EMALF, RDB_ECORRUPTED);
	}
	memcpy(&val, val_ptr, sizeof(val));
	RedisModule_FreeString(ctx, value);
	val  = change_bit(val, txn->instance - 1, false);
	if (val == 0) {
		RedisModule_HashSet(zones_index, REDISMODULE_HASH_NONE, origin_str, REDISMODULE_HASH_DELETE, NULL);
	} else {
		value = RedisModule_CreateString(ctx, (const char *)&val, sizeof(val));
		if (value == NULL) {
			RedisModule_CloseKey(zones_index);
			throw(KNOT_ENOMEM, RDB_EALLOC);
		}
		RedisModule_HashSet(zones_index, REDISMODULE_HASH_NONE, origin_str, value, NULL);
		RedisModule_FreeString(ctx, value);
	}
	RedisModule_FreeString(ctx, origin_str);
	RedisModule_CloseKey(zones_index);

	return_ok;
}

static void zone_purge_v(RedisModuleCtx *ctx, const arg_dname_t *origin, rdb_txn_t *txn)
{
	exception_t e = zone_purge(ctx, origin, txn);
	if (e.ret != KNOT_EOK) {
		RedisModule_ReplyWithError(ctx, RDB_EEVENT);
	} else {
		RedisModule_ReplicateVerbatim(ctx);
		RedisModule_ReplyWithSimpleString(ctx, RDB_RETURN_OK);
	}
}

typedef struct {
	RedisModuleCtx *ctx;
	size_t count;
	int ret;
	uint8_t instance; // Used by zone_info
	bool txt;         // Used by zone_list
	bool instances;   // Used by zone_list
} scan_ctx_t;

static void zone_list_cb(RedisModuleKey *key, RedisModuleString *zone_name,
                         RedisModuleString *mask, void *privdata)
{
	scan_ctx_t *sctx = privdata;

	if (sctx->txt) {
		char buf[KNOT_DNAME_TXT_MAXLEN + INSTANCE_MAX * 3];

		size_t len;
		const char *dname = RedisModule_StringPtrLen(zone_name, &len);
		RedisModule_Assert(knot_dname_to_str(buf, (knot_dname_t *)dname, sizeof(buf)) != NULL);

		if (sctx->instances) {
			const uint8_t *mask_p = (const uint8_t *)RedisModule_StringPtrLen(mask, &len);
			RedisModule_Assert(len == sizeof(uint8_t));

			bool first = true;
			for (unsigned inst = 1; inst <= INSTANCE_MAX; ++inst) {
				if ((*mask_p) & (1 << (inst - 1))) {
					char item[] = { first ? ':' : ',', ' ', '0' + inst, '\0' };
					strlcat(buf, item, sizeof(buf));
					first = false;
				}
			}
		}
		RedisModule_ReplyWithCString(sctx->ctx, buf);
	} else {
		if (sctx->instances) {
			RedisModule_ReplyWithArray(sctx->ctx, 2);
			RedisModule_ReplyWithString(sctx->ctx, zone_name);
			RedisModule_ReplyWithString(sctx->ctx, mask);
		} else {
			RedisModule_ReplyWithString(sctx->ctx, zone_name);
		}
	}

	++(sctx->count);
}

static void zone_list(RedisModuleCtx *ctx, bool instances, bool txt)
{
	scan_ctx_t sctx = {
		.ctx = ctx,
		.txt = txt,
		.instances = instances
	};

	RedisModuleKey *zones_index = get_zones_index(ctx, REDISMODULE_READ);
	if (zones_index == NULL) {
		RedisModule_ReplyWithError(ctx, RDB_EALLOC);
		return;
	}
	RedisModuleScanCursor *cursor = RedisModule_ScanCursorCreate();
	if (cursor == NULL) {
		RedisModule_CloseKey(zones_index);
		RedisModule_ReplyWithError(ctx, RDB_EALLOC);
		return;
	}

	RedisModule_ReplyWithArray(ctx, REDISMODULE_POSTPONED_ARRAY_LEN);
	while (RedisModule_ScanKey(zones_index, cursor, zone_list_cb, &sctx) && sctx.ret == KNOT_EOK);
	RedisModule_ReplySetArrayLength(ctx, sctx.count);

	RedisModule_ScanCursorDestroy(cursor);
	RedisModule_CloseKey(zones_index);
}

exception_t zone_info_serial(RedisModuleCtx *ctx, size_t *counter, const arg_dname_t *origin,
                             const rdb_txn_t *txn, const uint32_t serial_end, const uint32_t serial)
{
	index_k upd_index_key = get_commited_upd_index(ctx, origin, txn, serial, REDISMODULE_READ);
	if (upd_index_key == NULL) {
		return_ok;
	}

	uint32_t serial_next = 0;
	exception_t e = index_soa_serial(ctx, upd_index_key, true, &serial_next);
	if (e.ret != KNOT_EOK) {
		RedisModule_CloseKey(upd_index_key);
		raise(e);
	}

	if (serial_next != serial_end) {
		e = zone_info_serial(ctx, counter, origin, txn, serial_end, serial_next);
		if (e.ret != KNOT_EOK) {
			RedisModule_CloseKey(upd_index_key);
			raise(e);
		}
	}

	char buf[64];
	(void)snprintf(buf, sizeof(buf), "update: %u -> %u", serial_next, serial);
	RedisModule_ReplyWithCString(ctx, buf);
	*counter += 1;

	RedisModule_CloseKey(upd_index_key);

	return_ok;
}

static void zone_info_serials(RedisModuleCtx *ctx, arg_dname_t *origin, rdb_txn_t *txn)
{
	if (set_active_transaction(ctx, origin, txn) != KNOT_EOK) {
		RedisModule_ReplyWithError(ctx, RDB_EZONE);
		return;
	}

	RedisModuleString *soa_rrset_keyname = rrset_keyname_construct(ctx, origin, txn, origin, KNOT_RRTYPE_SOA);
	rrset_k soa_rrset_key = RedisModule_OpenKey(ctx, soa_rrset_keyname, REDISMODULE_READ);
	RedisModule_FreeString(ctx, soa_rrset_keyname);
	rrset_v *rrset = RedisModule_ModuleTypeGetValue(soa_rrset_key);
	if (rrset == NULL) {
		RedisModule_CloseKey(soa_rrset_key);
		RedisModule_ReplyWithError(ctx, RDB_ENOSOA);
		return;
	}
	uint32_t serial_it = knot_soa_serial(rrset->rrs.rdata);
	RedisModule_CloseKey(soa_rrset_key);

	RedisModule_ReplyWithArray(ctx, 3);
	char buf[64];
	(void)snprintf(buf, sizeof(buf), "instance: %u", txn->instance);
	RedisModule_ReplyWithCString(ctx, buf);
	(void)snprintf(buf, sizeof(buf), "serial: %u", serial_it);
	RedisModule_ReplyWithCString(ctx, buf);

	size_t upd_count = 0;
	RedisModule_ReplyWithArray(ctx, REDISMODULE_POSTPONED_ARRAY_LEN);
	exception_t e = zone_info_serial(ctx, &upd_count, origin, txn, serial_it, serial_it);
	if (e.ret != KNOT_EOK && e.what != NULL) {
		RedisModule_ReplyWithError(ctx, e.what);
		upd_count++;
	}
	RedisModule_ReplySetArrayLength(ctx, upd_count);
}

static void zone_info_cb(RedisModuleKey *key, RedisModuleString *zone_name,
                         RedisModuleString *mask, void *privdata)
{
	scan_ctx_t *sctx = privdata;

	char buf[KNOT_DNAME_TXT_MAXLEN];

	size_t len;
	const char *dname = RedisModule_StringPtrLen(zone_name, &len);
	arg_dname_t origin = { .data = (uint8_t *)dname, .len = len };
	RedisModule_Assert(knot_dname_to_str(buf, (knot_dname_t *)dname, sizeof(buf)) != NULL);

	const uint8_t *mask_p = (const uint8_t *)RedisModule_StringPtrLen(mask, &len);
	RedisModule_Assert(len == sizeof(uint8_t));

	RedisModule_ReplyWithArray(sctx->ctx, 2);
	RedisModule_ReplyWithCString(sctx->ctx, buf);

	RedisModule_ReplyWithArray(sctx->ctx, REDISMODULE_POSTPONED_ARRAY_LEN);
	size_t inst_count = 0;
	if (sctx->instance != 0) {
		if ((*mask_p) & (1 << (sctx->instance - 1))) {
			rdb_txn_t txn = {
				.instance = sctx->instance,
				.id = TXN_ID_ACTIVE
			};
			zone_info_serials(sctx->ctx, &origin, &txn);
			++inst_count;
		}
	} else {
		for (unsigned inst = 1; inst <= INSTANCE_MAX; ++inst) {
			if ((*mask_p) & (1 << (inst - 1))) {
				rdb_txn_t txn = {
					.instance = inst,
					.id = TXN_ID_ACTIVE
				};
				zone_info_serials(sctx->ctx, &origin, &txn);
				++inst_count;
			}
		}
	}
	RedisModule_ReplySetArrayLength(sctx->ctx, inst_count);

	++(sctx->count);
}

static void zone_info(RedisModuleCtx *ctx, arg_dname_t *origin, rdb_txn_t *txn)
{
	scan_ctx_t sctx = {
		.ctx = ctx,
		.instance = (txn != NULL) ? txn->instance : 0
	};

	RedisModuleKey *zones_index = get_zones_index(ctx, REDISMODULE_READ);
	if (zones_index == NULL) {
		RedisModule_ReplyWithError(ctx, RDB_EALLOC);
		return;
	}

	if (origin != NULL) {
		RedisModuleString *origin_str = RedisModule_CreateString(ctx, (const char *)origin->data, origin->len);
		if (origin_str == NULL) {
			RedisModule_CloseKey(zones_index);
			RedisModule_ReplyWithError(ctx, RDB_EALLOC);
			return;
		}

		RedisModuleString *value;
		if (RedisModule_HashGet(zones_index, REDISMODULE_HASH_NONE, origin_str, &value, NULL) != REDISMODULE_OK) {
			RedisModule_FreeString(ctx, origin_str);
			RedisModule_CloseKey(zones_index);
			RedisModule_ReplyWithError(ctx, RDB_ECORRUPTED);
			return;
		}
		zone_info_cb(zones_index, origin_str, value, &sctx);
		RedisModule_FreeString(ctx, value);
		RedisModule_FreeString(ctx, origin_str);
	} else {
		RedisModuleScanCursor *cursor = RedisModule_ScanCursorCreate();
		if (cursor == NULL) {
			RedisModule_CloseKey(zones_index);
			RedisModule_ReplyWithError(ctx, RDB_EALLOC);
			return;
		}

		RedisModule_ReplyWithArray(ctx, REDISMODULE_POSTPONED_ARRAY_LEN);
		while (RedisModule_ScanKey(zones_index, cursor, zone_info_cb, &sctx) && sctx.ret == KNOT_EOK);
		RedisModule_ReplySetArrayLength(ctx, sctx.count);

		RedisModule_ScanCursorDestroy(cursor);
	}
	RedisModule_CloseKey(zones_index);
}

static exception_t zone_meta_active_exchange(RedisModuleCtx *ctx, zone_meta_k key,
                                             const arg_dname_t *origin, rdb_txn_t *txn)
{
	size_t len = 0;
	zone_meta_storage_t *meta = (zone_meta_storage_t *)RedisModule_StringDMA(key, &len, REDISMODULE_WRITE);
	if (len != sizeof(*meta)) {
		throw(KNOT_EINVAL, RDB_ECORRUPTED);
	}

	exception_t e = { .ret = KNOT_EOK };
	uint8_t active_old = meta->active;
	if (active_old != ZONE_META_INACTIVE) {
		rdb_txn_t txn_old = {
			.instance = txn->instance,
			.id = active_old
		};
		e = zone_purge(ctx, origin, &txn_old);
		meta->lock[active_old] = 0;
	}
	meta->active = txn->id;
	raise(e);
}

static void zone_commit(RedisModuleCtx *ctx, const arg_dname_t *origin, rdb_txn_t *txn,
                        RedisModuleStreamID *stream_id)
{
	zone_meta_k meta_key = zone_meta_get_when_open(ctx, origin, txn, REDISMODULE_READ | REDISMODULE_WRITE);
	if (meta_key == NULL) {
		RedisModule_ReplyWithError(ctx, RDB_ETXN);
		return;
	}

	uint32_t serial = 0;
	index_k zone_index_key = get_zone_index(ctx, origin, txn, REDISMODULE_READ | REDISMODULE_WRITE); // NOTE for iteration need also key opened for writing
	exception_t e = index_soa_serial(ctx, zone_index_key, false, &serial);
	RedisModule_CloseKey(zone_index_key);
	if (e.ret != KNOT_EOK) {
		RedisModule_CloseKey(meta_key);
		RedisModule_ReplyWithError(ctx, e.what);
		return;
	}

	e = zone_meta_active_exchange(ctx, meta_key, origin, txn);
	RedisModule_CloseKey(meta_key);
	if (e.ret != KNOT_EOK) {
		RedisModule_ReplyWithError(ctx, e.what);
		return;
	}

	RedisModuleKey *zones_index = get_zones_index(ctx, REDISMODULE_READ | REDISMODULE_WRITE);
	RedisModuleString *origin_str = RedisModule_CreateString(ctx, (const char *)origin->data, origin->len);
	if (origin_str == NULL) {
		RedisModule_CloseKey(zones_index);
		RedisModule_ReplyWithError(ctx, RDB_EALLOC);
		return;
	}
	RedisModuleString *value = NULL;
	uint8_t val = 0;
	if (RedisModule_KeyType(zones_index) != REDISMODULE_KEYTYPE_EMPTY) {
		if (RedisModule_HashGet(zones_index, REDISMODULE_HASH_NONE, origin_str, &value, NULL) != REDISMODULE_OK) {
			RedisModule_FreeString(ctx, origin_str);
			RedisModule_CloseKey(zones_index);
			RedisModule_ReplyWithError(ctx, RDB_ECORRUPTED);
			return;
		}
		if (value != NULL) {
			size_t value_len = 0;
			const char *val_ptr = RedisModule_StringPtrLen(value, &value_len);
			if (value_len != sizeof(val)) {
				RedisModule_FreeString(ctx, origin_str);
				RedisModule_CloseKey(zones_index);
				RedisModule_ReplyWithError(ctx, RDB_ECORRUPTED);
				return;
			}
			memcpy(&val, val_ptr, sizeof(val));
			RedisModule_FreeString(ctx, value);
		}
	}
	val = change_bit(val, txn->instance - 1, true);
	value = RedisModule_CreateString(ctx, (const char *)&val, sizeof(val));
	if (value == NULL) {
		RedisModule_FreeString(ctx, origin_str);
		RedisModule_CloseKey(zones_index);
		RedisModule_ReplyWithError(ctx, RDB_EALLOC);
		return;
	}
	RedisModule_HashSet(zones_index, REDISMODULE_HASH_NONE, origin_str, value, NULL);
	RedisModule_FreeString(ctx, origin_str);
	RedisModule_FreeString(ctx, value);
	RedisModule_CloseKey(zones_index);

	commit_event(ctx, RDB_EVENT_ZONE, origin, txn->instance, serial, stream_id);

	// Replicate with explicit ID so replicas use the same ID.
	RedisModuleStreamID wire_id = WIRE_STREAM_ID(stream_id);
	RedisModule_Replicate(ctx, RDB_CMD_ZONE_COMMIT, "bbb", (char *)origin->data,
	                      origin->len, txn, sizeof(*txn), &wire_id, sizeof(wire_id));

	RedisModule_ReplyWithSimpleString(ctx, RDB_RETURN_OK);
}

static void zone_abort(RedisModuleCtx *ctx, const arg_dname_t *origin, rdb_txn_t *txn)
{
	zone_meta_k meta_key = zone_meta_get_when_open(ctx, origin, txn, REDISMODULE_READ | REDISMODULE_WRITE);
	if (meta_key == NULL) {
		RedisModule_ReplyWithError(ctx, RDB_ETXN);
		return;
	}

	size_t len = 0;
	zone_meta_storage_t *meta = (zone_meta_storage_t *)RedisModule_StringDMA(meta_key, &len, REDISMODULE_WRITE);
	if (meta == NULL || len != sizeof(zone_meta_storage_t)) {
		RedisModule_CloseKey(meta_key);
		RedisModule_ReplyWithError(ctx, RDB_ECORRUPTED);
		return;
	}
	meta->lock[txn->id] = 0;
	RedisModule_CloseKey(meta_key);

	int ret = delete_zone_index(ctx, origin, txn);
	if (ret == KNOT_EOK) {
		RedisModule_ReplicateVerbatim(ctx);
		RedisModule_ReplyWithSimpleString(ctx, RDB_RETURN_OK);
	} else if (ret == KNOT_EEXIST) {
		RedisModule_ReplyWithError(ctx, RDB_EZONE);
	} else {
		RedisModule_ReplyWithError(ctx, RDB_ECORRUPTED);
	}
}

static void zone_exists(RedisModuleCtx *ctx, const arg_dname_t *origin, rdb_txn_t *txn)
{
	int ret = set_active_transaction(ctx, origin, txn);
	if (ret != KNOT_EOK) {
		RedisModule_ReplyWithError(ctx, RDB_EZONE);
		return;
	}

	index_k zone_index_key = get_zone_index(ctx, origin, txn, REDISMODULE_READ);
	if (zone_index_key == NULL) {
		RedisModule_ReplyWithError(ctx, RDB_ENOSOA);
		return;
	}
	int zone_keytype = RedisModule_KeyType(zone_index_key);
	if (zone_keytype == REDISMODULE_KEYTYPE_EMPTY) {
		RedisModule_CloseKey(zone_index_key);
		RedisModule_ReplyWithError(ctx, RDB_ENOSOA);
		return;
	} else if (zone_keytype != REDISMODULE_KEYTYPE_ZSET) {
		RedisModule_CloseKey(zone_index_key);
		RedisModule_ReplyWithError(ctx, RDB_ECORRUPTED);
		return;
	}

	uint32_t serial = 0;
	exception_t e = index_soa_serial(ctx, zone_index_key, false, &serial);
	RedisModule_CloseKey(zone_index_key);
	if (e.ret != KNOT_EOK) {
		RedisModule_ReplyWithError(ctx, e.what);
		return;
	}

	RedisModule_ReplyWithLongLong(ctx, serial);
}

static int dump_rrset(RedisModuleCtx *ctx, knot_rrset_t *rrset, char *buf,
                      size_t buf_size, long *count, dump_mode_t mode)
{
	const knot_dump_style_t style = KNOT_DUMP_STYLE_DEFAULT;

	knot_dname_txt_storage_t owner;
	(void)knot_dname_to_str(owner, rrset->owner, sizeof(owner));

	char rtype[16];
	(void)knot_rrtype_to_string(rrset->type, rtype, sizeof(rtype));

	char ttl[16];
	if (rrset->type != KNOT_RRTYPE_RRSIG) {
		if (rrset->ttl == TTL_EMPTY) {
			strlcpy(ttl, TTL_EMPTY_STR, sizeof(ttl));
		} else {
			(void)snprintf(ttl, sizeof(ttl), "%u", rrset->ttl);
		}
	}

	knot_rdata_t *rr = rrset->rrs.rdata;
	for (uint16_t i = 0; i < rrset->rrs.count; i++) {
		if (rrset->type == KNOT_RRTYPE_RRSIG) {
			uint32_t orig_ttl = knot_rrsig_original_ttl(rr);
			if (orig_ttl == TTL_EMPTY) {
				strlcpy(ttl, TTL_EMPTY_STR, sizeof(ttl));
			} else {
				(void)snprintf(ttl, sizeof(ttl), "%u", orig_ttl);
			}
		}

		int ret = knot_rrset_txt_dump_data(rrset, i, buf, buf_size, &style);
		if (ret == KNOT_ESPACE) {
			(*count)++;
			RedisModule_ReplyWithError(ctx, RDB_EALLOC);
			return -1;
		} else if (ret < 0) {
			(*count)++;
			RedisModule_ReplyWithError(ctx, RDB_EMALF);
			return -1;
		}

		if (mode == DUMP_COMPACT) {
			char *line = sprintf_alloc("%s %s %s %s", owner, ttl, rtype, buf);
			if (line == NULL) {
				(*count)++;
				RedisModule_ReplyWithError(ctx, RDB_EALLOC);
				return -1;
			}
			RedisModule_ReplyWithStringBuffer(ctx, line, strlen(line));
			free(line);
		} else {
			RedisModule_Assert(mode == DUMP_TXT);
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

static bool meta_exists(RedisModuleCtx *ctx, const arg_dname_t *origin, rdb_txn_t *txn)
{
	RedisModule_Assert(txn->instance != 0);

	RedisModuleString *txn_k = zone_meta_keyname_construct(ctx, origin, txn->instance);
	zone_meta_k key = RedisModule_OpenKey(ctx, txn_k, REDISMODULE_READ);
	RedisModule_FreeString(ctx, txn_k);
	if (key == NULL) {
		return false;
	} else if (RedisModule_KeyType(key) != REDISMODULE_KEYTYPE_STRING) {
		RedisModule_CloseKey(key);
		return false;
	}
	size_t len = 0;
	const zone_meta_storage_t *meta = (const zone_meta_storage_t *)RedisModule_StringDMA(key, &len, REDISMODULE_READ);
	bool out = meta->lock[txn->id] != 0;
	RedisModule_CloseKey(key);
	return out;
}

static void zone_load(RedisModuleCtx *ctx, const arg_dname_t *origin, rdb_txn_t *txn,
                      const arg_dname_t *opt_owner, uint16_t *opt_rtype, dump_mode_t mode)
{
	if (txn->id == TXN_ID_ACTIVE) {
		int ret = set_active_transaction(ctx, origin, txn);
		if (ret != KNOT_EOK) {
			RedisModule_ReplyWithError(ctx, RDB_EZONE);
			return;
		}
	} else if (meta_exists(ctx, origin, txn) == false) {
		RedisModule_ReplyWithError(ctx, RDB_ECORRUPTED);
		return;
	}

	index_k index_key = get_zone_index(ctx, origin, txn, REDISMODULE_READ);
	if (index_key == NULL) {
		RedisModule_ReplyWithEmptyArray(ctx);
		return;
	}
	int zone_keytype = RedisModule_KeyType(index_key);
	if (zone_keytype != REDISMODULE_KEYTYPE_ZSET) {
		RedisModule_CloseKey(index_key);
		RedisModule_ReplyWithError(ctx, RDB_EMALF);
		return;
	}

	char buf[128 * 1024];

	long count = 0;
	RedisModule_ReplyWithArray(ctx, REDISMODULE_POSTPONED_ARRAY_LEN);
	foreach_in_zset (index_key) {
		RedisModuleString *el = RedisModule_ZsetRangeCurrentElement(index_key, NULL);
		rrset_k rrset_key = RedisModule_OpenKey(ctx, el, REDISMODULE_READ);
		if (rrset_key == NULL) {
			RedisModule_FreeString(ctx, el);
			count++;
			RedisModule_ReplyWithError(ctx, RDB_ECORRUPTED);
			break;
		}

		size_t key_strlen = 0;
		const char *key_str = RedisModule_StringPtrLen(el, &key_strlen);
		wire_ctx_t w = wire_ctx_init((uint8_t *)key_str, key_strlen);
		wire_ctx_skip(&w, RDB_PREFIX_LEN + 2 + origin->len);
		uint8_t owner_len = wire_ctx_read_u8(&w);
		knot_dname_t *owner = w.position;
		wire_ctx_skip(&w, owner_len);
		uint16_t rtype = wire_ctx_read_u16(&w);
		RedisModule_Assert(w.error == KNOT_EOK);
		RedisModule_FreeString(ctx, el);

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

		if (mode == DUMP_BIN) {
			RedisModule_ReplyWithArray(ctx, 5);
			RedisModule_ReplyWithStringBuffer(ctx, (char *)owner, owner_len);
			RedisModule_ReplyWithLongLong(ctx, rtype);
			RedisModule_ReplyWithLongLong(ctx, rrset->ttl);
			RedisModule_ReplyWithLongLong(ctx, rrset->rrs.count);
			RedisModule_ReplyWithStringBuffer(ctx, (const char *)rrset->rrs.rdata, rrset->rrs.size);
			count++;
		} else {
			knot_rrset_t rrset_out;
			knot_rrset_init(&rrset_out, owner, rtype, KNOT_CLASS_IN, rrset->ttl);
			rrset_out.rrs = rrset->rrs;
			if (dump_rrset(ctx, &rrset_out, buf, sizeof(buf), &count, mode) != 0) {
				RedisModule_CloseKey(rrset_key);
				break;
			}
		}
		RedisModule_CloseKey(rrset_key);
	}
	RedisModule_ZsetRangeStop(index_key);
	RedisModule_CloseKey(index_key);
	RedisModule_ReplySetArrayLength(ctx, count);
}

static void upd_meta_unlock(RedisModuleCtx *ctx, upd_meta_k key, uint8_t id)
{
	size_t len = 0;
	upd_meta_storage_t *meta = (upd_meta_storage_t *)RedisModule_StringDMA(key, &len, REDISMODULE_WRITE);
	RedisModule_Assert(len == sizeof(*meta));
	knot_wire_write_u16((uint8_t *)meta + offsetof(upd_meta_storage_t, lock[id]), 0);
}

static exception_t upd_abort(RedisModuleCtx *ctx, const arg_dname_t *origin, rdb_txn_t *txn)
{
	upd_meta_k meta_key = upd_meta_get_when_open(ctx, origin, txn, REDISMODULE_READ | REDISMODULE_WRITE);
	if (meta_key == NULL) {
		throw(KNOT_ENOENT, RDB_ETXN);
	}

	if (delete_upd_index(ctx, origin, txn) != KNOT_EOK) {
		RedisModule_CloseKey(meta_key);
		throw(KNOT_EINVAL, RDB_ECORRUPTED);
	}

	upd_meta_unlock(ctx, meta_key, txn->id);

	RedisModule_CloseKey(meta_key);
	return_ok;
}

static void upd_abort_v(RedisModuleCtx *ctx, const arg_dname_t *origin, rdb_txn_t *txn)
{
	exception_t e = upd_abort(ctx, origin, txn);
	if (e.ret != KNOT_EOK) {
		RedisModule_ReplyWithError(ctx, e.what);
	} else {
		RedisModule_ReplicateVerbatim(ctx);
		RedisModule_ReplyWithSimpleString(ctx, RDB_RETURN_OK);
	}
}

static int upd_check(const diff_v *diff, const rrset_v *rrset, uint16_t rtype,
                     int64_t *serial_upd, const char **err)
{
	if (diff->rem_rrs.count > 0) {
		if (rrset == NULL) {
			*err = "failed to remove non-existent record";
			return KNOT_ESEMCHECK;
		} else if (!knot_rdataset_subset(&diff->rem_rrs, &rrset->rrs)) {
			*err = "failed to remove non-existent record";
			return KNOT_ESEMCHECK;
		} else if (diff->rem_ttl != TTL_EMPTY && rrset->ttl != diff->rem_ttl) {
			*err = "failed to remove record with non-matching TTL";
			return KNOT_ESEMCHECK;
		}
	}

	if (rrset != NULL) {
		uint16_t rr_count = diff->add_rrs.count;
		knot_rdata_t *rr = diff->add_rrs.rdata;
		for (size_t i = 0; i < rr_count; ++i) {
			if (find_rr_pos(&rrset->rrs, rr) != KNOT_ENOENT) {
				*err = "failed to add existing record";
				return KNOT_ESEMCHECK;
			}
			rr = knot_rdataset_next(rr);
		}
	}

	if (rtype == KNOT_RRTYPE_SOA) {
		RedisModule_Assert(rrset != NULL);
		knot_rdataset_t soa_tmp;
		if (knot_rdataset_copy(&soa_tmp, &rrset->rrs, &mm) != KNOT_EOK ||
		    knot_rdataset_subtract(&soa_tmp, &diff->rem_rrs, &mm) != KNOT_EOK ||
		    knot_rdataset_merge(&soa_tmp, &diff->add_rrs, &mm) != KNOT_EOK) {
			*err = "failed to update SOA";
			return KNOT_ENOMEM;
		}

		if (soa_tmp.count != 1) {
			knot_rdataset_clear(&soa_tmp, &mm);
			*err = "exactly one SOA expected";
			return KNOT_ESEMCHECK;
		}

		uint32_t serial_new = knot_soa_serial(soa_tmp.rdata);
		uint32_t serial_diff = serial_new - knot_soa_serial(rrset->rrs.rdata);
		if (serial_diff == 0 || serial_diff >= 0x80000000U) {
			knot_rdataset_clear(&soa_tmp, &mm);
			*err = "new SOA serial not increased";
			return KNOT_ESEMCHECK;
		}
		*serial_upd = serial_new;

		knot_rdataset_clear(&soa_tmp, &mm);
	}

	return KNOT_EOK;
}

static exception_t upd_trim_history(RedisModuleCtx *ctx, const arg_dname_t *origin,
                                    const rdb_txn_t *txn, const uint16_t depth)
{
	rdb_txn_t zone_txn = {
		.instance = txn->instance,
		.id = TXN_ID_ACTIVE
	};
	int ret = set_active_transaction(ctx, origin, &zone_txn);
	if (ret != KNOT_EOK) {
		throw(KNOT_EEXIST, RDB_EZONE);
	}

	RedisModuleString *soa_rrset_keyname = rrset_keyname_construct(ctx, origin, &zone_txn, origin, KNOT_RRTYPE_SOA);
	rrset_k soa_rrset_key = RedisModule_OpenKey(ctx, soa_rrset_keyname, REDISMODULE_READ);
	if (soa_rrset_key == NULL) {
		throw(KNOT_EEXIST, RDB_ENOSOA);
	}
	RedisModule_FreeString(ctx, soa_rrset_keyname);

	rrset_v *rrset = RedisModule_ModuleTypeGetValue(soa_rrset_key);
	if (rrset == NULL) {
		RedisModule_CloseKey(soa_rrset_key);
		throw(KNOT_EEXIST, RDB_ENOSOA);
	}

	uint32_t serial_it = knot_soa_serial(rrset->rrs.rdata);
	uint32_t serial_begin = serial_it;
	RedisModule_CloseKey(soa_rrset_key);

	uint16_t counter = 0;
	for (counter = 0; counter < depth; ++counter) {
		if (counter != 0 && serial_begin == serial_it) {
			break;
		}
		index_k upd_index_key = get_commited_upd_index(ctx, origin, txn, serial_it, REDISMODULE_READ | REDISMODULE_WRITE);
		int upd_index_type = RedisModule_KeyType(upd_index_key);
		if (upd_index_type == REDISMODULE_KEYTYPE_EMPTY) {
			RedisModule_CloseKey(upd_index_key);
			return_ok;
		} else if (upd_index_type != REDISMODULE_KEYTYPE_ZSET) {
			RedisModule_CloseKey(upd_index_key);
			throw(KNOT_EINVAL, RDB_ECORRUPTED);
		}

		exception_t e = index_soa_serial(ctx, upd_index_key, true, &serial_it);
		RedisModule_CloseKey(upd_index_key);
		if (e.ret != KNOT_EOK) {
			throw(KNOT_EINVAL, e.what);
		}
	}

	if (counter < depth) {
		return_ok;
	}

	size_t c;
	exception_t e = upd_deep_delete(ctx, origin, txn, serial_it, &c);
	if (e.ret != KNOT_EOK) {
		raise(e);
	}

	return_ok;
}

static void upd_commit(RedisModuleCtx *ctx, const arg_dname_t *origin, rdb_txn_t *upd_txn,
                       RedisModuleStreamID *stream_id)
{
	upd_meta_k meta_key = upd_meta_get_when_open(ctx, origin, upd_txn, REDISMODULE_READ | REDISMODULE_WRITE);
	if (meta_key == NULL) {
		RedisModule_ReplyWithError(ctx, RDB_ETXN);
		return;
	}

	int ret = get_id(ctx, origin, upd_txn);
	if (ret < 0 || ret > UINT16_MAX) {
		RedisModule_CloseKey(meta_key);
		RedisModule_ReplyWithError(ctx, RDB_ETXN);
		return;
	}
	uint16_t id = ret;

	rdb_txn_t zone_txn = {
		.instance = upd_txn->instance
	};
	ret = set_active_transaction(ctx, origin, &zone_txn);
	if (ret != KNOT_EOK) {
		RedisModule_CloseKey(meta_key);
		RedisModule_ReplyWithError(ctx, RDB_EZONE);
		return;
	}

	// Check the update before its application.
	int64_t serial_upd = -1;
	index_k upd_key = get_upd_index(ctx, origin, upd_txn, id, REDISMODULE_READ | REDISMODULE_WRITE);
	foreach_in_zset(upd_key) {
		RedisModuleString *el = RedisModule_ZsetRangeCurrentElement(upd_key, NULL);
		size_t el_len = 0;
		const char *el_str = RedisModule_StringPtrLen(el, &el_len);
		RedisModule_Assert(el_str != NULL && el_len > 0);

		wire_ctx_t w = wire_ctx_init((uint8_t *)el_str, el_len);
		wire_ctx_skip(&w, RDB_PREFIX_LEN + 2 + origin->len);
		uint8_t owner_len = wire_ctx_read_u8(&w);
		arg_dname_t owner = {
			.data = w.position,
			.len = owner_len
		};
		wire_ctx_skip(&w, owner.len);
		uint16_t rtype = wire_ctx_read_u16(&w);

		diff_k diff_key = RedisModule_OpenKey(ctx, el, REDISMODULE_READ);
		RedisModule_FreeString(ctx, el);
		const diff_v *diff = RedisModule_ModuleTypeGetValue(diff_key);
		RedisModule_Assert(diff != NULL);

		RedisModuleString *rrset_keystr = rrset_keyname_construct(ctx, origin, &zone_txn, &owner, rtype);
		rrset_k rrset_key = RedisModule_OpenKey(ctx, rrset_keystr, REDISMODULE_READ);
		RedisModule_FreeString(ctx, rrset_keystr);
		rrset_v *rrset = RedisModule_ModuleTypeGetValue(rrset_key);

		const char *err = NULL;
		ret = upd_check(diff, rrset, rtype, &serial_upd, &err);
		RedisModule_CloseKey(rrset_key);
		RedisModule_CloseKey(diff_key);
		if (ret != KNOT_EOK) {
			char msg[512], owner_str[256], rtype_str[16];
			(void)knot_dname_to_str(owner_str, owner.data, sizeof(owner_str));
			(void)knot_rrtype_to_string(rtype, rtype_str, sizeof(rtype_str));
			(void)snprintf(msg, sizeof(msg), RDB_E("%s, owner %s, type %s"),
			               err, owner_str, rtype_str);
			RedisModule_CloseKey(upd_key);
			RedisModule_CloseKey(meta_key);
			RedisModule_ReplyWithError(ctx, msg);
			return;
		}
	}

	// Check if SOA serial was explicitly incremented; compute new serial otherwise.
	rrset_k soa_key = NULL;
	rrset_v *soa_rrset = NULL;
	uint32_t serial_new;
	if (serial_upd == -1) {
		index_k zone_key = get_zone_index(ctx, origin, &zone_txn, REDISMODULE_READ);
		RedisModuleString *soa_keyname = index_soa_keyname(ctx, zone_key);
		RedisModule_CloseKey(zone_key);
		soa_key = RedisModule_OpenKey(ctx, soa_keyname, REDISMODULE_WRITE);
		RedisModule_FreeString(ctx, soa_keyname);
		RedisModule_Assert(RedisModule_ModuleTypeGetType(soa_key) == rdb_rrset_t);
		soa_rrset = RedisModule_ModuleTypeGetValue(soa_key);
		RedisModule_Assert(soa_rrset != NULL);
		serial_new = knot_soa_serial(soa_rrset->rrs.rdata) + 1;
	} else {
		serial_new = serial_upd;
	}

	// Delete collision updates
	size_t len = 0;
	upd_meta_storage_t *meta = (upd_meta_storage_t *)RedisModule_StringDMA(meta_key, &len, REDISMODULE_WRITE);
	RedisModule_Assert(len == sizeof(*meta));

	size_t counter = 0;
	exception_t e = upd_deep_delete(ctx, origin, upd_txn, serial_new, &counter);
	if (e.ret != KNOT_EOK) {
		RedisModule_CloseKey(upd_key);
		RedisModule_CloseKey(meta_key);
		RedisModule_ReplyWithError(ctx, RDB_EHISTORY);
		return;
	}
	uint16_t depth = knot_wire_read_u16((uint8_t *)meta + offsetof(upd_meta_storage_t, depth));
	knot_wire_write_u16((uint8_t *)meta + offsetof(upd_meta_storage_t, depth), depth - counter);

	// Commit the update.
	index_k new_upd_key = get_commited_upd_index(ctx, origin, upd_txn, serial_new, REDISMODULE_READ | REDISMODULE_WRITE);
	foreach_in_zset(upd_key) {
		double score = 0.0;
		RedisModuleString *el = RedisModule_ZsetRangeCurrentElement(upd_key, &score);
		size_t el_len = 0;
		const char *el_str = RedisModule_StringPtrLen(el, &el_len);
		RedisModule_Assert(el_str != NULL && el_len > 0);

		RedisModule_Assert(RedisModule_ZsetAdd(new_upd_key, score, el, NULL) == REDISMODULE_OK);

		wire_ctx_t w = wire_ctx_init((uint8_t *)el_str, el_len);
		wire_ctx_skip(&w, RDB_PREFIX_LEN + 2 + origin->len);
		uint8_t owner_len = wire_ctx_read_u8(&w);
		arg_dname_t owner = {
			.data = w.position,
			.len = owner_len
		};
		wire_ctx_skip(&w, owner.len);
		uint16_t rtype = wire_ctx_read_u16(&w);

		diff_k diff_key = RedisModule_OpenKey(ctx, el, REDISMODULE_READ | REDISMODULE_WRITE);
		RedisModule_FreeString(ctx, el);
		diff_v *diff = RedisModule_ModuleTypeGetValue(diff_key);
		RedisModule_Assert(diff != NULL);

		uint16_t rr_count = diff->rem_rrs.count;
		knot_rdata_t *rr = diff->rem_rrs.rdata;
		for (size_t i = 0; i < rr_count; ++i) {
			exception_t ex = rdata_remove(ctx, origin, &zone_txn, &owner, &diff->rem_ttl, rtype, rr);
			if (ex.ret != KNOT_EOK) {
				RedisModule_Log(ctx, REDISMODULE_LOGLEVEL_WARNING, RDB_ESTORE);
			}
			rr = knot_rdataset_next(rr);
		}

		rr_count = diff->add_rrs.count;
		rr = diff->add_rrs.rdata;
		for (size_t i = 0; i < rr_count; ++i) {
			exception_t ex = rdata_add(ctx, origin, &zone_txn, &owner, diff->add_ttl, rtype, rr);
			if (ex.ret != KNOT_EOK) {
				RedisModule_Log(ctx, REDISMODULE_LOGLEVEL_WARNING, RDB_ESTORE);
			}
			rr = knot_rdataset_next(rr);
		}

		RedisModule_CloseKey(diff_key);
	}
	knot_wire_write_u16((uint8_t *)meta + offsetof(upd_meta_storage_t, depth), ++depth);
	RedisModule_DeleteKey(upd_key);
	RedisModule_CloseKey(upd_key);

	// Increment SOA serial and add a corresponding diff.
	if (serial_upd == -1) {
		RedisModuleString *soa_diff_keyname = diff_keyname_construct(ctx, origin, upd_txn, origin, KNOT_RRTYPE_SOA, id);
		diff_k soa_diff_key = RedisModule_OpenKey(ctx, soa_diff_keyname, REDISMODULE_WRITE);

		diff_v *diff = RedisModule_Calloc(1, sizeof(diff_v));
		RedisModule_Assert(diff != NULL);
		diff->add_ttl = soa_rrset->ttl;
		diff->rem_ttl = soa_rrset->ttl;
		RedisModule_Assert(soa_rrset != NULL);
		(void)knot_rdataset_copy(&diff->rem_rrs, &soa_rrset->rrs, &mm);
		knot_soa_serial_set(soa_rrset->rrs.rdata, serial_new);
		(void)knot_rdataset_copy(&diff->add_rrs, &soa_rrset->rrs, &mm);
		RedisModule_Assert(RedisModule_ModuleTypeSetValue(soa_diff_key, rdb_diff_t, diff) == REDISMODULE_OK);
		RedisModule_Assert(RedisModule_ZsetAdd(new_upd_key, evaluate_score(KNOT_RRTYPE_SOA), soa_diff_keyname, NULL) == REDISMODULE_OK);

		RedisModule_FreeString(ctx, soa_diff_keyname);
		RedisModule_CloseKey(soa_diff_key);
		RedisModule_CloseKey(soa_key);
	}
	RedisModule_CloseKey(new_upd_key);

	e = upd_trim_history(ctx, origin, upd_txn, rdb_upd_history_len);
	if (e.ret == KNOT_EOK) {
		knot_wire_write_u16((uint8_t *)meta + offsetof(upd_meta_storage_t, depth), MIN(depth, rdb_upd_history_len));
	}

	upd_meta_unlock(ctx, meta_key, upd_txn->id);
	RedisModule_CloseKey(meta_key);

	commit_event(ctx, RDB_EVENT_UPD, origin, upd_txn->instance, serial_new, stream_id);

	if (e.ret != KNOT_EOK) {
		RedisModule_ReplyWithError(ctx, e.what);
	} else {
		// Replicate with explicit ID so replicas use the same ID.
		RedisModuleStreamID wire_id = WIRE_STREAM_ID(stream_id);
		RedisModule_Replicate(ctx, RDB_CMD_UPD_COMMIT, "bbb", (char *)origin->data,
		                      origin->len, upd_txn, sizeof(*upd_txn), &wire_id, sizeof(wire_id));
		RedisModule_ReplyWithSimpleString(ctx, RDB_RETURN_OK);
	}
}

static int upd_dump(RedisModuleCtx *ctx, index_k index_key, const arg_dname_t *origin,
                    const arg_dname_t *opt_owner, const uint16_t *opt_rtype, dump_mode_t mode)
{
	RedisModule_Assert(RedisModule_KeyType(index_key) == REDISMODULE_KEYTYPE_ZSET);

	char buf[128 * 1024];

	long count = 0;
	RedisModule_ReplyWithArray(ctx, REDISMODULE_POSTPONED_ARRAY_LEN);
	foreach_in_zset (index_key) {
		double score = 0.0;
		RedisModuleString *el = RedisModule_ZsetRangeCurrentElement(index_key, &score);
		diff_k diff_key = RedisModule_OpenKey(ctx, el, REDISMODULE_READ);
		if (diff_key == NULL) {
			RedisModule_FreeString(ctx, el);
			continue;
		}

		size_t key_strlen = 0;
		const char *key_str = RedisModule_StringPtrLen(el, &key_strlen);
		wire_ctx_t w = wire_ctx_init((uint8_t *)key_str, key_strlen);
		wire_ctx_skip(&w, RDB_PREFIX_LEN + 2 + origin->len);
		uint8_t owner_len = wire_ctx_read_u8(&w);
		knot_dname_t *owner = w.position;
		wire_ctx_skip(&w, owner_len);
		uint16_t rtype = wire_ctx_read_u16(&w);
		RedisModule_Assert(w.error == KNOT_EOK);
		RedisModule_FreeString(ctx, el);

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
		if (mode == DUMP_BIN) {
			RedisModule_ReplyWithArray(ctx, 8);
			RedisModule_ReplyWithStringBuffer(ctx, (char *)owner, owner_len);
			RedisModule_ReplyWithLongLong(ctx, rtype);
			RedisModule_ReplyWithLongLong(ctx, diff->rem_ttl);
			RedisModule_ReplyWithLongLong(ctx, diff->add_ttl);
			RedisModule_ReplyWithLongLong(ctx, diff->rem_rrs.count);
			RedisModule_ReplyWithStringBuffer(ctx, (const char *)diff->rem_rrs.rdata, diff->rem_rrs.size);
			RedisModule_ReplyWithLongLong(ctx, diff->add_rrs.count);
			RedisModule_ReplyWithStringBuffer(ctx, (const char *)diff->add_rrs.rdata, diff->add_rrs.size);
		} else {
			RedisModule_ReplyWithArray(ctx, 2);
			RedisModule_ReplyWithArray(ctx, REDISMODULE_POSTPONED_ARRAY_LEN);
			long count_sub = 0;
			knot_rrset_t rrset_out;
			knot_rrset_init(&rrset_out, owner, rtype, KNOT_CLASS_IN, diff->rem_ttl);
			rrset_out.rrs = diff->rem_rrs;
			if (dump_rrset(ctx, &rrset_out, buf, sizeof(buf), &count_sub, mode) != 0) {
				RedisModule_CloseKey(diff_key);
				break;
			}
			RedisModule_ReplySetArrayLength(ctx, count_sub);

			RedisModule_ReplyWithArray(ctx, REDISMODULE_POSTPONED_ARRAY_LEN);
			count_sub = 0;
			knot_rrset_init(&rrset_out, owner, rtype, KNOT_CLASS_IN, diff->add_ttl);
			rrset_out.rrs = diff->add_rrs;
			if (dump_rrset(ctx, &rrset_out, buf, sizeof(buf), &count_sub, mode) != 0) {
				RedisModule_CloseKey(diff_key);
				break;
			}
			RedisModule_ReplySetArrayLength(ctx, count_sub);
		}
		count++;
		RedisModule_CloseKey(diff_key);
	}
	RedisModule_ZsetRangeStop(index_key);
	RedisModule_ReplySetArrayLength(ctx, count);

	return REDISMODULE_OK;
}

static void upd_diff(RedisModuleCtx *ctx, const arg_dname_t *origin, const rdb_txn_t *txn,
                     const arg_dname_t *opt_owner, uint16_t *opt_rtype, dump_mode_t mode)
{
	int ret = get_id(ctx, origin, txn);
	if (ret < 0 || ret > UINT16_MAX) {
		RedisModule_ReplyWithError(ctx, RDB_ETXN);
		return;
	}
	uint16_t id = ret;
	index_k index_key = get_upd_index(ctx, origin, txn, id, REDISMODULE_READ | REDISMODULE_WRITE);
	if (index_key == NULL) {
		RedisModule_ReplyWithError(ctx, RDB_ECORRUPTED);
		return;
	}

	upd_dump(ctx, index_key, origin, opt_owner, opt_rtype, mode);

	RedisModule_CloseKey(index_key);
}

/*!
 * \notice The changesets are searched for in reverse order: first the surrent SOA is read from the zone and
 *         then every changeset is found by its own "serial to". From inside of the changeset, the
 *         "serial from" is gained, digging deeper into the history down to the given limit. Thanks to
 *         a trick with recursion, the changesets are in the end returned in chronological order. The
 *         serial-related params are as follows:
 *
 * \param serial_begin    The current SOA serial of the zone, where the search starts. It is the newest (highest) serial.
 * \param serial_end      The serial where the search ends, specified by the user (caller of knot.upd.load). It is the oldest (lowest) serial.
 * \param serial          The "serial to" of the changeset that is being loaded.
 */
static exception_t upd_load_serial(RedisModuleCtx *ctx, size_t *counter, const arg_dname_t *origin,
                                   const rdb_txn_t *txn, const uint32_t serial_begin, const uint32_t serial_end,
                                   const uint32_t serial, const arg_dname_t *opt_owner, const uint16_t *opt_rtype,
                                   const dump_mode_t mode)
{
	index_k upd_index_key = get_commited_upd_index(ctx, origin, txn, serial, REDISMODULE_READ);
	if (upd_index_key == NULL) {
		throw(KNOT_ENOENT, NULL);
	}

	uint32_t serial_next = 0;
	exception_t e = index_soa_serial(ctx, upd_index_key, true, &serial_next);
	if (e.ret != KNOT_EOK) {
		RedisModule_CloseKey(upd_index_key);
		raise(e);
	}

	if (serial_next != serial_end && serial_next != serial_begin) {
		e = upd_load_serial(ctx, counter, origin, txn, serial_begin,
		                    serial_end, serial_next, opt_owner,
		                    opt_rtype, mode);
		if (e.ret != KNOT_EOK) {
			RedisModule_CloseKey(upd_index_key);
			raise(e);
		}
	}

	upd_dump(ctx, upd_index_key, origin, opt_owner, opt_rtype, mode);
	++(*counter);

	RedisModule_CloseKey(upd_index_key);

	return_ok;
}

static void upd_load(RedisModuleCtx *ctx, const arg_dname_t *origin, rdb_txn_t *txn,
                     const uint32_t serial, const arg_dname_t *opt_owner,
                     const uint16_t *opt_rtype, dump_mode_t mode)
{
	if (set_active_transaction(ctx, origin, txn) != KNOT_EOK) {
		RedisModule_ReplyWithError(ctx, RDB_EZONE);
		return;
	}

	RedisModuleString *soa_rrset_keyname = rrset_keyname_construct(ctx, origin, txn, origin, KNOT_RRTYPE_SOA);
	rrset_k soa_rrset_key = RedisModule_OpenKey(ctx, soa_rrset_keyname, REDISMODULE_READ);
	RedisModule_FreeString(ctx, soa_rrset_keyname);
	rrset_v *rrset = RedisModule_ModuleTypeGetValue(soa_rrset_key);
	if (rrset == NULL) {
		RedisModule_CloseKey(soa_rrset_key);
		RedisModule_ReplyWithError(ctx, RDB_ENOSOA);
		return;
	}
	uint32_t serial_it = knot_soa_serial(rrset->rrs.rdata);
	RedisModule_CloseKey(soa_rrset_key);

	size_t counter = 0;
	RedisModule_ReplyWithArray(ctx, REDISMODULE_POSTPONED_ARRAY_LEN);
	exception_t e = upd_load_serial(ctx, &counter, origin, txn, serial_it, serial,
	                                serial_it, opt_owner, opt_rtype, mode);
	if (e.ret != KNOT_EOK && e.what != NULL) {
		RedisModule_ReplyWithError(ctx, e.what);
		counter++;
	}
	RedisModule_ReplySetArrayLength(ctx, counter);
}
