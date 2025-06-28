/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: LGPL-2.1-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <arpa/inet.h>
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

#define KNOT_ZONE_RRSET_ENCODING_VERSION 1
#define KNOT_RDB_VERSION	"\x01"
#define KNOT_RDB_PREFIX		"k" KNOT_RDB_VERSION
#define KNOT_RDB_PREFIX_LEN	(sizeof(KNOT_RDB_PREFIX) - 1)

#define KNOT_DNAME_MAXLEN 255
#define KNOT_EVENT_MAX_SIZE 10

#define RRTYPE_SOA 6

#define KNOT_SCORE_SOA     0.
#define KNOT_SCORE_DEFAULT 1.

#define INSTANCE_DEFAULT	1
#define TXN_MAX_COUNT		9

#define TXN_ID_ACTIVE	0

#define KNOT_RRSET_KEY_MAXLEN (KNOT_RDB_PREFIX_LEN + 1 + KNOT_DNAME_MAXLEN + KNOT_DNAME_MAXLEN + sizeof(uint16_t) + sizeof(uint16_t))
#define TXN_KEYNAME_MAXLEN (KNOT_RDB_PREFIX_LEN + 1 + KNOT_DNAME_MAXLEN + sizeof(uint8_t))

#define foreach_in_zset_subset(key, min, max) \
	for (RedisModule_ZsetFirstInScoreRange(key, min, max, 0, 0); \
	     RedisModule_ZsetRangeEndReached(key) == 0; \
	     RedisModule_ZsetRangeNext(key))
#define foreach_in_zset(key) foreach_in_zset_subset(key, REDISMODULE_NEGATIVE_INFINITE, REDISMODULE_POSITIVE_INFINITE)

#define knot_zone_begin(...) knot_begin(ZONE, __VA_ARGS__)
#define knot_upd_begin(...)  knot_begin(UPD_TMP, __VA_ARGS__)

#define zone_txn_init(...) txn_init(ZONE_META, __VA_ARGS__)
// #define upd_txn_init(...)  txn_init(UPD_META, __VA_ARGS__)

#define zone_meta_keyname(...) meta_keyname(ZONE_META, __VA_ARGS__)
#define upd_meta_keyname(...)  meta_keyname(UPD_META, __VA_ARGS__)

#define delete_zone_index(...)  delete_index(ZONE, __VA_ARGS__)
#define delete_upd_index(...)  delete_index(UPD_TMP, __VA_ARGS__)

#define find_zone_index(...) find_index(ZONE, __VA_ARGS__)

#define knot_upd_add(ctx, origin, origin_len, txn, owner, owner_len, ttl, rtype, rdataset) knot_upd_add_rem((ctx), (origin), (origin_len), (txn), (owner), (owner_len), (ttl), (rtype), (rdataset), false)
#define knot_upd_remove(ctx, origin, origin_len, txn, owner, owner_len, ttl, rtype, rdataset) knot_upd_add_rem((ctx), (origin), (origin_len), (txn), (owner), (owner_len), (ttl), (rtype), (rdataset), true)

static uint32_t rdb_default_ttl = 600;

typedef struct {
	uint32_t ttl;
	knot_rdataset_t rrs;
} knot_rrset_v;

typedef struct {
	knot_rdataset_t add_rrs;
	knot_rdataset_t remove_rrs;
	uint32_t dest_ttl;
} knot_diff_v;

typedef enum {
	EVENT     = 1,
	ZONE_META = 2,
	ZONE      = 3,
	RRSET     = 4,
	UPD_META  = 5,
	UPD_TMP   = 6,
	UPD       = 7,
	DIFF      = 8,
} knot_rdb_type;

typedef enum {
	ZONE_CHANGED = 1,
} knot_event_type;

static void *redismodule_alloc(void *ptr, size_t bytes);
static void redismodule_free(void *ptr);

static knot_mm_t mm = {
	.alloc = redismodule_alloc,
	.ctx = NULL,
	.free = redismodule_free
};

static RedisModuleType *knot_zone_rrset_t;
static RedisModuleType *knot_diff_t;

static RedisModuleString *meta_keyname(const uint8_t prefix, RedisModuleCtx *ctx, const uint8_t *origin, unsigned origin_len, uint8_t instance)
{
	char buf[TXN_KEYNAME_MAXLEN];

	wire_ctx_t w = wire_ctx_init((uint8_t *)buf, sizeof(buf));
	wire_ctx_write(&w, KNOT_RDB_PREFIX, KNOT_RDB_PREFIX_LEN);
	wire_ctx_write(&w, &prefix, sizeof(prefix));
	wire_ctx_write(&w, origin, origin_len);
	wire_ctx_write(&w, &instance, sizeof(instance));
	RedisModule_Assert(w.error == KNOT_EOK);

	return RedisModule_CreateString(ctx, buf, wire_ctx_offset(&w));
}

static bool txn_get_when_open2(RedisModuleCtx *ctx, const arg_dname_t *origin, const rdb_txn_t *txn, RedisModuleKey **key, int rights)
{
	assert(key != NULL && *key == NULL);

	RedisModuleString *txn_k = zone_meta_keyname(ctx, origin->data, origin->len, txn->instance);
	*key = RedisModule_OpenKey(ctx, txn_k, rights);
	RedisModule_FreeString(ctx, txn_k);
	if (key == NULL || RedisModule_KeyType(*key) != REDISMODULE_KEYTYPE_STRING) {
		return false;
	}
	size_t len = 0;
	const char *transaction = RedisModule_StringDMA(*key, &len, REDISMODULE_WRITE);
	return txn->id != transaction[0] && transaction[txn->id] != 0;
}

static bool txn_is_open2(RedisModuleCtx *ctx, const arg_dname_t *origin, const rdb_txn_t *txn)
{
	RedisModuleKey *key = NULL;
	bool out = txn_get_when_open2(ctx, origin, txn, &key, REDISMODULE_READ);
	RedisModule_CloseKey(key);
	return out;
}

static void *knot_rrset_load(RedisModuleIO *rdb, int encver)
{
	if (encver != KNOT_ZONE_RRSET_ENCODING_VERSION) {
		// TODO ignore or version compatibility layers
		return NULL;
	}

	knot_rrset_v *rrset = RedisModule_Alloc(sizeof(knot_rrset_v));
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

static void knot_rrset_save(RedisModuleIO *rdb, void *value)
{
	knot_rrset_v *rrset = (knot_rrset_v *)value;
	RedisModule_SaveUnsigned(rdb, rrset->ttl);
	RedisModule_SaveUnsigned(rdb, rrset->rrs.count);
	RedisModule_SaveStringBuffer(rdb, (const char *)rrset->rrs.rdata, rrset->rrs.size);
}

static size_t knot_rrset_mem_usage(const void *value)
{
	const knot_rrset_v *rrset = (const knot_rrset_v *)value;
	if (value == NULL) {
		return 0UL;
	}
	return sizeof(*rrset) + rrset->rrs.size;
}

static void knot_rrset_rewrite(RedisModuleIO *aof, RedisModuleString *key, void *value)
{
	size_t key_strlen = 0;
	const knot_rrset_v *rrset = (const knot_rrset_v *)value;
	const uint8_t *key_str = (const uint8_t *)RedisModule_StringPtrLen(key, &key_strlen);
	RedisModule_EmitAOF(aof, "KNOT.RRSET.AOF_REWRITE", "bllb",
	                    key_str, key_strlen,
	                    (long long)rrset->ttl,
	                    (long long)rrset->rrs.count,
	                    rrset->rrs.rdata, rrset->rrs.size);
}

static void knot_zone_rrset_free(void *value)
{
	knot_rrset_v *rrset = (knot_rrset_v *)value;
	RedisModule_Free(rrset->rrs.rdata);
	RedisModule_Free(rrset);
}

static void *knot_diff_load(RedisModuleIO *rdb, int encver)
{
	if (encver != KNOT_ZONE_RRSET_ENCODING_VERSION) {
		// TODO ignore or version compatibility layers
		return NULL;
	}

	knot_diff_v *diff = RedisModule_Alloc(sizeof(knot_diff_v));
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

static void knot_diff_save(RedisModuleIO *rdb, void *value)
{
	knot_diff_v *diff = (knot_diff_v *)value;

	RedisModule_SaveUnsigned(rdb, diff->add_rrs.count);
	RedisModule_SaveStringBuffer(rdb, (const char *)diff->add_rrs.rdata, diff->add_rrs.size);

	RedisModule_SaveUnsigned(rdb, diff->remove_rrs.count);
	RedisModule_SaveStringBuffer(rdb, (const char *)diff->remove_rrs.rdata, diff->remove_rrs.size);

	RedisModule_SaveUnsigned(rdb, diff->dest_ttl);
}

static size_t knot_diff_mem_usage(const void *value)
{
	const knot_diff_v *diff = (const knot_diff_v *)value;
	if (value == NULL) {
		return 0UL;
	}
	return sizeof(*diff) + diff->add_rrs.size + diff->remove_rrs.size;
}

static void knot_diff_rewrite(RedisModuleIO *aof, RedisModuleString *key, void *value)
{
	// size_t key_strlen = 0;
	// const knot_diff_v *diff = (const knot_diff_v *)value;

	// TODO custom command to easy/fast store

	// const uint8_t *key_str = (const uint8_t *)RedisModule_StringPtrLen(key, &key_strlen);
	// RedisModule_EmitAOF(aof, "KNOT.RRSET.AOF_REWRITE", "bllb",
	//                     key_str, key_strlen,
	//                     (long long)diff->ttl,
	//                     (long long)diff->rrs.count,
	//                     diff->rrs.rdata, diff->rrs.size);
}

static void knot_diff_free(void *value)
{
	knot_diff_v *diff = (knot_diff_v *)value;
	RedisModule_Free(diff->add_rrs.rdata);
	RedisModule_Free(diff->remove_rrs.rdata);
	RedisModule_Free(diff);
}


static int commit_event(RedisModuleCtx *ctx, knot_event_type event, ...)
{
	RedisModule_Assert(ctx != NULL);

	static uint8_t prefix = EVENT;
	char buf[KNOT_RDB_PREFIX_LEN + 1];

	wire_ctx_t w = wire_ctx_init((uint8_t *)buf, sizeof(buf));
	wire_ctx_write(&w, KNOT_RDB_PREFIX, KNOT_RDB_PREFIX_LEN);
	wire_ctx_write(&w, &prefix, sizeof(prefix));
	RedisModule_Assert(w.error == KNOT_EOK);

	RedisModuleString *keyname = RedisModule_CreateString(ctx, buf, wire_ctx_offset(&w));
	RedisModuleKey *stream_key = RedisModule_OpenKey(ctx, keyname, REDISMODULE_READ | REDISMODULE_WRITE);
	RedisModule_FreeString(ctx, keyname);

	int zone_stream_type = RedisModule_KeyType(stream_key);
	if (zone_stream_type != REDISMODULE_KEYTYPE_EMPTY && zone_stream_type != REDISMODULE_KEYTYPE_STREAM) {
		RedisModule_CloseKey(stream_key);
		return RedisModule_ReplyWithError(ctx, "ERR Bad data");
	}

	RedisModuleString *_event[KNOT_EVENT_MAX_SIZE] = {
		RedisModule_CreateString(ctx, "event", sizeof("event") - 1),
		RedisModule_CreateStringFromLongLong(ctx, event),
	};

	va_list args;
	va_start(args, event);
	RedisModuleString **_event_it = _event + 2;
	while (_event_it < _event + KNOT_EVENT_MAX_SIZE) {
		*_event_it = va_arg(args, RedisModuleString *);
		if (*_event_it == NULL) {
			break;
		}
		_event_it += 1;
	}
	int64_t size = _event_it - _event;
	if (size % 2) {
		return RedisModule_ReplyWithError(ctx, "ERR Wrong number of arguments");
	}
	va_end(args);

	RedisModuleStreamID ts;
	RedisModule_StreamAdd(stream_key, REDISMODULE_STREAM_ADD_AUTOID, &ts, _event, size / 2);

	// TODO choose right time, no older events will be available (maybe use args ???)
	ts.ms = ts.ms - 60000; // 1 minute
	ts.seq = 0;
	long long removed_cnt = RedisModule_StreamTrimByID(stream_key, REDISMODULE_STREAM_TRIM_APPROX, &ts);
	if (removed_cnt) {
		RedisModule_Log(ctx, REDISMODULE_LOGLEVEL_NOTICE, "stream trimmed %lld old events", removed_cnt);
	}
	RedisModule_CloseKey(stream_key);

	RedisModule_FreeString(ctx, _event[0]);
	RedisModule_FreeString(ctx, _event[1]);

	return REDISMODULE_OK;
}

static RedisModuleKey *find_index(const uint8_t prefix, RedisModuleCtx *ctx, const uint8_t *origin, size_t origin_len, const rdb_txn_t *txn, int rights)
{
	RedisModule_Assert(ctx != NULL && txn != NULL);

	char buf[KNOT_RDB_PREFIX_LEN + 1 + KNOT_DNAME_MAXLEN + 2];

	wire_ctx_t w = wire_ctx_init((uint8_t *)buf, sizeof(buf));
	wire_ctx_write(&w, KNOT_RDB_PREFIX, KNOT_RDB_PREFIX_LEN);
	wire_ctx_write(&w, &prefix, sizeof(prefix));
	wire_ctx_write(&w, origin, origin_len);
	wire_ctx_write(&w, txn, sizeof(*txn));
	RedisModule_Assert(w.error == KNOT_EOK);

	RedisModuleString *keyname = RedisModule_CreateString(ctx, buf, wire_ctx_offset(&w));

	RedisModuleKey *key = RedisModule_OpenKey(ctx, keyname, rights);
	RedisModule_FreeString(ctx, keyname);

	return key;
}


static RedisModuleKey *find_upd_index(RedisModuleCtx *ctx, const uint8_t *origin, size_t origin_len, const rdb_txn_t *txn, uint16_t id, int rights)
{
	const uint8_t prefix = UPD_TMP;

	RedisModule_Assert(ctx != NULL && txn != NULL);

	char buf[KNOT_RDB_PREFIX_LEN + 1 + KNOT_DNAME_MAXLEN + 2];

	wire_ctx_t w = wire_ctx_init((uint8_t *)buf, sizeof(buf));
	wire_ctx_write(&w, KNOT_RDB_PREFIX, KNOT_RDB_PREFIX_LEN);
	wire_ctx_write(&w, &prefix, sizeof(prefix));
	wire_ctx_write(&w, origin, origin_len);
	wire_ctx_write(&w, txn, sizeof(*txn));
	wire_ctx_write(&w, &id, sizeof(id));
	RedisModule_Assert(w.error == KNOT_EOK);

	RedisModuleString *keyname = RedisModule_CreateString(ctx, buf, wire_ctx_offset(&w));

	RedisModuleKey *key = RedisModule_OpenKey(ctx, keyname, rights);
	RedisModule_FreeString(ctx, keyname);

	return key;
}

static knot_dname_t *parse_dname(RedisModuleCtx *ctx, RedisModuleString *arg, knot_dname_t *out, knot_dname_t *origin)
{
	assert(ctx != NULL && arg != NULL && out != NULL);

	size_t owner_len;
	const char *owner = RedisModule_StringPtrLen(arg, &owner_len);

	if (knot_dname_from_str(out, owner, KNOT_DNAME_MAXLEN) == NULL) {
		return NULL;
	}
	knot_dname_to_lower(out);

	if (origin != NULL) {
		bool fqdn = false;
		size_t prefix_len = 0;

		if (owner_len > 0 && (owner_len != 1 || owner[0] != '@')) {
			// Check if the owner is FQDN.
			if (owner[owner_len - 1] == '.') {
				fqdn = true;
			}

			prefix_len = knot_dname_size(out);
			if (prefix_len == 0) {
				return NULL;
			}

			// Ignore trailing dot.
			prefix_len--;
		}

		// Append the origin.
		if (!fqdn) {
			size_t origin_len = knot_dname_size(origin);
			if (origin_len == 0 || origin_len > KNOT_DNAME_MAXLEN - prefix_len) {
				return NULL;
			}
			memcpy((uint8_t *)out + prefix_len, origin, origin_len);
		}
	}

	return out;
}

static double evaluate_score(uint16_t rtype)
{
	switch (rtype) {
	case RRTYPE_SOA:
		return KNOT_SCORE_SOA;
	default:
		return KNOT_SCORE_DEFAULT;
	}
}

static RedisModuleString *construct_rrset_key(RedisModuleCtx *ctx, const rdb_txn_t *txn, const knot_dname_t *origin, size_t origin_len, const knot_dname_t *owner, size_t owner_len, uint16_t rtype)
{
	uint8_t buf[KNOT_RRSET_KEY_MAXLEN];
	uint8_t prefix = RRSET;

	wire_ctx_t w = wire_ctx_init((uint8_t *)buf, sizeof(buf));
	wire_ctx_write(&w, KNOT_RDB_PREFIX, KNOT_RDB_PREFIX_LEN);
	wire_ctx_write(&w, &prefix, sizeof(prefix));
	wire_ctx_write(&w, origin, origin_len);
	wire_ctx_write(&w, owner, owner_len);
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

static RedisModuleKey *get_rrset_key(RedisModuleCtx *ctx, const rdb_txn_t *txn,
                                     size_t origin_len, const uint8_t *origin,
                                     size_t owner_len, const uint8_t *owner, uint16_t rtype)
{
	RedisModuleKey *zone_key = find_zone_index(ctx, origin, origin_len, txn, REDISMODULE_READ | REDISMODULE_WRITE);
	int zone_keytype = RedisModule_KeyType(zone_key);
	if (zone_keytype != REDISMODULE_KEYTYPE_EMPTY &&
	    zone_keytype != REDISMODULE_KEYTYPE_ZSET) {
		RedisModule_CloseKey(zone_key);
		RedisModule_ReplyWithError(ctx, "ERR Bad data");
		return NULL;
	}

	RedisModuleString *rrset_keystr = construct_rrset_key(ctx, txn, origin, origin_len, owner, owner_len, rtype);

	RedisModule_ZsetAdd(zone_key, evaluate_score(rtype), rrset_keystr, NULL);
	RedisModule_CloseKey(zone_key);

	RedisModuleKey *rrset_key = RedisModule_OpenKey(ctx, rrset_keystr, REDISMODULE_READ | REDISMODULE_WRITE);
	RedisModule_FreeString(ctx, rrset_keystr);
	return rrset_key;
}

static int rdata_add(RedisModuleCtx *ctx, const rdb_txn_t *txn,
                     size_t origin_len, const uint8_t *origin,
                     size_t owner_len, const uint8_t *owner, uint16_t rtype,
                     uint32_t ttl, const knot_rdata_t *rdata)
{
	RedisModuleKey *rrset_key = get_rrset_key(ctx, txn, origin_len, origin, owner_len, owner, rtype);
	if (rrset_key == NULL) {
		return -1;
	}

	knot_rrset_v *rrset = NULL;
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
	} else if (RedisModule_ModuleTypeGetType(rrset_key) == knot_zone_rrset_t) {
		rrset = RedisModule_ModuleTypeGetValue(rrset_key);
	} else {
		RedisModule_CloseKey(rrset_key);
		RedisModule_ReplyWithError(ctx, "ERR Bad data");
		return -1;
	}
	rrset->ttl = ttl;

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
                     size_t origin_len, const uint8_t *origin, size_t owner_len,
                     const uint8_t *owner, uint16_t rtype, uint32_t ttl,
                     const knot_rdata_t *rdata)
{
	RedisModuleKey *zone_key = find_zone_index(ctx, origin, origin_len, txn, REDISMODULE_READ | REDISMODULE_WRITE);
	int zone_keytype = RedisModule_KeyType(zone_key);
	if (zone_keytype != REDISMODULE_KEYTYPE_EMPTY &&
	    zone_keytype != REDISMODULE_KEYTYPE_ZSET) {
		RedisModule_CloseKey(zone_key);
		RedisModule_ReplyWithError(ctx, "ERR Bad data");
		return -1;
	}

	RedisModuleString *rrset_keystr = construct_rrset_key(ctx, txn, origin, origin_len, owner, owner_len, rtype);

	RedisModuleKey *rrset_key = RedisModule_OpenKey(ctx, rrset_keystr, REDISMODULE_READ | REDISMODULE_WRITE);
	RedisModule_FreeString(ctx, rrset_keystr);

	knot_rrset_v *rrset = NULL;
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

	if (rrset->rrs.count == 0) {
		RedisModule_DeleteKey(rrset_key);
		RedisModule_ZsetRem(zone_key, rrset_keystr, NULL);
	}
	RedisModule_CloseKey(zone_key);

	RedisModule_CloseKey(rrset_key);

	return 0;
}

// [active_txn][1-9]
static int txn_init(const uint8_t prefix, RedisModuleCtx *ctx, rdb_txn_t *txn, const uint8_t *zone, size_t zone_len)
{
	assert(txn->instance != 0);

	RedisModuleString *keyname = meta_keyname(prefix, ctx, zone, zone_len, txn->instance);
	if (keyname == NULL) {
		RedisModule_ReplyWithError(ctx, "ERR failed to initialize transaction");
		return 0;
	}

	RedisModuleKey *key = RedisModule_OpenKey(ctx, keyname, REDISMODULE_WRITE);
	RedisModule_FreeString(ctx, keyname);

	int keytype = RedisModule_KeyType(key);
	if (keytype == REDISMODULE_KEYTYPE_EMPTY) {
		RedisModule_StringTruncate(key, 1 + TXN_MAX_COUNT);
	} else if (keytype != REDISMODULE_KEYTYPE_STRING) {
		RedisModule_CloseKey(key);
		RedisModule_ReplyWithError(ctx, "ERR Bad data");
		return KNOT_EINVAL;
	}

	size_t len;
	char *str = RedisModule_StringDMA(key, &len, REDISMODULE_WRITE);
	if (str == NULL || len != 1 + TXN_MAX_COUNT) {
		RedisModule_CloseKey(key);
		RedisModule_ReplyWithError(ctx, "ERR Bad data");
		return KNOT_EINVAL;
	}

	for (txn->id = 1; txn->id <= TXN_MAX_COUNT; txn->id++) {
		if (str[txn->id] == 0) {
			str[txn->id] = 1;
			break;
		}
	}
	RedisModule_CloseKey(key);
	if (txn->id > TXN_MAX_COUNT) {
		RedisModule_ReplyWithError(ctx, "ERR too many transactions");
		return KNOT_EBUSY;
	}

	return KNOT_EOK;
}

typedef struct {
	uint16_t counter;
	uint16_t lock[TXN_MAX_COUNT];
} upd_meta_storage_t;

static int upd_txn_init(RedisModuleCtx *ctx, rdb_txn_t *txn, const uint8_t *zone, size_t zone_len)
{
	static const uint8_t prefix = UPD_META;

	assert(txn->instance != 0);

	RedisModuleString *keyname = meta_keyname(prefix, ctx, zone, zone_len, txn->instance);
	if (keyname == NULL) {
		RedisModule_ReplyWithError(ctx, "ERR failed to initialize transaction");
		return 0;
	}

	RedisModuleKey *key = RedisModule_OpenKey(ctx, keyname, REDISMODULE_WRITE);
	RedisModule_FreeString(ctx, keyname);

	int keytype = RedisModule_KeyType(key);
	if (keytype == REDISMODULE_KEYTYPE_EMPTY) {
		RedisModule_StringTruncate(key, sizeof(upd_meta_storage_t));
	} else if (keytype != REDISMODULE_KEYTYPE_STRING) {
		RedisModule_CloseKey(key);
		RedisModule_ReplyWithError(ctx, "ERR Bad data");
		return KNOT_EINVAL;
	}

	size_t len;
	upd_meta_storage_t *storage = (upd_meta_storage_t *)RedisModule_StringDMA(key, &len, REDISMODULE_WRITE);
	if (storage == NULL || len != sizeof(upd_meta_storage_t)) {
		RedisModule_CloseKey(key);
		RedisModule_ReplyWithError(ctx, "ERR Bad data");
		return KNOT_EINVAL;
	}

	for (txn->id = 0; txn->id < TXN_MAX_COUNT; ++txn->id) {
		if (storage->lock[txn->id] == 0) {
			storage->lock[txn->id] = ++storage->counter;
			break;
		}
	}
	RedisModule_CloseKey(key);
	if (txn->id >= TXN_MAX_COUNT) {
		RedisModule_ReplyWithError(ctx, "ERR too many transactions");
		return KNOT_EBUSY;
	}

	return KNOT_EOK;
}

static uint8_t parse_instance(RedisModuleString *arg)
{
	size_t len;
	const char *data = RedisModule_StringPtrLen(arg, &len);
	if (len != 1 || *data < '1' || *data > '9') {
		return 0;
	} else {
		return *data - '0';
	}
}

static int parse_transaction(RedisModuleString *arg, rdb_txn_t *txn)
{
	assert(txn != NULL);

	size_t len;
	const char *data = RedisModule_StringPtrLen(arg, &len);
	if (len != 2){
		return KNOT_EINVAL;
	}
	uint8_t *txn_b = (uint8_t *)txn;
	for (int idx = 0; idx < len; ++idx) {
		if (data[idx] < '0' || data[idx] > '9') {
			return KNOT_EINVAL;
		}
		txn_b[idx] = (data[idx] - '0');
	}
	return KNOT_EOK;
}

static int parse_transaction2(RedisModuleString *arg, rdb_txn_t *txn)
{
	assert(txn != NULL);

	txn->id = TXN_ID_ACTIVE;

	size_t len;
	const char *data = RedisModule_StringPtrLen(arg, &len);
	switch (len) {
	case 2:
		if (data[1] < '0' || data[1] > '9') {
			return KNOT_EMALF;
		}
		txn->id = data[1] - '0';
	case 1: // FALLTHROUGH
		if (data[0] < '0' || data[0] > '9') {
			return KNOT_EMALF;
		}
		txn->instance = data[0] - '0';
		return KNOT_EOK;
	default:
		return EINVAL;
	}
}

static int parse_rtype(uint16_t *rtype, const RedisModuleString *source)
{
	assert(rtype != NULL);

	size_t len;
	const char *rtype_str = RedisModule_StringPtrLen(source, &len);
	return knot_rrtype_from_string(rtype_str, rtype);
}

static int serialize_transaction(const rdb_txn_t *txn)
{
	return 10 * txn->instance + txn->id;
}

static int active_transaction(RedisModuleCtx *ctx, const uint8_t *origin, rdb_txn_t *txn)
{
	assert(txn->instance > 0);

	size_t origin_dname_len = knot_dname_size(origin);
	RedisModuleString *txn_k = zone_meta_keyname(ctx, origin, origin_dname_len, txn->instance);
	RedisModuleKey *key = RedisModule_OpenKey(ctx, txn_k, REDISMODULE_READ);
	RedisModule_FreeString(ctx, txn_k);
	if (key == NULL || RedisModule_KeyType(key) != REDISMODULE_KEYTYPE_STRING) {
		return KNOT_EMALF;
	}
	size_t len = 0;
	const char *transaction = RedisModule_StringDMA(key, &len, REDISMODULE_READ);
	if (transaction[0] != 0) {
		txn->id = transaction[0];
		return KNOT_EOK;
	}
	return KNOT_EEXIST;
}

static int get_id(RedisModuleCtx *ctx, const knot_dname_t *origin, const rdb_txn_t *txn)
{
	RedisModuleString *txn_k = upd_meta_keyname(ctx, origin, knot_dname_size(origin), txn->instance);
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

static void delete_index(const uint8_t prefix, RedisModuleCtx *ctx, const rdb_txn_t *txn, const uint8_t *origin, size_t origin_len)
{
	RedisModule_Assert(ctx != NULL && txn != NULL);

	RedisModuleKey *index_key = NULL;
	switch (prefix) {
	case ZONE:
		index_key = find_zone_index(ctx, origin, origin_len, txn, REDISMODULE_READ | REDISMODULE_WRITE);
		break;
	case UPD_TMP:;
		int ret = get_id(ctx, origin, txn);
		if (ret < 0 || ret > UINT16_MAX) {
			RedisModule_ReplyWithError(ctx, "Unknown transaction ID");
			return;
		}
		uint16_t id = ret;
		index_key = find_upd_index(ctx, origin, origin_len, txn, id, REDISMODULE_READ | REDISMODULE_WRITE);
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

static bool txn_get_when_open(RedisModuleCtx *ctx, const knot_dname_t *origin_dname, const rdb_txn_t *txn, RedisModuleKey **key, int rights)
{
	assert(key != NULL && *key == NULL);

	size_t origin_dname_len = knot_dname_size(origin_dname);
	RedisModuleString *txn_k = zone_meta_keyname(ctx, origin_dname, origin_dname_len, txn->instance);
	*key = RedisModule_OpenKey(ctx, txn_k, rights);
	RedisModule_FreeString(ctx, txn_k);
	if (key == NULL || RedisModule_KeyType(*key) != REDISMODULE_KEYTYPE_STRING) {
		return false;
	}
	size_t len = 0;
	const char *transaction = RedisModule_StringDMA(*key, &len, REDISMODULE_WRITE);
	return txn->id != transaction[0] && transaction[txn->id] != 0;
}


static bool txn_is_open(RedisModuleCtx *ctx, const knot_dname_t *origin_dname, const rdb_txn_t *txn)
{
	RedisModuleKey *key = NULL;
	bool out = txn_get_when_open(ctx, origin_dname, txn, &key, REDISMODULE_READ);
	RedisModule_CloseKey(key);
	return out;
}

static int knot_rrset_aof_rewrite(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 5) {
		return RedisModule_WrongArity(ctx);
	}

	knot_rrset_v *rrset = RedisModule_Calloc(1, sizeof(knot_rrset_v));
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
	RedisModule_ReplyWithNull(ctx);

	return REDISMODULE_OK;
}

static int knot_begin(const uint8_t prefix, RedisModuleCtx *ctx, rdb_txn_t *txn, const uint8_t *zone, int zone_len)
{
	int ret = KNOT_EOK;
	switch (prefix) {
	case ZONE:
		ret = zone_txn_init(ctx, txn, zone, zone_len);
		delete_zone_index(ctx, txn, zone, zone_len);
		break;
	case UPD_TMP:
		ret = upd_txn_init(ctx, txn, zone, zone_len);
		delete_upd_index(ctx, txn, zone, zone_len);
		break;
	default:
		return KNOT_ENOTSUP;
	}
	if (ret != KNOT_EOK) {
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

// <zone_name> [<instance_id=1>]
static int knot_zone_begin_txt(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	rdb_txn_t txn = { .instance = 1 };
	knot_dname_storage_t zone;

	switch (argc) {
	case 3:
		if ((txn.instance = parse_instance(argv[2])) == 0) {
			return RedisModule_ReplyWithError(ctx, "ERR invalid zone instance");
		}
	case 2: // FALLTHROUGH
		if (parse_dname(ctx, argv[1], zone, NULL) == NULL) {
			return RedisModule_ReplyWithError(ctx, "ERR invalid zone name");
		}
		break;
	default:
		return RedisModule_WrongArity(ctx);
	}

	int ret = knot_zone_begin(ctx, &txn, zone, knot_dname_size(zone));
	if (ret != KNOT_EOK) {
		return REDISMODULE_OK;
	}

	return RedisModule_ReplyWithLongLong(ctx, serialize_transaction(&txn));
}

static int knot_zone_begin_bin(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	rdb_txn_t txn = { .instance = 1 };
	knot_dname_storage_t *zone = NULL;
	size_t zone_len = 0;

	switch (argc) {
	case 3:;
		size_t instance_len = 0;
		const char *txn_bin = (const char *)RedisModule_StringPtrLen(argv[2], &instance_len);
		if (instance_len != 1) {
			return RedisModule_ReplyWithError(ctx, "ERR invalid zone instance");
		}
		txn.instance = txn_bin[0];
	case 2: // FALLTHROUGH
		zone = (knot_dname_storage_t *)RedisModule_StringPtrLen(argv[1], &zone_len);
		if (zone_len > KNOT_DNAME_MAXLEN) {
			return RedisModule_ReplyWithError(ctx, "ERR invalid zone name");
		}
		break;
	default:
		return RedisModule_WrongArity(ctx);
	}
	assert(zone != NULL && zone_len > 0);

	if (knot_zone_begin(ctx, &txn, *zone, zone_len) != KNOT_EOK) {
		return REDISMODULE_ERR;
	}

	return RedisModule_ReplyWithStringBuffer(ctx, (const char *)&txn, sizeof(txn));
}

typedef struct {
	RedisModuleCtx *ctx;
	rdb_txn_t *txn;
	bool replied;
	bool remove;
} scanner_ctx_t;

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

	int ret = rdata_add(s_ctx->ctx, s_ctx->txn, s->zone_origin_length,
	                    s->zone_origin, s->r_owner_length, s->r_owner,
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

static int knot_zone_store_txt(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 4) {
		return RedisModule_WrongArity(ctx);
	}

	arg_dname_t origin;
	ARG_DNAME_TXT(argv[1], origin, NULL, "origin");

	rdb_txn_t txn;
	ARG_TXN_TXT(argv[2], txn, ctx, origin);

	void *zone_data;
	size_t data_len;
	ARG_DATA(argv[3], data_len, zone_data, "zone data");

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

	return RedisModule_ReplyWithSimpleString(ctx, RDB_OK);
}

static int knot_zone_store_bin(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 8) {
		return RedisModule_WrongArity(ctx);
	}

	arg_dname_t origin;
	ARG_DNAME(argv[1], origin, "origin");

	rdb_txn_t txn;
	ARG_TXN(argv[2], txn, ctx, origin);

	arg_dname_t owner;
	ARG_DNAME(argv[3], owner, "owner");

	uint32_t ttl;
	ARG_NUM(argv[4], ttl, "TTL");

	uint16_t rtype;
	ARG_NUM(argv[5], rtype, "record type");

	uint16_t rcount;
	ARG_NUM(argv[6], rcount, "record count");

	uint8_t *rdataset;
	size_t rdataset_len;
	ARG_DATA(argv[7], rdataset_len, rdataset, "rdataset");

	RedisModuleKey *rrset_key = get_rrset_key(ctx, &txn, origin.len, origin.data, owner.len, owner.data, rtype);
	if (rrset_key == NULL) {
		return REDISMODULE_OK;
	}
	if (RedisModule_KeyType(rrset_key) != REDISMODULE_KEYTYPE_EMPTY) {
		RedisModule_CloseKey(rrset_key);
		return RedisModule_ReplyWithError(ctx, "ERR non-empty RRset");
	}

	knot_rrset_v *rrset = RedisModule_Calloc(1, sizeof(*rrset));
	if (rrset == NULL) {
		RedisModule_CloseKey(rrset_key);
		return RedisModule_ReplyWithError(ctx, "ERR failed to allocate memory");
	}
	rrset->ttl = ttl;

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

	return RedisModule_ReplyWithSimpleString(ctx, RDB_OK);
}

static int knot_zone_commit(RedisModuleCtx *ctx, knot_dname_t *origin, rdb_txn_t *txn)
{
	RedisModuleKey *meta_key = NULL;
	if (txn_get_when_open(ctx, origin, txn, &meta_key, REDISMODULE_READ | REDISMODULE_WRITE) == false) {
		RedisModule_CloseKey(meta_key);
		RedisModule_ReplyWithError(ctx, "ERR Non-existent transaction");
		return KNOT_ENOENT;
	}

	size_t origin_len = knot_dname_size(origin);
	RedisModuleKey *zone_key = find_zone_index(ctx, origin, origin_len, txn, REDISMODULE_READ | REDISMODULE_WRITE);

	size_t soa_cnt = 0;
	foreach_in_zset_subset(zone_key, KNOT_SCORE_SOA, KNOT_SCORE_SOA) {
		double score = 0.0;
		RedisModuleString *el = RedisModule_ZsetRangeCurrentElement(zone_key, &score);
		if (el == NULL) {
			break;
		}

		++soa_cnt;
	}
	if (soa_cnt != 1) {
		RedisModule_CloseKey(meta_key);
		RedisModule_CloseKey(zone_key);
		RedisModule_ReplyWithError(ctx, "ERR Missing SOA");
		return KNOT_ENOENT;
	}
	RedisModule_CloseKey(zone_key);

	size_t len = 0;
	char *meta = RedisModule_StringDMA(meta_key, &len, REDISMODULE_WRITE);
	uint8_t active_old = meta[0];
	if (active_old) {
		rdb_txn_t txn_old = {
			.instance = txn->instance,
			.id = active_old
		};
		delete_zone_index(ctx, &txn_old, origin, origin_len);
		meta[active_old] = 0;
	}
	meta[0] = txn->id;
	// NOTE need to keep current transaction locked while active

	RedisModule_CloseKey(meta_key);

	RedisModuleString *origin_k = RedisModule_CreateString(ctx, "origin", sizeof("origin") - 1);
	RedisModuleString *origin_v = RedisModule_CreateString(ctx, (char *)origin, origin_len);
	(void)commit_event(ctx, ZONE_CHANGED, origin_k, origin_v, NULL);
	RedisModule_FreeString(ctx, origin_k);
	RedisModule_FreeString(ctx, origin_v);

	return KNOT_EOK;
}

static int knot_zone_commit_txt(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 3) {
		return RedisModule_WrongArity(ctx);
	}

	knot_dname_storage_t origin;
	rdb_txn_t txn;
	parse_dname(ctx, argv[1], origin, NULL);
	int ret = parse_transaction(argv[2], &txn);

	if (ret != KNOT_EOK) {
		return RedisModule_ReplyWithError(ctx, "Malformed transaction");
	}

	RedisModuleKey *meta_key = NULL;
	if (txn_get_when_open(ctx, origin, &txn, &meta_key, REDISMODULE_READ | REDISMODULE_WRITE) == false) {
		RedisModule_CloseKey(meta_key);
		return RedisModule_ReplyWithError(ctx, "Non-existent transaction");
	}

	knot_zone_commit(ctx, origin, &txn);

	return RedisModule_ReplyWithSimpleString(ctx, "OK");
}

static int knot_zone_commit_bin(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 3) {
		return RedisModule_WrongArity(ctx);
	}

	size_t origin_len = 0, txn_len = 0;
	knot_dname_storage_t *origin = (knot_dname_storage_t *)RedisModule_StringPtrLen(argv[1], &origin_len);
	rdb_txn_t *txn = (rdb_txn_t *)RedisModule_StringPtrLen(argv[2], &txn_len);

	if (origin_len > KNOT_DNAME_MAXLEN) {
		return RedisModule_ReplyWithError(ctx, "Malformed origin");
	}
	if (txn_len != sizeof(*txn)) {
		return RedisModule_ReplyWithError(ctx, "Malformed transaction");
	}

	knot_zone_commit(ctx, *origin, txn);

	return RedisModule_ReplyWithSimpleString(ctx, "OK");
}

static int knot_zone_abort(RedisModuleCtx *ctx, knot_dname_t *origin, rdb_txn_t *txn)
{
	RedisModuleKey *meta_key = NULL;
	if (txn_get_when_open(ctx, origin, txn, &meta_key, REDISMODULE_READ | REDISMODULE_WRITE) == false) {
		RedisModule_CloseKey(meta_key);
		RedisModule_ReplyWithError(ctx, "Non-existent transaction");
		return KNOT_ENOENT;
	}

	size_t len = 0;
	char *meta = RedisModule_StringDMA(meta_key, &len, REDISMODULE_WRITE);
	meta[txn->id] = 0;

	RedisModule_CloseKey(meta_key);

	delete_zone_index(ctx, txn, origin, knot_dname_size(origin));

	return KNOT_EOK;
}

static int knot_zone_abort_txt(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 3) {
		return RedisModule_WrongArity(ctx);
	}

	knot_dname_storage_t origin;
	rdb_txn_t txn;
	parse_dname(ctx, argv[1], origin, NULL);
	int ret = parse_transaction(argv[2], &txn);

	if (ret != KNOT_EOK) {
		return RedisModule_ReplyWithError(ctx, "Malformed transaction");
	}

	if (knot_zone_abort(ctx, origin, &txn) != KNOT_EOK) {
		return REDISMODULE_OK;
	}

	return RedisModule_ReplyWithSimpleString(ctx, "OK");
}

static int knot_zone_abort_bin(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 3) {
		return RedisModule_WrongArity(ctx);
	}

	size_t origin_len = 0, txn_len = 0;
	knot_dname_storage_t *origin = (knot_dname_storage_t *)RedisModule_StringPtrLen(argv[1], &origin_len);
	rdb_txn_t *txn = (rdb_txn_t *)RedisModule_StringPtrLen(argv[2], &txn_len);

	if (origin_len > KNOT_DNAME_MAXLEN) {
		return RedisModule_ReplyWithError(ctx, "Malformed origin");
	}
	if (txn_len != sizeof(*txn)) {
		return RedisModule_ReplyWithError(ctx, "Malformed transaction");
	}

	if (knot_zone_abort(ctx, *origin, txn) != KNOT_EOK) {
		return REDISMODULE_OK;
	}

	return RedisModule_ReplyWithSimpleString(ctx, "OK");
}

static int knot_zone_exists(RedisModuleCtx *ctx, knot_dname_t *origin, size_t origin_len, rdb_txn_t *txn)
{
	if (txn->id == TXN_ID_ACTIVE) {
		int ret = active_transaction(ctx, origin, txn);
		if (ret != KNOT_EOK) {
			return RedisModule_ReplyWithError(ctx, "ERR unknown instance");
		}
	}

	RedisModuleKey *zone_key = find_zone_index(ctx, origin, origin_len, txn, REDISMODULE_READ);
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

	foreach_in_zset_subset(zone_key, KNOT_SCORE_SOA, KNOT_SCORE_SOA) {
		double score = 0.0;
		RedisModuleString *el = RedisModule_ZsetRangeCurrentElement(zone_key, &score);
		if (el == NULL) {
			break;
		}

		RedisModuleKey *rrset_key = RedisModule_OpenKey(ctx, el, REDISMODULE_READ);
		if (rrset_key == NULL) {
			continue;
		}

		knot_rrset_v *rrset = RedisModule_ModuleTypeGetValue(rrset_key);
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

static int knot_zone_exists_txt(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	rdb_txn_t txn = {
		.instance = 1,
		.id = TXN_ID_ACTIVE
	};
	knot_dname_storage_t origin;

	switch (argc) {
	case 3:
		if ((txn.instance = parse_instance(argv[2])) == 0) {
			return RedisModule_ReplyWithError(ctx, "ERR invalid zone instance");
		}
	case 2: // FALLTHROUGH
		if (parse_dname(ctx, argv[1], origin, NULL) == NULL) {
			return RedisModule_ReplyWithError(ctx, "ERR invalid zone name");
		}
		break;
	default:
		return RedisModule_WrongArity(ctx);
	}

	knot_zone_exists(ctx, origin, knot_dname_size(origin), &txn);
	return REDISMODULE_OK;
}

static int knot_zone_exists_bin(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	rdb_txn_t txn = {
		.instance = 1,
		.id = TXN_ID_ACTIVE
	};

	size_t origin_len = 0, txn_len = 0;
	knot_dname_t *origin = NULL;

	switch (argc) {
	case 3:; // FALLTHROUGH
		const char *txn_recv = RedisModule_StringPtrLen(argv[2], &txn_len);
		if (txn_len < 1 || txn_len > 2) {
			return RedisModule_ReplyWithError(ctx, "Malformed transaction");
		}
		memcpy(&txn, txn_recv, txn_len);
	case 2: // FALLTHROUGH
		origin = (knot_dname_t *)RedisModule_StringPtrLen(argv[1], &origin_len);
		if (origin_len > KNOT_DNAME_MAXLEN) {
			return RedisModule_ReplyWithError(ctx, "Malformed origin");
		}
		break;
	default:
		return RedisModule_WrongArity(ctx);
	}

	knot_zone_exists(ctx, origin, origin_len, &txn);
	return REDISMODULE_OK;
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

static int knot_zone_load(RedisModuleCtx *ctx, knot_dname_t *origin, size_t origin_len, rdb_txn_t *txn, knot_dname_t *opt_owner, uint16_t *opt_rtype, bool txt)
{
	if (txn->id == TXN_ID_ACTIVE) {
		int ret = active_transaction(ctx, origin, txn);
		if (ret != KNOT_EOK) {
			return RedisModule_ReplyWithError(ctx, "ERR unknown instance");
		}
	}

	RedisModuleKey *index_key = find_zone_index(ctx, origin, origin_len, txn, REDISMODULE_READ);
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
	size_t opt_owner_len = (opt_owner != NULL) ? knot_dname_size(opt_owner) : 0;

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
		wire_ctx_skip(&w, KNOT_RDB_PREFIX_LEN + 1);
		wire_ctx_skip(&w, origin_len);
		knot_dname_t *owner = w.position;
		size_t owner_len = knot_dname_size(owner);
		wire_ctx_skip(&w, owner_len);
		uint16_t rtype = wire_ctx_read_u16(&w);
		RedisModule_Assert(w.error == KNOT_EOK);

		if (opt_owner != NULL &&
		    (opt_owner_len != owner_len || memcmp(owner, opt_owner, owner_len) != 0)) {
			RedisModule_CloseKey(rrset_key);
			continue;
		}
		if (opt_rtype != NULL && rtype != *opt_rtype) {
			RedisModule_CloseKey(rrset_key);
			continue;
		}

		knot_rrset_v *rrset_v = RedisModule_ModuleTypeGetValue(rrset_key);

		if (txt) {
			knot_rrset_t rrset;
			knot_rrset_init(&rrset, owner, rtype, KNOT_CLASS_IN, rrset_v->ttl);
			rrset.rrs = rrset_v->rrs;
			if (dump_rrset(ctx, &rrset, buf, sizeof(buf), &count, false) != 0) {
				RedisModule_CloseKey(rrset_key);
				break;
			}
		} else {
			RedisModule_ReplyWithArray(ctx, 5);
			RedisModule_ReplyWithStringBuffer(ctx, (char *)owner, owner_len);
			RedisModule_ReplyWithLongLong(ctx, rtype);
			RedisModule_ReplyWithLongLong(ctx, rrset_v->ttl);
			RedisModule_ReplyWithLongLong(ctx, rrset_v->rrs.count);
			RedisModule_ReplyWithStringBuffer(ctx, (const char *)rrset_v->rrs.rdata, rrset_v->rrs.size);
			count++;
		}
		RedisModule_CloseKey(rrset_key);
	}
	RedisModule_ZsetRangeStop(index_key);
	RedisModule_CloseKey(index_key);
	RedisModule_ReplySetArrayLength(ctx, count);

	return REDISMODULE_OK;
}

static int knot_zone_load_txt(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	knot_dname_storage_t origin;
	rdb_txn_t txn = {
		.instance = 1,
		.id = TXN_ID_ACTIVE
	};
	knot_dname_storage_t owner;
	uint16_t rtype = 0;

	// Origin must be parsed before owner!
	if (argc > 1) {
		if (parse_dname(ctx, argv[1], origin, NULL) == NULL) {
			return RedisModule_ReplyWithError(ctx, "ERR invalid zone name");
		}
	}

	switch (argc) {
	case 5:
		if (parse_rtype(&rtype, argv[4]) != KNOT_EOK) {
			return RedisModule_ReplyWithError(ctx, "ERR invalid rtype");
		}
	case 4: // FALLTHROUGH
		if (parse_dname(ctx, argv[3], owner, origin) == NULL) {
			return RedisModule_ReplyWithError(ctx, "ERR invalid owner");
		}
	case 3: // FALLTHROUGH
		if (parse_transaction2(argv[2], &txn) != KNOT_EOK) {
			return RedisModule_ReplyWithError(ctx, "ERR invalid zone instance");
		}
		break;
	default:
		return RedisModule_WrongArity(ctx);
	}

	knot_zone_load(ctx, origin, knot_dname_size(origin), &txn,
	               (argc >= 4) ? owner : NULL, (argc >= 5) ? &rtype : NULL,
	               true);

	return REDISMODULE_OK;
}

static int knot_zone_load_bin(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	rdb_txn_t txn = {
		.instance = 1,
		.id = TXN_ID_ACTIVE
	};

	size_t origin_len = 0, txn_len = 0, owner_len = 0, rtype_len = 0;
	knot_dname_t *origin = NULL, *owner = NULL;
	uint16_t rtype;

	switch (argc) {
	case 5:;
		const char *rtype_str = RedisModule_StringPtrLen(argv[4], &rtype_len);
		if (rtype_len != sizeof(rtype)) {
			return RedisModule_ReplyWithError(ctx, "Malformed rtype");
		}
		memcpy(&rtype, rtype_str, rtype_len);
	case 4: // FALLTHROUGH
		owner = (knot_dname_t *)RedisModule_StringPtrLen(argv[3], &owner_len);
		if (owner_len > KNOT_DNAME_MAXLEN) {
			return RedisModule_ReplyWithError(ctx, "Malformed owner");
		}
	case 3:; // FALLTHROUGH
		const char *txn_recv = RedisModule_StringPtrLen(argv[2], &txn_len);
		if (txn_len < 1 || txn_len > 2) {
			return RedisModule_ReplyWithError(ctx, "Malformed transaction");
		}
		memcpy(&txn, txn_recv, txn_len);
	case 2: // FALLTHROUGH
		origin = (knot_dname_t *)RedisModule_StringPtrLen(argv[1], &origin_len);
		if (origin_len > KNOT_DNAME_MAXLEN) {
			return RedisModule_ReplyWithError(ctx, "Malformed origin");
		}
		break;
	default:
		return RedisModule_WrongArity(ctx);
	}

	knot_zone_load(ctx, origin, origin_len, &txn,
	               (argc >= 4) ? owner : NULL, (argc >= 5) ? &rtype : NULL,
	               false);

	return REDISMODULE_OK;
}

static int knot_upd_begin_txt(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	rdb_txn_t txn = { .instance = 1 };
	knot_dname_storage_t zone;

	switch (argc) {
	case 3:
		if ((txn.instance = parse_instance(argv[2])) == 0) {
			return RedisModule_ReplyWithError(ctx, "ERR invalid zone instance");
		}
	case 2: // FALLTHROUGH
		if (parse_dname(ctx, argv[1], zone, NULL) == NULL) {
			return RedisModule_ReplyWithError(ctx, "ERR invalid zone name");
		}
		break;
	default:
		return RedisModule_WrongArity(ctx);
	}

	int ret = knot_upd_begin(ctx, &txn, zone, knot_dname_size(zone));
	if (ret != KNOT_EOK) {
		return REDISMODULE_OK;
	}

	return RedisModule_ReplyWithLongLong(ctx, serialize_transaction(&txn));
}

static bool upd_meta_get_when_open(RedisModuleCtx *ctx, const knot_dname_t *origin_dname, const rdb_txn_t *txn, RedisModuleKey **key, int rights)
{
	assert(key != NULL && *key == NULL);

	size_t origin_dname_len = knot_dname_size(origin_dname);
	RedisModuleString *txn_k = upd_meta_keyname(ctx, origin_dname, origin_dname_len, txn->instance);
	*key = RedisModule_OpenKey(ctx, txn_k, rights);
	RedisModule_FreeString(ctx, txn_k);
	if (key == NULL || RedisModule_KeyType(*key) != REDISMODULE_KEYTYPE_STRING) {
		return false;
	}
	size_t len = 0;
	const upd_meta_storage_t *transaction = (const upd_meta_storage_t *)RedisModule_StringDMA(*key, &len, REDISMODULE_WRITE);
	return transaction->lock[txn->id] != 0;
}

static RedisModuleString *construct_diff_key(RedisModuleCtx *ctx, const knot_dname_t *origin, size_t origin_len, const rdb_txn_t *txn, const knot_dname_t *owner, size_t owner_len, uint16_t rtype, uint16_t id)
{
	RedisModule_Assert(ctx != NULL && txn != NULL);

	uint8_t prefix = DIFF;
	char buf[KNOT_RRSET_KEY_MAXLEN];

	wire_ctx_t w = wire_ctx_init((uint8_t *)buf, sizeof(buf));
	wire_ctx_write(&w, KNOT_RDB_PREFIX, KNOT_RDB_PREFIX_LEN);
	wire_ctx_write(&w, &prefix, sizeof(prefix));
	wire_ctx_write(&w, origin, origin_len);
	wire_ctx_write(&w, owner, owner_len);
	wire_ctx_write(&w, &rtype, sizeof(rtype));
	wire_ctx_write(&w, txn, sizeof(*txn));
	wire_ctx_write(&w, &id, sizeof(id));

	RedisModule_Assert(w.error == KNOT_EOK);

	return RedisModule_CreateString(ctx, buf, wire_ctx_offset(&w));
}

static int knot_upd_add_rem(RedisModuleCtx *ctx, const knot_dname_t *origin, const size_t origin_len, const rdb_txn_t *txn, const knot_dname_t *owner, const size_t owner_len, const uint32_t ttl, const uint16_t rtype, const knot_rdata_t *rdataset, const bool remove)
{
	int ret = get_id(ctx, origin, txn);
	if (ret < 0 || ret > UINT16_MAX) {
		return RedisModule_ReplyWithError(ctx, "Unknown transaction ID");
	}
	uint16_t id = ret;

	RedisModuleString *diff_keystr = construct_diff_key(ctx, origin, origin_len, txn, owner, knot_dname_size(owner), rtype, id);
	RedisModuleKey *diff_key = RedisModule_OpenKey(ctx, diff_keystr, REDISMODULE_READ | REDISMODULE_WRITE);

	knot_diff_v *diff = NULL;
	int diff_keytype = RedisModule_KeyType(diff_key);
	if (diff_keytype == REDISMODULE_KEYTYPE_EMPTY) {
		diff = RedisModule_Calloc(1, sizeof(knot_diff_v));
		if (diff == NULL) {
			RedisModule_CloseKey(diff_key);
			RedisModule_ReplyWithError(ctx, "ERR Cannot allocate memory");
			return KNOT_ENOMEM;
		}
		RedisModule_ModuleTypeSetValue(diff_key, knot_diff_t, diff);

		RedisModuleKey *diff_index_key = find_upd_index(ctx, origin, origin_len, txn, id, REDISMODULE_READ | REDISMODULE_WRITE);
		if (RedisModule_KeyType(diff_index_key) != REDISMODULE_KEYTYPE_EMPTY &&
		    RedisModule_KeyType(diff_index_key) != REDISMODULE_KEYTYPE_ZSET) {
			RedisModule_ReplyWithError(ctx, "ERR Bad data");
			return KNOT_EINVAL;
		}
		//TODO decide, if we need score for SOA record (probably not needed)
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

	//TODO TTL
	if (remove == true) {
		knot_rdataset_remove(&diff->add_rrs, rdataset, &mm);
		knot_rdataset_add(&diff->remove_rrs, rdataset, &mm);
	} else {
		knot_rdataset_remove(&diff->remove_rrs, rdataset, &mm);
		knot_rdataset_add(&diff->add_rrs, rdataset, &mm);
	}

	RedisModule_CloseKey(diff_key);
	RedisModule_FreeString(ctx, diff_keystr);

	return KNOT_EOK;
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

	int ret = KNOT_EOK;
	if (s_ctx->remove == false) {
		ret = knot_upd_add(s_ctx->ctx, s->zone_origin, s->zone_origin_length, s_ctx->txn, s->r_owner, s->r_owner_length, s->r_ttl, s->r_type, rdata);
	} else {
		ret = knot_upd_remove(s_ctx->ctx, s->zone_origin, s->zone_origin_length, s_ctx->txn, s->r_owner, s->r_owner_length, s->r_ttl, s->r_type, rdata);
	}
	if (ret != 0) {
		s_ctx->replied = true;
		s->state = ZS_STATE_STOP;
		return;
	}
}

static int knot_upd_add_txt(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 4) {
		return RedisModule_WrongArity(ctx);
	}

	rdb_txn_t txn;
	knot_dname_storage_t origin;
	size_t record_len = 0, origin_len = 0;
	const char *origin_str = RedisModule_StringPtrLen(argv[1], &origin_len);
	if (parse_dname(ctx, argv[1], origin, NULL) == NULL) {
		return RedisModule_ReplyWithError(ctx, "Malformed origin");
	}
	int ret = parse_transaction(argv[2], &txn);
	if (ret != KNOT_EOK) {
		return RedisModule_ReplyWithError(ctx, "Malformed transaction");
	}
	const char *record_str = RedisModule_StringPtrLen(argv[3], &record_len);

	if (txn_is_open(ctx, origin, &txn) == false) {
		RedisModule_ReplyWithError(ctx, "Non-existent transaction");
		return KNOT_EINVAL;
	}

	zs_scanner_t s;
	scanner_ctx_t s_ctx = { ctx, &txn, false, false };
	if (zs_init(&s, origin_str, KNOT_CLASS_IN, rdb_default_ttl) != 0 ||
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

	return RedisModule_ReplyWithSimpleString(ctx, "OK");
}

static int knot_upd_remove_txt(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 4) {
		return RedisModule_WrongArity(ctx);
	}

	rdb_txn_t txn;
	knot_dname_storage_t origin;
	size_t record_len = 0, origin_len = 0;
	const char *origin_str = RedisModule_StringPtrLen(argv[1], &origin_len);
	if (parse_dname(ctx, argv[1], origin, NULL) == NULL) {
		return RedisModule_ReplyWithError(ctx, "Malformed origin");
	}
	int ret = parse_transaction(argv[2], &txn);
	if (ret != KNOT_EOK) {
		return RedisModule_ReplyWithError(ctx, "Malformed transaction");
	}
	const char *record_str = RedisModule_StringPtrLen(argv[3], &record_len);

	if (txn_is_open(ctx, origin, &txn) == false) {
		RedisModule_ReplyWithError(ctx, "Non-existent transaction");
		return KNOT_EINVAL;
	}

	zs_scanner_t s;
	scanner_ctx_t s_ctx = { ctx, &txn, false, true };
	if (zs_init(&s, origin_str, KNOT_CLASS_IN, rdb_default_ttl) != 0 ||
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

	return RedisModule_ReplyWithSimpleString(ctx, "OK");
}

static RedisModuleString *construct_commited_upd_key(RedisModuleCtx *ctx, const knot_dname_t *origin, size_t origin_len, uint32_t serial)
{
	RedisModule_Assert(ctx != NULL);

	uint8_t prefix = UPD;
	char buf[KNOT_RRSET_KEY_MAXLEN];

	wire_ctx_t w = wire_ctx_init((uint8_t *)buf, sizeof(buf));
	wire_ctx_write(&w, KNOT_RDB_PREFIX, KNOT_RDB_PREFIX_LEN);
	wire_ctx_write(&w, &prefix, sizeof(prefix));
	wire_ctx_write(&w, origin, origin_len);
	wire_ctx_write(&w, &serial, sizeof(serial));
	RedisModule_Assert(w.error == KNOT_EOK);

	return RedisModule_CreateString(ctx, buf, wire_ctx_offset(&w));
}

static int knot_upd_commit(RedisModuleCtx *ctx, knot_dname_t *origin, rdb_txn_t *txn)
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

	size_t origin_len = knot_dname_size(origin);
	rdb_txn_t zone_txn = {
		.instance = txn->instance
	};
	ret = active_transaction(ctx, origin, &zone_txn);
	if (ret != KNOT_EOK) {
		RedisModule_ReplyWithError(ctx, "ERR None active zone");
		return KNOT_ENOENT;
	}
	RedisModuleKey *zone_key = find_zone_index(ctx, origin, origin_len, &zone_txn, REDISMODULE_READ | REDISMODULE_WRITE);

	RedisModuleKey *soa_key = NULL;
	uint32_t serial = 0;
	size_t soa_cnt = 0;
	knot_rrset_v *rrset = NULL;
	foreach_in_zset_subset(zone_key, KNOT_SCORE_SOA, KNOT_SCORE_SOA) {
		double score = 0.0;
		RedisModuleString *el = RedisModule_ZsetRangeCurrentElement(zone_key, &score);
		if (el == NULL) {
			break;
		}

		// RedisModule_CloseKey(soa_key); //NOTE close key when there is more than one SOA (ensure closed keys when bugg)

		soa_key = RedisModule_OpenKey(ctx, el, REDISMODULE_WRITE);
		if (RedisModule_ModuleTypeGetType(soa_key) != knot_zone_rrset_t) {
			RedisModule_ReplyWithError(ctx, "ERR Bad data");
			return KNOT_ENOENT;
		}
		rrset = RedisModule_ModuleTypeGetValue(soa_key);
		serial = knot_soa_serial(rrset->rrs.rdata);

		++soa_cnt;
	}
	RedisModule_CloseKey(zone_key);
	if (soa_cnt != 1) {
		RedisModule_CloseKey(soa_key);
		RedisModule_CloseKey(meta_key);
		RedisModule_CloseKey(zone_key);
		RedisModule_ReplyWithError(ctx, "ERR Missing SOA");
		return KNOT_ENOENT;
	}

	RedisModuleKey *upd_key = find_upd_index(ctx, origin, origin_len, txn, id, REDISMODULE_READ | REDISMODULE_WRITE);
	RedisModuleString *new_upd = construct_commited_upd_key(ctx, origin, origin_len, serial);
	RedisModuleKey *new_upd_key = RedisModule_OpenKey(ctx, new_upd, REDISMODULE_READ | REDISMODULE_WRITE);
	foreach_in_zset(upd_key) {
		double score = 0.0;
		RedisModuleString *el = RedisModule_ZsetRangeCurrentElement(upd_key, &score);
		if (el == NULL) {
			break;
		}

		RedisModule_ZsetAdd(new_upd_key, score, el, NULL);

		size_t el_len = 0;
		const char *el_str = RedisModule_StringPtrLen(el, &el_len);
		el_str += 3 + origin_len;
		size_t owner_len = knot_dname_size((const knot_dname_t *)el_str);
		uint16_t rtype = 0;
		memcpy(&rtype, el_str + owner_len, sizeof(rtype));

		RedisModuleKey *diff_key = RedisModule_OpenKey(ctx, el, REDISMODULE_READ);
		const knot_diff_v *diff = RedisModule_ModuleTypeGetValue(diff_key);

		uint16_t rr_count = diff->add_rrs.count;
		knot_rdata_t *rr = diff->add_rrs.rdata;
		for (size_t i = 0; i < rr_count; ++i) {
			// TODO TTL
			rdata_add(ctx, &zone_txn, origin_len, origin, owner_len, (const uint8_t *)el_str, rtype, 3600, diff->add_rrs.rdata);
			rr = knot_rdataset_next(rr);
		}
		rr_count = diff->remove_rrs.count;
		rr = diff->remove_rrs.rdata;
		for (size_t i = 0; i < rr_count; ++i) {
			// TODO TTL
			rdata_remove(ctx, &zone_txn, origin_len, origin, owner_len, (const uint8_t *)el_str, rtype, 3600, diff->remove_rrs.rdata);
			rr = knot_rdataset_next(rr);
		}

		// RedisModule_CloseKey(rrset_key);
		RedisModule_CloseKey(diff_key);
	}
	RedisModule_DeleteKey(upd_key);
	RedisModule_CloseKey(upd_key);

	knot_soa_serial_set(rrset->rrs.rdata, serial + 1);
	RedisModule_CloseKey(soa_key);

	size_t len = 0;
	upd_meta_storage_t *transaction = (upd_meta_storage_t *)RedisModule_StringDMA(meta_key, &len, REDISMODULE_WRITE);
	transaction->lock[txn->id] = 0;

	RedisModule_CloseKey(meta_key);

	RedisModuleString *origin_k = RedisModule_CreateString(ctx, "origin", sizeof("origin") - 1);
	RedisModuleString *origin_v = RedisModule_CreateString(ctx, (char *)origin, origin_len);
	(void)commit_event(ctx, ZONE_CHANGED, origin_k, origin_v, NULL);
	RedisModule_FreeString(ctx, origin_k);
	RedisModule_FreeString(ctx, origin_v);

	return KNOT_EOK;
}

static int knot_upd_commit_txt(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 3) {
		return RedisModule_WrongArity(ctx);
	}

	knot_dname_storage_t origin;
	rdb_txn_t txn;
	parse_dname(ctx, argv[1], origin, NULL);
	int ret = parse_transaction(argv[2], &txn);

	if (ret != KNOT_EOK) {
		return RedisModule_ReplyWithError(ctx, "Malformed transaction");
	}

	// RedisModuleKey *meta_key = NULL;
	// if (txn_get_when_open(ctx, origin, &txn, &meta_key, REDISMODULE_READ | REDISMODULE_WRITE) == false) {
	// 	RedisModule_CloseKey(meta_key);
	// 	return RedisModule_ReplyWithError(ctx, "Non-existent transaction");
	// }

	knot_upd_commit(ctx, origin, &txn);

	return RedisModule_ReplyWithSimpleString(ctx, "OK");
}

static int knot_upd_abort(RedisModuleCtx *ctx, knot_dname_t *origin, rdb_txn_t *txn)
{
	RedisModuleKey *meta_key = NULL;
	if (upd_meta_get_when_open(ctx, origin, txn, &meta_key, REDISMODULE_READ | REDISMODULE_WRITE) == false) {
		RedisModule_CloseKey(meta_key);
		RedisModule_ReplyWithError(ctx, "Non-existent transaction");
		return KNOT_ENOENT;
	}

	delete_upd_index(ctx, txn, origin, knot_dname_size(origin));

	size_t len = 0;
	upd_meta_storage_t *meta = (upd_meta_storage_t *)RedisModule_StringDMA(meta_key, &len, REDISMODULE_WRITE);
	meta->lock[txn->id] = 0;
	RedisModule_CloseKey(meta_key);

	return KNOT_EOK;
}

static int knot_upd_abort_txt(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 3) {
		return RedisModule_WrongArity(ctx);
	}

	knot_dname_storage_t origin;
	rdb_txn_t txn;
	if (parse_dname(ctx, argv[1], origin, NULL) == NULL) {
		return RedisModule_ReplyWithError(ctx, "Malformed dname");
	}

	int ret = parse_transaction(argv[2], &txn);
	if (ret != KNOT_EOK) {
		return RedisModule_ReplyWithError(ctx, "Malformed transaction");
	}

	if (knot_upd_abort(ctx, origin, &txn) != KNOT_EOK) {
		return REDISMODULE_OK;
	}

	return RedisModule_ReplyWithSimpleString(ctx, "OK");
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
		.rdb_load = knot_rrset_load,
		.rdb_save = knot_rrset_save,
		.mem_usage = knot_rrset_mem_usage,
		.aof_rewrite = knot_rrset_rewrite,
		.free = knot_zone_rrset_free
	};

	RedisModuleTypeMethods diff_tm = {
		.version = REDISMODULE_TYPE_METHOD_VERSION,
		.rdb_load = knot_diff_load,
		.rdb_save = knot_diff_save,
		.mem_usage = knot_diff_mem_usage,
		.aof_rewrite = knot_diff_rewrite,
		.free = knot_diff_free
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
		if (strncmp(key, "default-ttl", key_len) == 0) {
			if (RedisModule_StringToLongLong(argv[i + 1], &num) == REDISMODULE_OK) {
				rdb_default_ttl = num;
			} else {
				LOAD_ERROR(ctx, "invalid configuration option value");
			}
		} else {
			LOAD_ERROR(ctx, "unknown configuration option");
		}
	}

	knot_zone_rrset_t = RedisModule_CreateDataType(ctx, "KnotRRset", // Note: Name length has to be exactly 9
	                                               KNOT_ZONE_RRSET_ENCODING_VERSION,
	                                               &rrset_tm);
	if (knot_zone_rrset_t == NULL) {
		LOAD_ERROR(ctx, "failed to load");
	}

	knot_diff_t = RedisModule_CreateDataType(ctx, "KnotDiffT", // Note: Name length has to be exactly 9
	                                         KNOT_ZONE_RRSET_ENCODING_VERSION,
	                                         &diff_tm);


	if (RedisModule_CreateCommand(ctx, "knot.rrset.aof_rewrite", knot_rrset_aof_rewrite, "write",    1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, "knot.zone.begin",        knot_zone_begin_txt,    "write",    1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, "knot.zone.begin.bin",    knot_zone_begin_bin,    "write",    1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, "knot.zone.store",        knot_zone_store_txt,    "write",    1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, "knot.zone.store.bin",    knot_zone_store_bin,    "write",    1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, "knot.zone.commit",       knot_zone_commit_txt,   "write",    1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, "knot.zone.commit.bin",   knot_zone_commit_bin,   "write",    1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, "knot.zone.abort",        knot_zone_abort_txt,    "write",    1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, "knot.zone.abort.bin",    knot_zone_abort_bin,    "write",    1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, "knot.zone.exists",       knot_zone_exists_txt,   "readonly", 1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, "knot.zone.exists.bin",   knot_zone_exists_bin,   "readonly", 1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, "knot.zone.load",         knot_zone_load_txt,     "readonly", 1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, "knot.zone.load.bin",     knot_zone_load_bin,     "readonly", 1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, "knot.upd.begin",         knot_upd_begin_txt,     "write",    1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, "knot.upd.add",           knot_upd_add_txt,       "write",    1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, "knot.upd.remove",        knot_upd_remove_txt,    "write",    1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, "knot.upd.commit",        knot_upd_commit_txt,    "write",    1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, "knot.upd.abort",         knot_upd_abort_txt,     "write",    1, 1, 1) == REDISMODULE_ERR
	) {
		LOAD_ERROR(ctx, "failed to load");
	}

	RedisModule_Log(ctx, REDISMODULE_LOGLEVEL_NOTICE, "loaded with default-ttl=%u", rdb_default_ttl);

	return REDISMODULE_OK;
}
