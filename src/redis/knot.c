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

#define find_zone_index(...) find_index(ZONE, __VA_ARGS__)

static uint32_t rdb_default_ttl = 600;

typedef struct {
	uint32_t ttl;
	knot_rdataset_t rrs;
} knot_rrset_v;

typedef struct {
	uint8_t instance;
	uint8_t id;
} transaction_t;

typedef enum {
	EVENT     = 1,
	ZONE      = 2,
	ZONE_META = 3,
	RRSET     = 4,
	UPD       = 5,
	UPD_TXN   = 6,
	DIFF      = 7,
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

static RedisModuleKey *find_index(const uint8_t prefix, RedisModuleCtx *ctx, const uint8_t *origin, size_t origin_len, const transaction_t *txn, int rights)
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

static knot_dname_t *parse_dname(RedisModuleCtx *ctx, RedisModuleString *arg, knot_dname_storage_t *out)
{
	assert(ctx != NULL && arg != NULL && out != NULL);

	size_t len;
	const char *data = RedisModule_StringPtrLen(arg, &len);
	return knot_dname_from_str(*out, data, sizeof(*out));
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

static RedisModuleString *construct_rrset_key(RedisModuleCtx *ctx, const transaction_t *txn, const uint8_t *origin, size_t origin_len, const uint8_t *owner, size_t owner_len, uint16_t rtype)
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

static int rdata_add(RedisModuleCtx *ctx, const transaction_t *txn,
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

	RedisModule_ZsetAdd(zone_key, evaluate_score(rtype), rrset_keystr, NULL);
	RedisModule_CloseKey(zone_key);

	RedisModuleKey *rrset_key = RedisModule_OpenKey(ctx, rrset_keystr, REDISMODULE_READ | REDISMODULE_WRITE);
	RedisModule_FreeString(ctx, rrset_keystr);

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

RedisModuleString *meta_keyname(RedisModuleCtx *ctx, const uint8_t *origin, unsigned origin_len, uint8_t instance)
{
	char buf[TXN_KEYNAME_MAXLEN];
	uint8_t prefix = ZONE_META;

	wire_ctx_t w = wire_ctx_init((uint8_t *)buf, sizeof(buf));
	wire_ctx_write(&w, KNOT_RDB_PREFIX, KNOT_RDB_PREFIX_LEN);
	wire_ctx_write(&w, &prefix, sizeof(prefix));
	wire_ctx_write(&w, origin, origin_len);
	wire_ctx_write(&w, &instance, sizeof(instance));
	RedisModule_Assert(w.error == KNOT_EOK);

	return RedisModule_CreateString(ctx, buf, wire_ctx_offset(&w));
}

// [active_txn][1-9]
static int txn_init(RedisModuleCtx *ctx, transaction_t *txn, const uint8_t *zone, size_t zone_len)
{
	assert(txn->instance != 0);

	RedisModuleString *keyname = meta_keyname(ctx, zone, zone_len, txn->instance);
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

static int parse_transaction(RedisModuleString *arg, transaction_t *txn)
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

static int parse_transaction2(RedisModuleString *arg, transaction_t *txn)
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

static int serialize_transaction(const transaction_t *txn)
{
	return 10 * txn->instance + txn->id;
}

static int active_transaction(RedisModuleCtx *ctx, const uint8_t *origin, transaction_t *txn)
{
	assert(txn->instance > 0);

	size_t origin_dname_len = knot_dname_size(origin);
	RedisModuleString *txn_k = meta_keyname(ctx, origin, origin_dname_len, txn->instance);
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

static void delete_index(RedisModuleCtx *ctx, const transaction_t *txn, const uint8_t *origin, size_t origin_len)
{
	RedisModule_Assert(ctx != NULL && txn != NULL);

	RedisModuleKey *index_key = find_zone_index(ctx, origin, origin_len, txn, REDISMODULE_READ | REDISMODULE_WRITE);
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

static bool txn_get_when_open(RedisModuleCtx *ctx, const knot_dname_storage_t* origin_dname, const transaction_t *txn, RedisModuleKey **key, int rights)
{
	assert(key != NULL && *key == NULL);

	size_t origin_dname_len = knot_dname_size(*origin_dname);
	RedisModuleString *txn_k = meta_keyname(ctx, (const uint8_t *)origin_dname, origin_dname_len, txn->instance);
	*key = RedisModule_OpenKey(ctx, txn_k, rights);
	RedisModule_FreeString(ctx, txn_k);
	if (key == NULL || RedisModule_KeyType(*key) != REDISMODULE_KEYTYPE_STRING) {
		return false;
	}
	size_t len = 0;
	const char *transaction = RedisModule_StringDMA(*key, &len, REDISMODULE_WRITE);
	return txn->id != transaction[0] && transaction[txn->id] != 0;
}


static bool txn_is_open(RedisModuleCtx *ctx, const knot_dname_storage_t* origin_dname, const transaction_t *txn)
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

static int knot_zone_begin(RedisModuleCtx *ctx, transaction_t *txn, const uint8_t *zone, int zone_len)
{
	int ret = txn_init(ctx, txn, zone, zone_len);
	if (ret != KNOT_EOK) {
		return KNOT_EINVAL;
	}

	RedisModuleString *keyname = RedisModule_CreateStringPrintf(ctx,
		KNOT_RDB_PREFIX "%c%.*s%c%c", ZONE, zone_len, (char *)zone,
		txn->instance, txn->id);
	RedisModuleKey *key = RedisModule_OpenKey(ctx, keyname, REDISMODULE_WRITE);
	RedisModule_FreeString(ctx, keyname);
	RedisModule_CloseKey(key);

	delete_index(ctx, txn, zone, zone_len);

	return KNOT_EOK;
}

// <zone_name> [<instance_id=1>]
static int knot_zone_begin_txt(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	transaction_t txn = { .instance = 1 };
	knot_dname_storage_t zone;

	switch (argc) {
	case 3:
		if ((txn.instance = parse_instance(argv[2])) == 0) {
			return RedisModule_ReplyWithError(ctx, "ERR invalid zone instance");
		}
	case 2: // FALLTHROUGH
		if (parse_dname(ctx, argv[1], &zone) == NULL) {
			return RedisModule_ReplyWithError(ctx, "ERR invalid zone name");
		}
		break;
	default:
		return RedisModule_WrongArity(ctx);
	}

	size_t zone_len = knot_dname_size(zone);
	assert(zone_len > 0);

	int ret = knot_zone_begin(ctx, &txn, zone, zone_len);
	if (ret != KNOT_EOK) {
		return REDISMODULE_OK;
	}

	return RedisModule_ReplyWithLongLong(ctx, serialize_transaction(&txn));
}

static int knot_zone_begin_bin(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	transaction_t txn = { .instance = 1 };
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
	transaction_t *txn;
	bool replied;
} scanner_ctx_t;

static void scanner_data(zs_scanner_t *s)
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
	(void)snprintf(msg, sizeof(msg), "Parser failed (%s), line %"PRIu64,
	               zs_strerror(s->error.code), s->line_counter);
	RedisModule_ReplyWithError(s_ctx->ctx, msg);

	s_ctx->replied = true;
	s->state = ZS_STATE_STOP;
}

// TODO.. Origin is in argument twice, would be nice to reduce it
static int knot_zone_store(RedisModuleCtx *ctx, knot_dname_storage_t *origin, const char *origin_str, transaction_t *txn, const char *record_str, size_t record_len)
{
	if (txn_is_open(ctx, origin, txn) == false) {
		RedisModule_ReplyWithError(ctx, "Non-existent transaction");
		return KNOT_EINVAL;
	}

	zs_scanner_t s;
	scanner_ctx_t s_ctx = { ctx, txn };
	if (zs_init(&s, origin_str, KNOT_CLASS_IN, rdb_default_ttl) != 0 ||
	    zs_set_input_string(&s, record_str, record_len) != 0 ||
	    zs_set_processing(&s, scanner_data, scanner_error, &s_ctx) != 0 ||
	    zs_parse_all(&s) != 0) {
		zs_deinit(&s);
		if (!s_ctx.replied) {
			RedisModule_ReplyWithError(ctx, "Parser failed");
			return KNOT_EMALF;
		}
		return KNOT_EMALF;
	}
	zs_deinit(&s);

	return KNOT_EOK;
}

static int knot_zone_store_txt(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 4) {
		return RedisModule_WrongArity(ctx);
	}

	size_t origin_len = 0, record_len = 0;
	transaction_t txn;
	const char *origin_str = RedisModule_StringPtrLen(argv[1], &origin_len);
	int ret = parse_transaction(argv[2], &txn);
	const char *record_str = RedisModule_StringPtrLen(argv[3], &record_len);

	if (ret != KNOT_EOK) {
		return RedisModule_ReplyWithError(ctx, "Malformed transaction");
	}

	/* Convert origin to dname */
	knot_dname_storage_t origin_dname;
	parse_dname(ctx, argv[1], &origin_dname);

	ret = knot_zone_store(ctx, &origin_dname, origin_str, &txn, record_str, record_len);
	if (ret != KNOT_EOK) {
		return REDISMODULE_OK;
	}

	return RedisModule_ReplyWithSimpleString(ctx, "OK");
}

static int knot_zone_store_bin(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 4) {
		return RedisModule_WrongArity(ctx);
	}

	size_t origin_len = 0, txn_len = 0, record_len = 0;
	knot_dname_storage_t *origin = (knot_dname_storage_t *)RedisModule_StringPtrLen(argv[1], &origin_len);
	transaction_t *txn = (transaction_t *)RedisModule_StringPtrLen(argv[2], &txn_len);
	const char *record_str = RedisModule_StringPtrLen(argv[3], &record_len);

	if (origin_len > KNOT_DNAME_MAXLEN) {
		return RedisModule_ReplyWithError(ctx, "Malformed origin");
	}
	if (txn_len != sizeof(*txn)) {
		return RedisModule_ReplyWithError(ctx, "Malformed transaction");
	}

	char origin_str[KNOT_DNAME_TXT_MAXLEN];
	if (knot_dname_to_str(origin_str, *origin, KNOT_DNAME_TXT_MAXLEN) == NULL) {
		return RedisModule_ReplyWithError(ctx, "Malformed origin");
	}

	if (txn_is_open(ctx, origin, txn) == false) {
		return RedisModule_ReplyWithError(ctx, "Non-existent transaction");
	}

	int ret = knot_zone_store(ctx, origin, origin_str, txn, record_str, record_len);
	if (ret != KNOT_EOK) {
		return REDISMODULE_OK;
	}

	return RedisModule_ReplyWithSimpleString(ctx, "OK");
}

static int knot_zone_commit(RedisModuleCtx *ctx, knot_dname_storage_t *origin, transaction_t *txn)
{
	RedisModuleKey *meta_key = NULL;
	if (txn_get_when_open(ctx, origin, txn, &meta_key, REDISMODULE_READ | REDISMODULE_WRITE) == false) {
		RedisModule_CloseKey(meta_key);
		RedisModule_ReplyWithError(ctx, "ERR Non-existent transaction");
		return KNOT_ENOENT;
	}

	size_t origin_len = knot_dname_size(*origin);
	RedisModuleKey *zone_key = find_zone_index(ctx, *origin, origin_len, txn, REDISMODULE_READ | REDISMODULE_WRITE);

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
		transaction_t txn_old = {
			.instance = txn->instance,
			.id = active_old
		};
		delete_index(ctx, &txn_old, *origin, origin_len);
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
	transaction_t txn;
	parse_dname(ctx, argv[1], &origin);
	int ret = parse_transaction(argv[2], &txn);

	if (ret != KNOT_EOK) {
		return RedisModule_ReplyWithError(ctx, "Malformed transaction");
	}

	RedisModuleKey *meta_key = NULL;
	if (txn_get_when_open(ctx, &origin, &txn, &meta_key, REDISMODULE_READ | REDISMODULE_WRITE) == false) {
		RedisModule_CloseKey(meta_key);
		return RedisModule_ReplyWithError(ctx, "Non-existent transaction");
	}

	knot_zone_commit(ctx, &origin, &txn);

	return RedisModule_ReplyWithSimpleString(ctx, "OK");
}

static int knot_zone_commit_bin(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 3) {
		return RedisModule_WrongArity(ctx);
	}

	size_t origin_len = 0, txn_len = 0;
	knot_dname_storage_t *origin = (knot_dname_storage_t *)RedisModule_StringPtrLen(argv[1], &origin_len);
	transaction_t *txn = (transaction_t *)RedisModule_StringPtrLen(argv[2], &txn_len);

	if (origin_len > KNOT_DNAME_MAXLEN) {
		return RedisModule_ReplyWithError(ctx, "Malformed origin");
	}
	if (txn_len != sizeof(*txn)) {
		return RedisModule_ReplyWithError(ctx, "Malformed transaction");
	}

	knot_zone_commit(ctx, origin, txn);

	return RedisModule_ReplyWithSimpleString(ctx, "OK");
}

static int knot_zone_abort(RedisModuleCtx *ctx, knot_dname_storage_t *origin, transaction_t *txn)
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

	delete_index(ctx, txn, *origin, knot_dname_size(*origin));

	return KNOT_EOK;
}

static int knot_zone_abort_txt(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 3) {
		return RedisModule_WrongArity(ctx);
	}

	knot_dname_storage_t origin;
	transaction_t txn;
	parse_dname(ctx, argv[1], &origin);
	int ret = parse_transaction(argv[2], &txn);

	if (ret != KNOT_EOK) {
		return RedisModule_ReplyWithError(ctx, "Malformed transaction");
	}

	if (knot_zone_abort(ctx, &origin, &txn) != KNOT_EOK) {
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
	transaction_t *txn = (transaction_t *)RedisModule_StringPtrLen(argv[2], &txn_len);

	if (origin_len > KNOT_DNAME_MAXLEN) {
		return RedisModule_ReplyWithError(ctx, "Malformed origin");
	}
	if (txn_len != sizeof(*txn)) {
		return RedisModule_ReplyWithError(ctx, "Malformed transaction");
	}

	if (knot_zone_abort(ctx, origin, txn) != KNOT_EOK) {
		return REDISMODULE_OK;
	}

	return RedisModule_ReplyWithSimpleString(ctx, "OK");
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

static int knot_zone_load(RedisModuleCtx *ctx, knot_dname_storage_t *origin, size_t origin_len, transaction_t *txn, knot_dname_storage_t *opt_owner, uint16_t *opt_rtype, bool txt)
{
	if (txn->id == TXN_ID_ACTIVE) {
		int ret = active_transaction(ctx, *origin, txn);
		if (ret != KNOT_EOK) {
			return RedisModule_ReplyWithError(ctx, "ERR unknown instance");
		}
	}

	RedisModuleKey *index_key = find_zone_index(ctx, *origin, origin_len, txn, REDISMODULE_READ);
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
		wire_ctx_skip(&w, KNOT_RDB_PREFIX_LEN + 1);
		wire_ctx_skip(&w, knot_dname_size(w.position));
		knot_dname_t *owner = w.position;
		size_t owner_len = knot_dname_size(owner);
		wire_ctx_skip(&w, owner_len);
		uint16_t rtype = wire_ctx_read_u16(&w);
		RedisModule_Assert(w.error == KNOT_EOK);


		if (opt_owner != NULL && memcmp(owner, *opt_owner, owner_len) != 0) {
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
	transaction_t txn = {
		.instance = 1,
		.id = TXN_ID_ACTIVE
	};
	knot_dname_storage_t owner;
	uint16_t rtype = 0;

	switch (argc) {
	case 5:
		if (parse_rtype(&rtype, argv[4]) != KNOT_EOK) {
			return RedisModule_ReplyWithError(ctx, "ERR invalid rtype");
		}
	case 4: // FALLTHROUGH
		if (parse_dname(ctx, argv[3], &owner) == NULL) {
			return RedisModule_ReplyWithError(ctx, "ERR invalid owner");
		}
	case 3:; // FALLTHROUGH
		int ret = parse_transaction2(argv[2], &txn);
		if (ret != KNOT_EOK) {
			return RedisModule_ReplyWithError(ctx, "ERR invalid zone instance");
		}
	case 2: // FALLTHROUGH
		if (parse_dname(ctx, argv[1], &origin) == NULL) {
			return RedisModule_ReplyWithError(ctx, "ERR invalid zone name");
		}
		break;
	default:
		return RedisModule_WrongArity(ctx);
	}

	knot_zone_load(ctx, &origin, knot_dname_size(origin), &txn,
	               (argc >= 4) ? &owner : NULL, (argc >= 5) ? &rtype : NULL,
	               true);

	return REDISMODULE_OK;
}

static int knot_zone_load_bin(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	static transaction_t txn = {
		.instance = 1,
		.id = TXN_ID_ACTIVE
	};

	size_t origin_len = 0, txn_len = 0, owner_len = 0, rtype_len = 0;
	knot_dname_storage_t *origin = NULL, *owner = NULL;
	uint16_t rtype;

	switch (argc) {
	case 5:;
		const char *rtype_str = RedisModule_StringPtrLen(argv[4], &rtype_len);
		if (rtype_len != sizeof(rtype)) {
			return RedisModule_ReplyWithError(ctx, "Malformed rtype");
		}
		memcpy(&rtype, rtype_str, rtype_len);
	case 4: // FALLTHROUGH
		owner = (knot_dname_storage_t *)RedisModule_StringPtrLen(argv[3], &owner_len);
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
		origin = (knot_dname_storage_t *)RedisModule_StringPtrLen(argv[1], &origin_len);
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

	if (RedisModule_CreateCommand(ctx, "knot.rrset.aof_rewrite", knot_rrset_aof_rewrite, "write",    1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, "knot.zone.begin",        knot_zone_begin_txt,    "write",    1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, "knot.zone.begin.bin",    knot_zone_begin_bin,    "write",    1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, "knot.zone.store",        knot_zone_store_txt,    "write",    1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, "knot.zone.store.bin",    knot_zone_store_bin,    "write",    1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, "knot.zone.commit",       knot_zone_commit_txt,   "write",    1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, "knot.zone.commit.bin",   knot_zone_commit_bin,   "write",    1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, "knot.zone.abort",        knot_zone_abort_txt,    "write",    1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, "knot.zone.abort.bin",    knot_zone_abort_bin,    "write",    1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, "knot.zone.load",         knot_zone_load_txt,     "readonly", 1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, "knot.zone.load.bin",     knot_zone_load_bin,     "readonly", 1, 1, 1) == REDISMODULE_ERR
	) {
		LOAD_ERROR(ctx, "failed to load");
	}

	RedisModule_Log(ctx, REDISMODULE_LOGLEVEL_NOTICE, "loaded with default-ttl=%u", rdb_default_ttl);

	return REDISMODULE_OK;
}
