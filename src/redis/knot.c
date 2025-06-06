/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: LGPL-2.1-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <arpa/inet.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define REDISMODULE_MAIN // Fixes loading error undefined symbol: RedisModule_ReplySetArrayLength.
#include "contrib/redis/redismodule.h"
#include "redis/knot.h"

#include "libknot/attribute.h"
#undef _public_
#define _public_ _hidden_

#include "libknot/rrtype/soa.h"
#include "libknot/rrtype/naptr.c"
#include "libknot/rdataset.c"
#include "libknot/rrset.c"
#include "libknot/mm_ctx.h"
#include "libknot/dname.c"
#include "libknot/descriptor.c"
#include "contrib/mempattern.c"
#include "contrib/string.c"
#include "contrib/ucw/mempool.c"
#include "libzscanner/functions.c"
#include "libzscanner/scanner.c.t0"

#define KNOT_ZONE_RRSET_ENCODING_VERSION 1
#define KNOT_RDB_VERSION	"\x01"
#define KNOT_RDB_PREFIX		"k" KNOT_RDB_VERSION

#define KNOT_DNAME_MAXLEN 255
#define KNOT_EVENT_MAX_SIZE 10

#define RRTYPE_SOA 6

#define KNOT_SCORE_SOA     0.
#define KNOT_SCORE_DEFAULT 1.

#define INSTANCE_DEFAULT	1
#define TXN_MAX_COUNT		9

#define KNOT_RRSET_KEY_MAXLEN (sizeof(KNOT_RDB_PREFIX) + KNOT_DNAME_MAXLEN + KNOT_DNAME_MAXLEN + sizeof(uint16_t) + sizeof(uint16_t))
#define TXN_KEYNAME_MAXLEN (sizeof(KNOT_RDB_PREFIX) + KNOT_DNAME_MAXLEN + sizeof(uint8_t))

#define foreach_in_zset_subset(key, min, max) \
	for (RedisModule_ZsetFirstInScoreRange(key, min, max, 0, 0); \
	     RedisModule_ZsetRangeEndReached(key) == 0; \
	     RedisModule_ZsetRangeNext(key))
#define foreach_in_zset(key) foreach_in_zset_subset(key, REDISMODULE_NEGATIVE_INFINITE, REDISMODULE_POSITIVE_INFINITE)

#define find_zone_index(...) find_index(ZONE, __VA_ARGS__)

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
	ZONE_TXN  = 3,
	RRSET     = 4,
	UPD       = 5,
	UPD_TXN   = 6,
	DIFF      = 7,
} knot_rdb_type;

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
	if (rrset) {
		RedisModule_Free(rrset->rrs.rdata);
		RedisModule_Free(rrset);
	}
}

static RedisModuleKey *find_index(const uint8_t prefix, RedisModuleCtx *ctx, const uint8_t *origin, size_t origin_len, const transaction_t *txn, int rights)
{
	RedisModule_Assert(ctx != NULL && txn != NULL);

	char buf[1 + KNOT_DNAME_MAXLEN + 2];
	char *ptr = buf;

	ptr = memcpy(ptr, KNOT_RDB_PREFIX, sizeof(KNOT_RDB_PREFIX) - 1);
	ptr = memcpy(ptr + sizeof(KNOT_RDB_PREFIX) - 1, &prefix, sizeof(prefix));
	ptr = memcpy(ptr + sizeof(prefix), origin, origin_len);
	ptr = memcpy(ptr + origin_len, txn, sizeof(*txn));
	ptr += sizeof(*txn);
	RedisModuleString *keyname = RedisModule_CreateString(ctx, buf, ptr - buf);

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
	uint8_t key_data[KNOT_RRSET_KEY_MAXLEN];
	uint8_t *ptr = key_data;
	uint8_t prefix = RRSET;

	ptr = memcpy(ptr, KNOT_RDB_PREFIX, sizeof(KNOT_RDB_PREFIX) - 1);
	ptr = memcpy(ptr + sizeof(KNOT_RDB_PREFIX) - 1, &prefix, sizeof(prefix));
	ptr = memcpy(ptr + sizeof(prefix), origin, origin_len);
	ptr = memcpy(ptr + origin_len, owner, owner_len);
	ptr = memcpy(ptr + owner_len, &rtype, sizeof(rtype));
	ptr = memcpy(ptr + sizeof(rtype), txn, sizeof(*txn));
	ptr += sizeof(*txn);
	return RedisModule_CreateString(ctx, (const char *)key_data, ptr - key_data);
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
		return RedisModule_ReplyWithError(ctx, "ERR Bad data");
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
			return RedisModule_ReplyWithError(ctx, "ERR Cannot allocate memory");
		}
		int ret = RedisModule_ModuleTypeSetValue(rrset_key, knot_zone_rrset_t, NULL);
		if (ret != REDISMODULE_OK) {
			return RedisModule_ReplyWithError(ctx, "ERR Unable to store module value");
		}
	} else if (RedisModule_ModuleTypeGetType(rrset_key) == knot_zone_rrset_t) {
		rrset = RedisModule_ModuleTypeGetValue(rrset_key);
	} else {
		RedisModule_CloseKey(rrset_key);
		return RedisModule_ReplyWithError(ctx, "ERR Bad data");
	}
	assert(rrset != NULL);

	rrset->ttl = ttl;

	RedisModule_Log(ctx, REDISMODULE_LOGLEVEL_WARNING, "RDATA %u %.*s", rdata->len, rdata->len, rdata->data);
	void *tmp = rrset->rrs.rdata;
	int ret = knot_rdataset_add(&rrset->rrs, rdata, &mm);
	RedisModule_Log(ctx, REDISMODULE_LOGLEVEL_WARNING, "RDATA %p -> %p", tmp, rrset->rrs.rdata);
	if (ret != KNOT_EOK) {
		RedisModule_CloseKey(rrset_key);
		return RedisModule_ReplyWithError(ctx, "ERR Unable to add");
	}

	RedisModule_CloseKey(rrset_key);

	return REDISMODULE_OK;
}

RedisModuleString *txn_keyname(RedisModuleCtx *ctx, const knot_dname_storage_t *origin, unsigned origin_len, uint8_t namespace)
{
	char buf[TXN_KEYNAME_MAXLEN];
	char *ptr = buf;

	ptr = memcpy(ptr, KNOT_RDB_PREFIX, sizeof(KNOT_RDB_PREFIX) - 1);
	ptr += sizeof(KNOT_RDB_PREFIX) - 1; *ptr = ZONE_TXN;
	ptr = memcpy(ptr + 1, origin, origin_len);
	ptr += origin_len; *ptr = namespace;
	ptr += sizeof(namespace);

	return RedisModule_CreateString(ctx, buf, ptr - buf);
}

// [active_txn][1-9]
static int txn_init(RedisModuleCtx *ctx, transaction_t *txn, knot_dname_storage_t *zone, size_t zone_len)
{
	assert(txn->instance != 0);

	RedisModuleString *keyname = txn_keyname(ctx, zone, zone_len, txn->instance);
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

static int serialize_transaction(const transaction_t *txn)
{
	return 10 * txn->instance + txn->id;
}

static int active_transaction(RedisModuleCtx *ctx, const knot_dname_storage_t *origin, transaction_t *txn)
{
	assert(txn->instance > 0);

	size_t origin_dname_len = knot_dname_size(*origin);
	RedisModuleString *txn_k = txn_keyname(ctx, origin, origin_dname_len, txn->instance);
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

static void delete_index(RedisModuleCtx *ctx, const transaction_t *txn, uint8_t *origin, size_t origin_len)
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
	RedisModuleString *txn_k = txn_keyname(ctx, origin_dname, origin_dname_len, txn->instance);
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

// <zone_name> [<instance_id=1>]
static int knot_zone_begin(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
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

	uint8_t zone_len = knot_dname_size(zone);
	assert(zone_len > 0);

	int ret = txn_init(ctx, &txn, &zone, zone_len);
	if (ret != KNOT_EOK) {
		return REDISMODULE_ERR;
	}

	RedisModuleString *keyname = RedisModule_CreateStringPrintf(ctx,
		KNOT_RDB_PREFIX "%c%.*s%c%c", ZONE, zone_len, zone,
		txn.instance, txn.id);
	RedisModuleKey *key = RedisModule_OpenKey(ctx, keyname, REDISMODULE_WRITE);
	RedisModule_FreeString(ctx, keyname);
	RedisModule_CloseKey(key);

	delete_index(ctx, &txn, zone, zone_len);

	return RedisModule_ReplyWithLongLong(ctx, serialize_transaction(&txn));
}

static int knot_zone_store(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
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

	if (txn_is_open(ctx, &origin_dname, &txn) == false) {
		return RedisModule_ReplyWithError(ctx, "Non-existent transaction");
	}

	zs_scanner_t s;
	if (zs_init(&s, origin_str, KNOT_CLASS_IN, 0) != 0 ||
	    zs_set_input_string(&s, record_str, record_len) != 0 ||
	    zs_parse_record(&s) != 0 ||
	    s.state != ZS_STATE_DATA) {
		zs_deinit(&s);
		return RedisModule_ReplyWithError(ctx, "Failed to parse the record");
	}

	knot_rrset_t rrset;
	knot_rrset_init(&rrset, s.r_owner, s.r_type, s.r_class, s.r_ttl);
	if (knot_rrset_add_rdata(&rrset, s.r_data, s.r_data_length, &mm) != KNOT_EOK ||
	    knot_rrset_rr_to_canonical(&rrset) != KNOT_EOK) {
		knot_rdataset_clear(&rrset.rrs, &mm);
		zs_deinit(&s);
		return RedisModule_ReplyWithError(ctx, "Failed to store the record");
	}

	ret = rdata_add(ctx, &txn, s.zone_origin_length, s.zone_origin,
			    s.r_owner_length, s.r_owner, s.r_type, s.r_ttl,
			    rrset.rrs.rdata);
	knot_rdataset_clear(&rrset.rrs, &mm);
	zs_deinit(&s);


	return RedisModule_ReplyWithSimpleString(ctx, "OK");
}

static int knot_zone_commit(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
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

	size_t len = 0;
	char *meta = RedisModule_StringDMA(meta_key, &len, REDISMODULE_WRITE);
	uint8_t active_old = meta[0];
	if (active_old) meta[active_old] = 0;
	meta[0] = txn.id;
	// NOTE need to keep current transaction locked while active

	RedisModule_CloseKey(meta_key);
	
	return RedisModule_ReplyWithSimpleString(ctx, "OK");
}

static int knot_zone_abort(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
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

	size_t len = 0;
	char *meta = RedisModule_StringDMA(meta_key, &len, REDISMODULE_WRITE);
	meta[txn.id] = 0;

	RedisModule_CloseKey(meta_key);

	delete_index(ctx, &txn, origin, knot_dname_size(origin));
	
	return RedisModule_ReplyWithSimpleString(ctx, "OK");
}

static int knot_zone_load(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	knot_dname_storage_t origin;
	transaction_t txn = { .instance = 1 };

	switch (argc) {
	case 3:
		if ((txn.instance = parse_instance(argv[2])) == 0) {
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

	int ret = active_transaction(ctx, &origin, &txn);
	if (ret != KNOT_EOK) {
		return RedisModule_ReplyWithError(ctx, "ERR unknown instance");
	}

	size_t origin_len = knot_dname_size(origin);
	RedisModuleKey *index_key = find_zone_index(ctx, origin, origin_len, &txn, REDISMODULE_READ);
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

	long count = 0;
	RedisModule_ReplyWithArray(ctx, REDISMODULE_POSTPONED_ARRAY_LEN);
	foreach_in_zset (index_key) {
		double score = 0.0;
		RedisModuleString *el = RedisModule_ZsetRangeCurrentElement(index_key, &score);
		if (el == NULL) {
			break;
		}

		size_t rrset_strlen = 0;
		const char *rrset_str = RedisModule_StringPtrLen(el, &rrset_strlen);
		const char *ptr = rrset_str + sizeof(KNOT_RDB_PREFIX);
		ptr += knot_dname_size((const knot_dname_t *)ptr);

		RedisModuleKey *rrset_key = RedisModule_OpenKey(ctx, el, REDISMODULE_READ);
		if (rrset_key == NULL) {
			continue;
		}
		knot_rrset_v *rrset = RedisModule_ModuleTypeGetValue(rrset_key);

		// RedisModule_ReplyWithArray(ctx, 5);
		RedisModule_ReplyWithArray(ctx, 2);
		size_t owner_len = knot_dname_size((const knot_dname_t *)ptr);
		RedisModule_ReplyWithStringBuffer(ctx, ptr, owner_len);

		uint16_t rtype = 0;
		memcpy(&rtype, ptr + owner_len, sizeof(uint16_t));
		RedisModule_ReplyWithLongLong(ctx, rtype);
		// RedisModule_ReplyWithLongLong(ctx, rrset->ttl);
		// RedisModule_ReplyWithLongLong(ctx, rrset->rrs.count);
		// RedisModule_ReplyWithStringBuffer(ctx, (const char *)rrset->rrs.rdata, rrset->rrs.size);

		RedisModule_CloseKey(rrset_key);

		++count;
	}
	RedisModule_ZsetRangeStop(index_key);
	RedisModule_CloseKey(index_key);
	RedisModule_ReplySetArrayLength(ctx, count);

	return REDISMODULE_OK;
}

__attribute__((visibility("default")))
int RedisModule_OnLoad(RedisModuleCtx *ctx)
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
		return REDISMODULE_ERR;
	}

	knot_zone_rrset_t = RedisModule_CreateDataType(ctx, "KnotRRset", // Note: Name length has to be exactly 9
	                                               KNOT_ZONE_RRSET_ENCODING_VERSION,
	                                               &rrset_tm);
	if (knot_zone_rrset_t == NULL) {
		RedisModule_Log(ctx, REDISMODULE_LOGLEVEL_WARNING, "ERR 'knot' module already loaded");
		RedisModule_ReplyWithError(ctx, "ERR 'knot' module already loaded");
		return REDISMODULE_ERR;
	}

	if (RedisModule_CreateCommand(ctx, "knot.rrset.aof_rewrite", knot_rrset_aof_rewrite, "write", 1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, "knot.zone.begin",        knot_zone_begin,        "write", 1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, "knot.zone.store",        knot_zone_store,        "write", 1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, "knot.zone.commit",       knot_zone_commit,       "write", 1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, "knot.zone.abort",        knot_zone_abort,        "write", 1, 1, 1) == REDISMODULE_ERR ||
	    RedisModule_CreateCommand(ctx, "knot.zone.load",         knot_zone_load,         "write", 1, 1, 1) == REDISMODULE_ERR
	) {
		RedisModule_Log(ctx, REDISMODULE_LOGLEVEL_WARNING, "ERR 'knot' module already loaded");
		RedisModule_ReplyWithError(ctx, "ERR 'knot' module already loaded");
		return REDISMODULE_ERR;
	}

	return REDISMODULE_OK;
}
