/*  Copyright (C) 2025 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdbool.h>
#include <string.h>

#define REDISMODULE_MAIN // Fixes loading error undefined symbol: RedisModule_ReplySetArrayLength.
#include "contrib/redis/redismodule.h"

#define KNOT_ZONE_RRSET_ENCODING_VERSION 0

#define KNOT_DNAME_MAXLEN 255
#define KNOT_RRSET_KEY_MAXLEN (1 + KNOT_DNAME_MAXLEN + KNOT_DNAME_MAXLEN + sizeof(uint16_t))

#define RRTYPE_SOA 6

#define KNOT_SCORE_SOA     0.
#define KNOT_SCORE_DEFAULT 1.

#define foreach_in_zset_subset(key, min, max) \
		for (RedisModule_ZsetFirstInScoreRange(key, min, max, 0, 0); \
		     RedisModule_ZsetRangeEndReached(key) == false; \
		     RedisModule_ZsetRangeNext(key))
#define foreach_in_zset(key) foreach_in_zset_subset(key, REDISMODULE_NEGATIVE_INFINITE, REDISMODULE_POSITIVE_INFINITE)

typedef enum {
	EVENTS,
	ZONE_INDEX,
	RRSET
} KnotTypeID;

typedef struct {
	uint32_t ttl;
	struct {
		uint16_t count;
		uint32_t size;
		uint8_t *rdata;
	} rrs;
} knot_zone_rrset_v;

static RedisModuleType *knot_zone_rrset_t;

static size_t dname_size(const uint8_t *name)
{
	size_t len = 0;
	while (*name != '\0') {
		uint8_t lblen = *name + 1;
		len += lblen;
		name += lblen;
	}

	return len + 1;
}

static void *knot_zone_rrset_load(RedisModuleIO *rdb, int encver)
{
	if (encver != KNOT_ZONE_RRSET_ENCODING_VERSION) {
		// TODO ignore or version compatibility layers
		return NULL;
	}

	knot_zone_rrset_v *rrset = RedisModule_Alloc(sizeof(knot_zone_rrset_v));
	if (rrset == NULL) {
		return NULL;
	}
	size_t len = 0;
	rrset->ttl = RedisModule_LoadUnsigned(rdb);
	rrset->rrs.count = RedisModule_LoadUnsigned(rdb);
	rrset->rrs.rdata = (uint8_t *)RedisModule_LoadStringBuffer(rdb, &len);
	if (len > UINT32_MAX) {
		RedisModule_Free(rrset->rrs.rdata);
		RedisModule_Free(rrset);
		return NULL;
	}
	rrset->rrs.size = len;
	return rrset;
}

static void knot_zone_rrset_save(RedisModuleIO *rdb, void *value)
{
	knot_zone_rrset_v *rrset = (knot_zone_rrset_v *)value;
	RedisModule_SaveUnsigned(rdb, rrset->ttl);
	RedisModule_SaveUnsigned(rdb, rrset->rrs.count);
	RedisModule_SaveStringBuffer(rdb, (const char *)rrset->rrs.rdata, rrset->rrs.size);
}

static void knot_zone_rrset_rewrite(RedisModuleIO *aof, RedisModuleString *key, void *value)
{
	// TODO insert-by-id
	RedisModule_EmitAOF(aof, "KNOT.RRSET.INSERT", "sss", "com.", "dns1.example.com.", "A");
}

static void knot_zone_rrset_free(void *value)
{
	knot_zone_rrset_v *rrset = (knot_zone_rrset_v *)value;
	RedisModule_Free(rrset->rrs.rdata);
	RedisModule_Free(rrset);
}

static inline RedisModuleKey *find_zone(RedisModuleCtx *ctx, const uint8_t *origin, size_t origin_len, int rights)
{
	static const uint8_t prefix = ZONE_INDEX;

	if (ctx == NULL || origin == NULL) {
		return NULL;
	}

	RedisModuleString *keyname = RedisModule_CreateString(ctx, (const char *)&prefix, sizeof(prefix));
	RedisModule_StringAppendBuffer(ctx, keyname, (const char *)origin, origin_len);
	RedisModuleKey *key = RedisModule_OpenKey(ctx, keyname, rights);
	RedisModule_FreeString(ctx, keyname);

	return key;
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

static int knot_zone_exists(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 2) {
		return RedisModule_WrongArity(ctx);
	}

	size_t origin_len = 0;
	const uint8_t *origin = (const uint8_t *)RedisModule_StringPtrLen(argv[1], &origin_len);

	RedisModuleKey *zone_key = find_zone(ctx, origin, origin_len, REDISMODULE_READ);
	if (zone_key == NULL) {
		return RedisModule_ReplyWithLongLong(ctx, false);
	} else if (RedisModule_KeyType(zone_key) == REDISMODULE_KEYTYPE_EMPTY) {
		RedisModule_CloseKey(zone_key);
		return RedisModule_ReplyWithLongLong(ctx, false);
	} else if (RedisModule_KeyType(zone_key) != REDISMODULE_KEYTYPE_ZSET) {
		RedisModule_CloseKey(zone_key);
		return RedisModule_ReplyWithError(ctx, "ERR Bad data");
	}

	RedisModule_ZsetFirstInScoreRange(zone_key, KNOT_SCORE_SOA, KNOT_SCORE_SOA, 0, 0);
	bool exists = !RedisModule_ZsetRangeEndReached(zone_key);
	RedisModule_ZsetRangeStop(zone_key);
	RedisModule_CloseKey(zone_key);

	return RedisModule_ReplyWithLongLong(ctx, exists);
}

static int knot_zone_load(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 2) {
		return RedisModule_WrongArity(ctx);
	}

	size_t origin_len = 0;
	const uint8_t *origin = (const uint8_t *)RedisModule_StringPtrLen(argv[1], &origin_len);

	RedisModuleKey *zone_key = find_zone(ctx, origin, origin_len, REDISMODULE_READ);
	if (zone_key == NULL) {
		return RedisModule_ReplyWithError(ctx, "ERR Unable find");
	}
	int zone_keytype = RedisModule_KeyType(zone_key);
	if (zone_keytype == REDISMODULE_KEYTYPE_EMPTY) {
		RedisModule_CloseKey(zone_key);
		return RedisModule_ReplyWithError(ctx, "ERR Does not exist");
	} else if (zone_keytype != REDISMODULE_KEYTYPE_ZSET) {
		RedisModule_CloseKey(zone_key);
		return RedisModule_ReplyWithError(ctx, "ERR Bad data");
	}

	long count = 0;
	RedisModule_ReplyWithArray(ctx, REDISMODULE_POSTPONED_ARRAY_LEN);
	foreach_in_zset (zone_key) {
		double score = 0.0;
		RedisModuleString *el = RedisModule_ZsetRangeCurrentElement(zone_key, &score);
		if (el == NULL) {
			break;
		}

		size_t rrset_strlen = 0;
		const char *rrset_str = RedisModule_StringPtrLen(el, &rrset_strlen);

		uint16_t rtype = 0;
		memcpy(&rtype, rrset_str + rrset_strlen - sizeof(uint16_t), sizeof(uint16_t));

		RedisModuleKey *rrset_key = RedisModule_OpenKey(ctx, el, REDISMODULE_READ);
		knot_zone_rrset_v *rrset = RedisModule_ModuleTypeGetValue(rrset_key);
		RedisModule_CloseKey(rrset_key);

		RedisModule_ReplyWithArray(ctx, 5);
		RedisModule_ReplyWithStringBuffer(ctx, rrset_str + origin_len + 1, rrset_strlen - origin_len - 3);
		RedisModule_ReplyWithLongLong(ctx, rtype);
		RedisModule_ReplyWithLongLong(ctx, rrset->ttl);
		RedisModule_ReplyWithLongLong(ctx, rrset->rrs.count);
		RedisModule_ReplyWithStringBuffer(ctx, (const char *)rrset->rrs.rdata, rrset->rrs.size);

		++count;
	}
	RedisModule_ZsetRangeStop(zone_key);
	RedisModule_CloseKey(zone_key);
	RedisModule_ReplySetArrayLength(ctx, count);

	return REDISMODULE_OK;
}

static int knot_zone_purge(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 2) {
		return RedisModule_WrongArity(ctx);
	}

	size_t origin_len = 0;
	const uint8_t *origin = (const uint8_t *)RedisModule_StringPtrLen(argv[1], &origin_len);

	RedisModuleKey *zone_key = find_zone(ctx, origin, origin_len, REDISMODULE_READ | REDISMODULE_WRITE);
	if (zone_key == NULL) {
		return RedisModule_ReplyWithError(ctx, "ERR Unable find");
	}

	int zone_index_type = RedisModule_KeyType(zone_key);
	if (zone_index_type == REDISMODULE_KEYTYPE_EMPTY) {
		RedisModule_CloseKey(zone_key);
		return RedisModule_ReplyWithError(ctx, "ERR Does not exist");
	} else if (zone_index_type != REDISMODULE_KEYTYPE_ZSET) {
		RedisModule_CloseKey(zone_key);
		return RedisModule_ReplyWithError(ctx, "ERR Bad data");
	}

	foreach_in_zset (zone_key) {
		double score = 0.0;
		RedisModuleString *el = RedisModule_ZsetRangeCurrentElement(zone_key, &score);
		if (el == NULL) {
			break;
		}

		RedisModuleKey *rrset_key = RedisModule_OpenKey(ctx, el, REDISMODULE_READ | REDISMODULE_WRITE);
		RedisModule_DeleteKey(rrset_key);
		RedisModule_CloseKey(rrset_key);
	}
	RedisModule_ZsetRangeStop(zone_key);
	RedisModule_DeleteKey(zone_key);
	RedisModule_CloseKey(zone_key);

	RedisModule_ReplyWithEmptyString(ctx);

	return REDISMODULE_OK;
}

static int knot_rrset_store(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 7) {
		return RedisModule_WrongArity(ctx);
	}

	size_t origin_len = 0;
	const uint8_t *origin = (const uint8_t *)RedisModule_StringPtrLen(argv[1], &origin_len);

	RedisModuleKey *zone_key = find_zone(ctx, origin, origin_len, REDISMODULE_READ | REDISMODULE_WRITE);
	if (zone_key == NULL) {
		return RedisModule_ReplyWithError(ctx, "ERR Unable find");
	}

	int zone_keytype = RedisModule_KeyType(zone_key);
	if (zone_keytype != REDISMODULE_KEYTYPE_EMPTY && zone_keytype != REDISMODULE_KEYTYPE_ZSET) {
		RedisModule_CloseKey(zone_key);
		return RedisModule_ReplyWithError(ctx, "ERR Bad data");
	}

	size_t owner_strlen;
	const char *owner_str = RedisModule_StringPtrLen(argv[2], &owner_strlen);
	long long type = 0;
	int ret = RedisModule_StringToLongLong(argv[3], &type);
	if (ret != REDISMODULE_OK) {
		RedisModule_CloseKey(zone_key);
		return RedisModule_ReplyWithError(ctx, "ERR Wrong RRTYPE format");
	} else if (type < 0 || type > UINT16_MAX) {
		RedisModule_CloseKey(zone_key);
		return RedisModule_ReplyWithError(ctx, "ERR Value out of range");
	}
	uint16_t rtype = type;
	uint8_t key_data[KNOT_RRSET_KEY_MAXLEN];
	uint8_t *key_ptr = key_data;
	key_ptr[0] = RRSET;
	key_ptr = memcpy(key_ptr + 1, origin, origin_len);
	key_ptr = memcpy(key_ptr + origin_len, owner_str, owner_strlen);
	key_ptr = memcpy(key_ptr + owner_strlen, &rtype, sizeof(rtype));
	key_ptr += sizeof(rtype);
	RedisModuleString *rrset_keystr = RedisModule_CreateString(ctx, (const char *)key_data, key_ptr - key_data);

	RedisModule_ZsetAdd(zone_key, evaluate_score(rtype), rrset_keystr, NULL);
	RedisModule_CloseKey(zone_key);

	RedisModuleKey *rrset_key = RedisModule_OpenKey(ctx, rrset_keystr, REDISMODULE_READ | REDISMODULE_WRITE);
	RedisModule_FreeString(ctx, rrset_keystr);

	knot_zone_rrset_v *rrset = RedisModule_Calloc(1, sizeof(knot_zone_rrset_v));
	long long ttl_val = 0;
	ret = RedisModule_StringToLongLong(argv[4], &ttl_val);
	if (ttl_val < 0 || type > UINT32_MAX) {
		RedisModule_CloseKey(rrset_key);
		return RedisModule_ReplyWithError(ctx, "ERR Value out of range");
	}
	rrset->ttl = ttl_val;

	long long count_val = 0;
	ret = RedisModule_StringToLongLong(argv[5], &count_val);
	if (count_val < 0 || type > UINT16_MAX) {
		RedisModule_CloseKey(rrset_key);
		return RedisModule_ReplyWithError(ctx, "ERR Value out of range");
	}
	rrset->rrs.count = count_val;

	size_t rdataset_strlen;
	const char *rdataset_str = RedisModule_StringPtrLen(argv[6], &rdataset_strlen);
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

	RedisModule_ReplyWithEmptyString(ctx);

	return REDISMODULE_OK;
}

int RedisModule_OnLoad(RedisModuleCtx *ctx)
{
	RedisModuleTypeMethods tm = {
		.version = REDISMODULE_TYPE_METHOD_VERSION,
		.rdb_load = knot_zone_rrset_load,
		.rdb_save = knot_zone_rrset_save,
		.aof_rewrite = knot_zone_rrset_rewrite,
		.free = knot_zone_rrset_free
	};

	if (RedisModule_Init(ctx, "knot", 1, REDISMODULE_APIVER_1) == REDISMODULE_ERR) {
		return REDISMODULE_ERR;
	}

	knot_zone_rrset_t = RedisModule_CreateDataType(ctx, "KnotRRset", // Note: Name length has to be exactly 9
	                                               KNOT_ZONE_RRSET_ENCODING_VERSION,
	                                               &tm);
	if (knot_zone_rrset_t == NULL) {
		RedisModule_Log(ctx, REDISMODULE_LOGLEVEL_WARNING, "ERR 'knot' module already loaded");
		RedisModule_ReplyWithError(ctx, "ERR 'knot' module already loaded");
		return REDISMODULE_ERR;
	}

	if (	RedisModule_CreateCommand(ctx, "knot.zone.exists", knot_zone_exists, "readonly", 1, 1, 1) == REDISMODULE_ERR ||
		RedisModule_CreateCommand(ctx, "knot.zone.load", knot_zone_load, "readonly", 1, 1, 1) == REDISMODULE_ERR ||
		RedisModule_CreateCommand(ctx, "knot.zone.purge", knot_zone_purge, "write pubsub", 1, 1, 1) == REDISMODULE_ERR ||
		RedisModule_CreateCommand(ctx, "knot.rrset.store", knot_rrset_store, "write pubsub", 1, 1, 1) == REDISMODULE_ERR
	) {
		RedisModule_Log(ctx, REDISMODULE_LOGLEVEL_WARNING, "ERR 'knot' module already loaded");
		RedisModule_ReplyWithError(ctx, "ERR 'knot' module already loaded");
		return REDISMODULE_ERR;
	}

	return REDISMODULE_OK;
}
