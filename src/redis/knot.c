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

#include "contrib/redis/redismodule.h"

#define KNOT_ZONE_RRSET_ENCODING_VERSION 0

#define KNOT_DNAME_MAXLEN 255
#define KNOT_RRSET_KEY_MAXLEN (1 + sizeof(uint32_t) + KNOT_DNAME_MAXLEN + sizeof(uint16_t))

#define RRTYPE_SOA 6

#define KNOT_SCORE_SOA     0.
#define KNOT_SCORE_DEFAULT 1.

#define KNOT_CHANNEL "knot.events"

#define find_zone(ctx, origin, rights)       find1(ZONE, (ctx), (origin), (rights))
#define find_zone_index(ctx, origin, rights) find1(ZONE_INDEX, (ctx), (origin), (rights))

#define foreach_in_zset_subset(key, min, max) \
		for (RedisModule_ZsetFirstInScoreRange(key, min, max, 0, 0); \
		     RedisModule_ZsetRangeEndReached(key) == false; \
		     RedisModule_ZsetRangeNext(key))
#define foreach_in_zset(key) foreach_in_zset_subset(key, REDISMODULE_NEGATIVE_INFINITE, REDISMODULE_POSITIVE_INFINITE)

typedef enum {
	ZONE,
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

struct rrset_list_ctx {
	RedisModuleString *origin;
	long ctr;
	uint32_t lookup_id;
};

static RedisModuleType *knot_zone_rrset_t;

typedef uint8_t knot_dname_t;

size_t knot_dname_size(const knot_dname_t *name)
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

static inline RedisModuleKey *find1(const uint8_t prefix, RedisModuleCtx *ctx, const knot_dname_t *origin, int rights)
{
	if (ctx == NULL || origin == NULL) {
		return NULL;
	}

	const size_t origin_len = knot_dname_size(origin);
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

static int read_zone_id(RedisModuleKey *key, uint32_t *id)
{
	if (RedisModule_KeyType(key) != REDISMODULE_KEYTYPE_STRING) {
		return -1;
	}
	size_t len = 0;
	const uint32_t *val = (const uint32_t *)RedisModule_StringDMA(key, &len, REDISMODULE_READ);
	if (len != sizeof(uint32_t)) {
		return -1;
	}
	memcpy(id, val, sizeof(uint32_t));
	return 0;
}

static int knot_zone_exists(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 2) {
		return RedisModule_WrongArity(ctx);
	}

	size_t origin_len = 0;
	const knot_dname_t *origin_dname = (const knot_dname_t *)RedisModule_StringPtrLen(argv[1], &origin_len);

	RedisModuleKey *zone_index_key = find_zone_index(ctx, origin_dname, REDISMODULE_READ);
	if (zone_index_key == NULL) {
		return RedisModule_ReplyWithLongLong(ctx, false);
	} else if (RedisModule_KeyType(zone_index_key) == REDISMODULE_KEYTYPE_EMPTY) {
		RedisModule_CloseKey(zone_index_key);
		return RedisModule_ReplyWithLongLong(ctx, false);
	} else if (RedisModule_KeyType(zone_index_key) != REDISMODULE_KEYTYPE_ZSET) {
		RedisModule_CloseKey(zone_index_key);
		return RedisModule_ReplyWithError(ctx, "ERR Bad data");
	}

	RedisModule_ZsetFirstInScoreRange(zone_index_key, KNOT_SCORE_SOA, KNOT_SCORE_SOA, 0, 0);
	bool exists = !RedisModule_ZsetRangeEndReached(zone_index_key);
	RedisModule_ZsetRangeStop(zone_index_key);
	RedisModule_CloseKey(zone_index_key);

	return RedisModule_ReplyWithLongLong(ctx, exists);
}

static int knot_zone_load(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 2) {
		return RedisModule_WrongArity(ctx);
	}

	size_t origin_len = 0;
	const knot_dname_t *origin_dname = (const knot_dname_t *)RedisModule_StringPtrLen(argv[1], &origin_len);

	RedisModuleKey *zone_index_key = find_zone_index(ctx, origin_dname, REDISMODULE_READ);
	if (zone_index_key == NULL) {
		return RedisModule_ReplyWithError(ctx, "ERR Unable find");
	}
	int zone_index_type = RedisModule_KeyType(zone_index_key);
	if (zone_index_type == REDISMODULE_KEYTYPE_EMPTY) {
		RedisModule_CloseKey(zone_index_key);
		return RedisModule_ReplyWithError(ctx, "ERR Does not exist");
	} else if (zone_index_type != REDISMODULE_KEYTYPE_ZSET) {
		RedisModule_CloseKey(zone_index_key);
		return RedisModule_ReplyWithError(ctx, "ERR Bad data");
	}

	long count = 0;
	RedisModule_ReplyWithArray(ctx, REDISMODULE_POSTPONED_ARRAY_LEN);
	foreach_in_zset (zone_index_key) {
		double score = 0.0;
		RedisModuleString *el = RedisModule_ZsetRangeCurrentElement(zone_index_key, &score);
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
		RedisModule_ReplyWithStringBuffer(ctx, rrset_str + 5, rrset_strlen - (5 + 2));
		RedisModule_ReplyWithLongLong(ctx, rtype);
		RedisModule_ReplyWithLongLong(ctx, rrset->ttl);
		RedisModule_ReplyWithLongLong(ctx, rrset->rrs.count);
		RedisModule_ReplyWithStringBuffer(ctx, (const char *)rrset->rrs.rdata, rrset->rrs.size);

		++count;
	}
	RedisModule_ZsetRangeStop(zone_index_key);
	RedisModule_CloseKey(zone_index_key);
	RedisModule_ReplySetArrayLength(ctx, count);

	return REDISMODULE_OK;
}

static int knot_zone_purge(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 2) {
		return RedisModule_WrongArity(ctx);
	}

	size_t origin_len = 0;
	const knot_dname_t *origin_dname = (const knot_dname_t *)RedisModule_StringPtrLen(argv[1], &origin_len);

	RedisModuleKey *zone_index_key = find_zone_index(ctx, origin_dname, REDISMODULE_READ | REDISMODULE_WRITE);
	if (zone_index_key == NULL) {
		return RedisModule_ReplyWithError(ctx, "ERR Unable find");
	}

	int zone_index_type = RedisModule_KeyType(zone_index_key);
	if (zone_index_type == REDISMODULE_KEYTYPE_EMPTY) {
		RedisModule_CloseKey(zone_index_key);
		return RedisModule_ReplyWithError(ctx, "ERR Does not exist");
	} else if (zone_index_type != REDISMODULE_KEYTYPE_ZSET) {
		RedisModule_CloseKey(zone_index_key);
		return RedisModule_ReplyWithError(ctx, "ERR Bad data");
	}

	foreach_in_zset (zone_index_key) {
		double score = 0.0;
		RedisModuleString *el = RedisModule_ZsetRangeCurrentElement(zone_index_key, &score);
		if (el == NULL) {
			break;
		}

		RedisModuleKey *rrset_key = RedisModule_OpenKey(ctx, el, REDISMODULE_READ | REDISMODULE_WRITE);
		RedisModule_DeleteKey(rrset_key);
		RedisModule_CloseKey(rrset_key);
	}
	RedisModule_ZsetRangeStop(zone_index_key);
	RedisModule_DeleteKey(zone_index_key);
	RedisModule_CloseKey(zone_index_key);

	RedisModuleKey *zone_key = find_zone(ctx, origin_dname, REDISMODULE_READ | REDISMODULE_WRITE);
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

	size_t origin_strlen;
	const knot_dname_t *origin_dname = (const knot_dname_t *)RedisModule_StringPtrLen(argv[1], &origin_strlen);

	RedisModuleKey *zone_key = find_zone(ctx, origin_dname, REDISMODULE_READ | REDISMODULE_WRITE);
	if (zone_key == NULL) {
		return RedisModule_ReplyWithError(ctx, "ERR Unable find");
	}
	RedisModuleString *zone_id = NULL;
	if (RedisModule_KeyType(zone_key) != REDISMODULE_KEYTYPE_EMPTY) {
		uint32_t id = 0;
		int ret = read_zone_id(zone_key, &id);
		if (ret == -1) {
			RedisModule_CloseKey(zone_key);
			return RedisModule_ReplyWithError(ctx, "ERR Bad data");
		}
		zone_id = RedisModule_CreateString(ctx, (const char *)&id, sizeof(id));
	} else {
		uint32_t id;
		RedisModule_GetRandomBytes((unsigned char *)&id, sizeof(id));
		zone_id = RedisModule_CreateString(ctx, (const char *)&id, sizeof(id));
		RedisModule_StringSet(zone_key, zone_id);
	}
	RedisModule_CloseKey(zone_key);

	size_t zoneid_strlen, owner_strlen;
	const char *zoneid_str = RedisModule_StringPtrLen(zone_id, &zoneid_strlen);
	const char *owner_str = RedisModule_StringPtrLen(argv[2], &owner_strlen);
	long long type = 0;
	int ret = RedisModule_StringToLongLong(argv[3], &type);
	if (ret != REDISMODULE_OK) {
		RedisModule_FreeString(ctx, zone_id);
		return RedisModule_ReplyWithError(ctx, "ERR Wrong RRTYPE format");
	} else if (type < 0 || type > UINT16_MAX) {
		RedisModule_FreeString(ctx, zone_id);
		return RedisModule_ReplyWithError(ctx, "ERR Value out of range");
	}
	uint16_t rtype = type;
	uint8_t key_data[KNOT_RRSET_KEY_MAXLEN];
	uint8_t *key_ptr = key_data;
	key_ptr[0] = RRSET;
	key_ptr = memcpy(key_ptr + 1, zoneid_str, zoneid_strlen);
	key_ptr = memcpy(key_ptr + zoneid_strlen, owner_str, owner_strlen);
	key_ptr = memcpy(key_ptr + owner_strlen, &rtype, sizeof(rtype));
	key_ptr += sizeof(rtype);

	RedisModule_FreeString(ctx, zone_id);
	RedisModuleString *key_str = RedisModule_CreateString(ctx, (const char *)key_data, key_ptr - key_data);

	// NOTE remove this when testing legacy rrset scanning (without ZONE_INDEX)
	static const uint8_t zone_index_prefix = ZONE_INDEX;
	RedisModuleString *list_key_str =  RedisModule_CreateString(ctx, (const char *)(&zone_index_prefix), sizeof(zone_index_prefix));
	ret = RedisModule_StringAppendBuffer(ctx, list_key_str, (const char *)origin_dname, origin_strlen);
	RedisModuleKey *zone_index_key = RedisModule_OpenKey(ctx, list_key_str, REDISMODULE_READ | REDISMODULE_WRITE);
	RedisModule_FreeString(ctx, list_key_str);
	RedisModule_ZsetAdd(zone_index_key, evaluate_score(rtype), key_str, NULL);
	RedisModule_CloseKey(zone_index_key);
	// END OF BLOCK

	RedisModuleKey *rrset_key = RedisModule_OpenKey(ctx, key_str, REDISMODULE_READ | REDISMODULE_WRITE);
	RedisModule_FreeString(ctx, key_str);

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
