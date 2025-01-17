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

#include "contrib/redis/redismodule.h"
#include "libdnssec/random.h"

#define KNOT_ZONE_RRSET_ENCODING_VERSION 0

typedef enum {
	COUNTERS, //TODO replace random with counter ??
	ZONE,
	RRSET
} KnotTypeID;

typedef struct {
	uint16_t len;
	uint8_t data[];
} knot_zone_rdata_v;

typedef struct {
	uint16_t count;
	uint32_t size;
	knot_zone_rdata_v *rdata;
}  knot_zone_rdataset_v;

typedef struct {
	uint32_t ttl;
	uint16_t rclass;
	knot_zone_rdataset_v rrs;
}  knot_zone_rrset_v;

static RedisModuleType *knot_zone_rrset_t;

#include <string.h>

static void *knot_zone_rrset_load(RedisModuleIO *rdb, int encver)
{
	if (encver != KNOT_ZONE_RRSET_ENCODING_VERSION) {
		// TODO or version compatibility layers
		return NULL;
	}

	knot_zone_rrset_v *rrset = RedisModule_Alloc(sizeof(knot_zone_rrset_v));
	rrset->ttl = RedisModule_LoadUnsigned(rdb);
	rrset->rclass = RedisModule_LoadUnsigned(rdb);
	rrset->rrs.count = RedisModule_LoadUnsigned(rdb);
	rrset->rrs.size = RedisModule_LoadUnsigned(rdb);
	if (rrset->rrs.size == 0) {
		rrset->rrs.rdata = RedisModule_Alloc(rrset->rrs.size);
		uint8_t *pos = (uint8_t *)rrset->rrs.rdata;
		for (size_t idx = 0; idx < rrset->rrs.count; ++idx) {
			knot_zone_rdata_v *rdata = (knot_zone_rdata_v *)pos;
			size_t len;
			char *rdata_data = RedisModule_LoadStringBuffer(rdb, &len);
			rdata->len = len;
			memcpy(rdata->data, rdata_data, rdata->len);
			pos += sizeof(knot_zone_rdata_v) + rdata->len;
		}
	}
	return rrset;

}

static void knot_zone_rrset_save(RedisModuleIO *rdb, void *value)
{
	knot_zone_rrset_v *rrset = (knot_zone_rrset_v *)value;
	RedisModule_SaveUnsigned(rdb, rrset->ttl);
	RedisModule_SaveUnsigned(rdb, rrset->rclass);
	RedisModule_SaveUnsigned(rdb, rrset->rrs.count);
	RedisModule_SaveUnsigned(rdb, rrset->rrs.size);
	if (rrset->rrs.size) {
		uint8_t *pos = (uint8_t *)rrset->rrs.rdata;
		for (size_t idx = 0; idx < rrset->rrs.count; ++idx) {
			knot_zone_rdata_v *rdata = (knot_zone_rdata_v *)pos;
			RedisModule_SaveStringBuffer(rdb, rdata->data, rdata->len);
			pos += sizeof(knot_zone_rdata_v) + rdata->len;
		}
	}
}

static void knot_zone_rrset_rewrite(RedisModuleIO *aof, RedisModuleString *key, void *value)
{
	// TODO
	RedisModule_EmitAOF(aof, "KNOT.RRSET.INSERT", "sss", "com.", "dns1.example.com.", "A");
}

static void knot_zone_rrset_free(void *value)
{
	knot_zone_rrset_v *rrset = (knot_zone_rrset_v *)value;
	RedisModule_Free(rrset->rrs.rdata);
	RedisModule_Free(value);
}

// #include "../libknot/dname.h"

static RedisModuleKey *find_zone(RedisModuleCtx *ctx, RedisModuleString *zone, int rights)
{
	size_t zone_str_len;
	const char *zone_str = RedisModule_StringPtrLen(zone, &zone_str_len);
	// uint8_t dname_data[256];
	// int dname_data_len = 0;
	// if (knot_dname_from_str(dname_data, zone_str, sizeof(dname_data)) == NULL) {
		// return NULL;
	// }
	// if (zone_str_len > UINT32_MAX) {
	// 	return NULL;
	// }

	// RedisModuleString *key_str = RedisModule_CreateStringPrintf(ctx, "%c%.*s", ZONE, dname_data_len, dname_data);

	if (zone_str_len > UINT32_MAX) {
		return NULL;
	}

	RedisModuleString *key_str = RedisModule_CreateStringPrintf(ctx, "%c%.*s", ZONE, (int)zone_str_len, zone_str);
	RedisModuleKey *key = RedisModule_OpenKey(ctx, key_str, rights);

	RedisModule_FreeString(ctx, key_str);
	return key;
}


int knot_zone_insert(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 2) {
		return RedisModule_WrongArity(ctx);
	}

	RedisModuleKey *zone_k = find_zone(ctx, argv[1], REDISMODULE_READ | REDISMODULE_WRITE);
	if (zone_k != NULL && RedisModule_KeyType(zone_k) != REDISMODULE_KEYTYPE_EMPTY) {
		RedisModule_CloseKey(zone_k);
		RedisModule_ReplyWithError(ctx, "Already exists");
		return REDISMODULE_OK;
	}

	uint32_t id = dnssec_random_uint32_t();
	RedisModuleString *zone_id = RedisModule_CreateString(ctx, (const char*)&id, sizeof(id));
	RedisModule_StringSet(zone_k, zone_id);

	RedisModule_ReplyWithString(ctx, zone_id);

	RedisModule_FreeString(ctx, zone_id);
	RedisModule_CloseKey(zone_k);

	return REDISMODULE_OK;
}

static void zone_list_cb(RedisModuleCtx *ctx, RedisModuleString *keyname, RedisModuleKey *key, void *privdata)
{
	size_t len = 0;
	const char *k = RedisModule_StringPtrLen(keyname, &len);
	if (k[0] != ZONE) {
		return;
	}

	long *ctr = privdata;
	++(*ctr);

	RedisModule_ReplyWithStringBuffer(ctx, k + 1, len - 1);
}

int knot_zone_list(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 1) {
		RedisModule_ReplyWithError(ctx, "Missing argument");
		return REDISMODULE_ERR;
	}

	long ctr = 0;
	RedisModule_ReplyWithArray(ctx, REDISMODULE_POSTPONED_ARRAY_LEN);

	RedisModuleScanCursor *cursor = RedisModule_ScanCursorCreate();
	while (RedisModule_Scan(ctx, cursor, zone_list_cb, &ctr) != 0);
	RedisModule_ScanCursorDestroy(cursor);

	RedisModule_ReplySetArrayLength(ctx, ctr);
	return REDISMODULE_OK;
}

static RedisModuleKey *find_rrset(RedisModuleCtx *ctx,
                                  const RedisModuleString *zone_id,
                                  RedisModuleString *owner,
                                  RedisModuleString *type,
                                  int rights)
{
	size_t zoneid_strlen, owner_strlen, type_strlen;
	const char *zoneid_str = RedisModule_StringPtrLen(zone_id, &zoneid_strlen);
	const char *owner_str = RedisModule_StringPtrLen(owner, &owner_strlen);
	const char *type_str = RedisModule_StringPtrLen(type, &type_strlen);

	RedisModuleString *key_str = RedisModule_CreateStringPrintf(ctx, "%c", RRSET);
	RedisModule_StringAppendBuffer(ctx, key_str, zoneid_str, zoneid_strlen);
	RedisModule_StringAppendBuffer(ctx, key_str, owner_str, owner_strlen);
	RedisModule_StringAppendBuffer(ctx, key_str, type_str, type_strlen);
	RedisModuleKey *key = RedisModule_OpenKey(ctx, key_str, rights);

	RedisModule_FreeString(ctx, key_str);
	return key;
}

int knot_rrset_insert(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc < 4 || argc > 5) { // TODO 5th argument TTL
		return RedisModule_WrongArity(ctx);
	}

	RedisModuleKey *zone_k = find_zone(ctx, argv[1], REDISMODULE_READ | REDISMODULE_WRITE);
	RedisModuleString *zone_id = NULL;
	if (zone_k != NULL && RedisModule_KeyType(zone_k) != REDISMODULE_KEYTYPE_EMPTY) {
		size_t len = 0;
		const char *val = RedisModule_StringDMA(zone_k, &len, REDISMODULE_READ);
		zone_id = RedisModule_CreateString(ctx, val, len);
		goto insert_rrset;
	}

	uint32_t id = dnssec_random_uint32_t();
	zone_id = RedisModule_CreateString(ctx, (const char *)&id, sizeof(id));
	RedisModule_StringSet(zone_k, zone_id);
	RedisModule_CloseKey(zone_k);

insert_rrset:
	RedisModuleKey *rrset_k = find_rrset(ctx, zone_id, argv[2], argv[3], REDISMODULE_READ | REDISMODULE_WRITE);
	if (rrset_k != NULL && RedisModule_KeyType(rrset_k) != REDISMODULE_KEYTYPE_EMPTY) {
		RedisModule_CloseKey(zone_k);
		RedisModule_ReplyWithError(ctx, "Already exists");
		return REDISMODULE_OK;
	}

	knot_zone_rrset_v *rrset = RedisModule_Alloc(sizeof(knot_zone_rrset_v));
	rrset->ttl = 3600;
	rrset->rclass = 1;
	rrset->rrs = (knot_zone_rdataset_v){
		.count = 0,
		.size = 0
	};

	RedisModuleString *ttl = RedisModule_CreateStringFromLongLong(ctx, rrset->ttl);
	RedisModule_ModuleTypeSetValue(rrset_k, knot_zone_rrset_t, rrset);
	RedisModule_CloseKey(rrset_k);

	// RedisModule_ListInsert(rrset_k, 0, ttl); //TODO Right now just list, make it own structure

	RedisModule_ReplyWithString(ctx, ttl);


	RedisModule_FreeString(ctx, zone_id);
	RedisModule_FreeString(ctx, ttl);

	return REDISMODULE_OK;
}


int knot_rrset_get(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 5) {
		return RedisModule_WrongArity(ctx);
	}

	RedisModuleKey *zone_k = find_zone(ctx, argv[1], REDISMODULE_READ);
	if (zone_k == NULL || RedisModule_KeyType(zone_k) == REDISMODULE_KEYTYPE_EMPTY) {
		RedisModule_ReplyWithError(ctx, "Does not exist");
		return REDISMODULE_ERR;
	}
	size_t len = 0;
	const char *val = RedisModule_StringDMA(zone_k, &len, REDISMODULE_READ);
	RedisModuleString *zone_id = RedisModule_CreateString(ctx, val, len);
	RedisModule_CloseKey(zone_k);

	RedisModuleKey *rrset_k = find_rrset(ctx, zone_id, argv[2], argv[3], REDISMODULE_READ);
	if (rrset_k == NULL || RedisModule_KeyType(rrset_k) == REDISMODULE_KEYTYPE_EMPTY) {
		RedisModule_ReplyWithError(ctx, "Does not exist");
		return REDISMODULE_ERR;
	}
	RedisModule_FreeString(ctx, zone_id);

	if (RedisModule_ModuleTypeGetType(rrset_k) != knot_zone_rrset_t) {
		RedisModule_ReplyWithError(ctx, "Wrong type");
		return REDISMODULE_ERR;
	}
	knot_zone_rrset_v *rrset = RedisModule_ModuleTypeGetValue(rrset_k);
	RedisModule_CloseKey(rrset_k);
	//TODO parse last command argument (TTL, RCLASS etc.)
	RedisModule_ReplyWithLongLong(ctx, rrset->ttl);

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
	                                               KNOT_ZONE_RRSET_ENCODING_VERSION, &tm);
	if (knot_zone_rrset_t == NULL) {
		return REDISMODULE_ERR;
	}

	if (
		// RedisModule_CreateCommand(ctx, "knot.zone.get", knot_zone_insert, "readonly", 1, 1, 1) == REDISMODULE_ERR ||
		RedisModule_CreateCommand(ctx, "knot.zone.insert", knot_zone_insert, "write", 1, 1, 1) == REDISMODULE_ERR ||
		RedisModule_CreateCommand(ctx, "knot.zone.list", knot_zone_list, "readonly", 1, 1, 1) == REDISMODULE_ERR ||
		RedisModule_CreateCommand(ctx, "knot.rrset.insert", knot_rrset_insert, "write", 1, 1, 1) == REDISMODULE_ERR ||
		RedisModule_CreateCommand(ctx, "knot.rrset.get", knot_rrset_get, "readonly", 1, 1, 1) == REDISMODULE_ERR 
	) {
		return REDISMODULE_ERR;
	}

	return REDISMODULE_OK;
}
