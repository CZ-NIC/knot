#include "redismodule.h"

#define KNOT_ZONE_KEY_ENCODING_VERSION 0

typedef enum {
	COUNTERS, //TODO replace random with counter ??
	ZONE,
	RRSET
} KnotTypeID;

typedef struct {
	char zone[5];
	char owner[5];
	short type;
}  KnotZoneK;

typedef struct {
	int ttl;
	char data[5];
}  KnotZoneV;

static RedisModuleType *KnotZoneType;

// static void KnotZoneRDBSave(RedisModuleIO *rdb, void *value)
// {
// 	RedisModuleKey *key = RedisModule_OpenKey(rdb, value,
// 	                                          REDISMODULE_WRITE);
// 	KnotZoneV data = { 0 };
// 	RedisModule_ModuleTypeSetValue(key, KnotZoneType, &data);
// }


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
		RedisModule_ReplyWithError(ctx, "Missing argument");
		return REDISMODULE_OK;
	}

	RedisModuleKey *zone_k = find_zone(ctx, argv[1], REDISMODULE_READ | REDISMODULE_WRITE);
	if (zone_k == NULL || RedisModule_KeyType(zone_k) != REDISMODULE_KEYTYPE_EMPTY) {
		RedisModule_CloseKey(zone_k);
		RedisModule_ReplyWithError(ctx, "Already exists");
		return REDISMODULE_OK;
	}

	long long id;
	RedisModule_GetRandomBytes((unsigned char *)&id, sizeof(id));
	RedisModuleString *zone_id = RedisModule_CreateStringFromLongLong(ctx, id);
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
	RedisModule_ReplyWithArray(ctx, REDISMODULE_POSTPONED_LEN);

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

	RedisModuleString *key_str = RedisModule_CreateStringPrintf(
		ctx,
		"%c%.*s%.*s%.*s",
		RRSET,
		(int)zoneid_strlen, zoneid_str,
		(int)owner_strlen, owner_str,
		(int)type_strlen, type_str);
	RedisModuleKey *key = RedisModule_OpenKey(ctx, key_str, rights);

	RedisModule_FreeString(ctx, key_str);
	return key;
}

int knot_rrset_insert(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc < 4) {
		RedisModule_ReplyWithError(ctx, "Missing argument");
		return REDISMODULE_OK;
	}
	if (argc > 5) { //TODO Set 5th argument custom TTL
		RedisModule_ReplyWithError(ctx, "Too many argument");
		return REDISMODULE_OK;
	}

	RedisModuleKey *zone_k = find_zone(ctx, argv[1], REDISMODULE_READ | REDISMODULE_WRITE);
	RedisModuleString *zone_id = NULL;
	if (zone_k == NULL || RedisModule_KeyType(zone_k) != REDISMODULE_KEYTYPE_EMPTY) {
		zone_id = RedisModule_CreateStringFromString(ctx, RedisModule_GetKeyNameFromModuleKey(zone_k));
		goto insert_rrset;
	}

	long long id;
	RedisModule_GetRandomBytes((unsigned char *)&id, sizeof(id));
	zone_id = RedisModule_CreateStringFromLongLong(ctx, id);
	RedisModule_StringSet(zone_k, zone_id);
	RedisModule_CloseKey(zone_k);

insert_rrset:
	RedisModuleKey *rrset_k = find_rrset(ctx, zone_id, argv[2], argv[3], REDISMODULE_READ | REDISMODULE_WRITE);
	if (rrset_k == NULL || RedisModule_KeyType(rrset_k) != REDISMODULE_KEYTYPE_EMPTY) {
		RedisModule_CloseKey(zone_k);
		RedisModule_ReplyWithError(ctx, "Already exists");
		return REDISMODULE_OK;
	}
	RedisModuleString *ttl = RedisModule_CreateStringFromLongLong(ctx, 3600);
	RedisModule_ListInsert(rrset_k, 0, ttl); //TODO Right now just list, make it own structure

	RedisModule_ReplyWithString(ctx, ttl);

	RedisModule_FreeString(ctx, zone_id);
	RedisModule_FreeString(ctx, ttl);

	return REDISMODULE_OK;
}

int RedisModule_OnLoad(RedisModuleCtx *ctx)
{
	// RedisModuleTypeMethods tm = {
	// 	.version = REDISMODULE_TYPE_METHOD_VERSION,
	// 	.rdb_load = KnotZoneRDBLoad,
	// 	.rdb_save = KnotZoneRDBSave,
	// 	.aof_rewrite = MyTypeAOFRewrite,
	// 	.free = MyTypeFree
	// };

	// KnotZoneType = RedisModule_CreateDataType(ctx, "KnotZoneT", // Note: Name length has to be exactly 9
	//                                           KNOT_ZONE_KEY_ENCODING_VERSION,
	//                                           &tm);
	// if (KnotZoneType == NULL) {
	// 	return REDISMODULE_ERR;
	// }

	// return REDISMODULE_OK;

	if (RedisModule_Init(ctx, "knot", 1, REDISMODULE_APIVER_1) == REDISMODULE_ERR) {
		return REDISMODULE_ERR;
	}

	if (
		// RedisModule_CreateCommand(ctx, "knot.zone.get", knot_zone_insert, "readonly", 1, 1, 1) == REDISMODULE_ERR ||
		RedisModule_CreateCommand(ctx, "knot.zone.insert", knot_zone_insert, "write", 1, 1, 1) == REDISMODULE_ERR ||
		RedisModule_CreateCommand(ctx, "knot.zone.list", knot_zone_list, "readonly", 1, 1, 1) == REDISMODULE_ERR ||
		RedisModule_CreateCommand(ctx, "knot.rrset.insert", knot_rrset_insert, "write", 1, 1, 1) == REDISMODULE_ERR
	) {
		return REDISMODULE_ERR;
	}

	return REDISMODULE_OK;
}