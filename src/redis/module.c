#include "redismodule.h"

#define KNOT_ZONE_KEY_ENCODING_VERSION 0

typedef enum {
	STORAGE,
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
		return REDISMODULE_ERR;
	}

	RedisModuleKey *zone_k = find_zone(ctx, argv[1], REDISMODULE_WRITE);
	if (zone_k == NULL || RedisModule_KeyType(zone_k) != REDISMODULE_KEYTYPE_EMPTY) {
		RedisModule_CloseKey(zone_k);
		RedisModule_ReplyWithError(ctx, "Already exists");
		return REDISMODULE_ERR;
	}

	long long id;
	RedisModule_GetRandomBytes((unsigned char *)&id, sizeof(id));
	RedisModuleString *zone_id = RedisModule_CreateStringFromLongLong(ctx, id);
	RedisModule_StringSet(zone_k, zone_id);

	RedisModule_ReplyWithString(ctx, zone_id);

	RedisModule_FreeString(ctx, zone_id);
	RedisModule_CloseKey(zone_k);

	RedisModule_ReplyWithString(ctx, zone_id);

	return REDISMODULE_OK;
}

// static void zone_list_format_cb(RedisModuleCtx *ctx, RedisModuleString *keyname, RedisModuleKey *key, void *privdata)
// {
// 	RedisModule_ReplyWithString(ctx, keyname);
// }

// int knot_zone_list(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
// {
// 	if (argc != 1) {
// 		RedisModule_ReplyWithError(ctx, "Missing argument");
// 		return REDISMODULE_ERR;
// 	}

// 	RedisModuleScanCursor *cursor = RedisModule_ScanCursorCreate();
// 	int ret = RedisModule_Scan(ctx, cursor, zone_list_format_cb, NULL);
// 	RedisModule_ScanCursorDestroy(cursor);

// 	RedisModule_ReplyWithLongLong(ctx, 0); // TODO ??
// 	return REDISMODULE_OK;
// }


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

	if (RedisModule_CreateCommand(ctx, "knot.zone.insert", knot_zone_insert, "write", 1, 1, 1) == REDISMODULE_ERR) {
		return REDISMODULE_ERR;
	}

	// if (RedisModule_CreateCommand(ctx, "knot.zone.list", knot_zone_list, "read", 1, 1, 1) == REDISMODULE_ERR) {
	// 	return REDISMODULE_ERR;
	// }

	return REDISMODULE_OK;
}