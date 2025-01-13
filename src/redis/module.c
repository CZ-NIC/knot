#include "redismodule.h"

static RedisModuleType *KnotZoneType;
#define KNOT_ZONE_KEY_ENCODING_VERSION 0

typedef struct {
	char zone[5];
	char owner[5];
	short type;
}  KnotZoneK;

typedef struct {
	int ttl;
	char data[5];
}  KnotZoneV;

// static void KnotZoneRDBSave(RedisModuleIO *rdb, void *value)
// {
// 	RedisModuleKey *key = RedisModule_OpenKey(rdb, value,
// 	                                          REDISMODULE_WRITE);
// 	KnotZoneV data = { 0 };
// 	RedisModule_ModuleTypeSetValue(key, KnotZoneType, &data);
// }

int knot_zone_insert(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	RedisModule_ReplyWithLongLong(ctx, 0);
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

	if (RedisModule_CreateCommand(ctx, "knot.zone.insert", knot_zone_insert, "write", 1, 1, 1) == REDISMODULE_ERR) {
		return REDISMODULE_ERR;
	}
}