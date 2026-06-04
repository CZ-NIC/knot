/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: LGPL-2.1-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#define GEOIP_ENCODING_VERSION	1
#define GEOIP_NAME		"KnotGeoIP"

typedef knot_rdataset_t geoip_v;

static RedisModuleType *rdb_geoip_t;

static void *rdb_geoip_load(RedisModuleIO *io, int encver)
{
	if (encver != GEOIP_ENCODING_VERSION) {
		RedisModule_LogIOError(io, REDISMODULE_LOGLEVEL_WARNING, RDB_ECOMPAT);
		return NULL;
	}

	geoip_v *rrset = RedisModule_Alloc(sizeof(geoip_v));
	if (rrset == NULL) {
		RedisModule_LogIOError(io, REDISMODULE_LOGLEVEL_WARNING, RDB_EALLOC);
		return NULL;
	}
	size_t len = 0;
	rrset->count = RedisModule_LoadUnsigned(io);
	rrset->rdata = (knot_rdata_t *)RedisModule_LoadStringBuffer(io, &len);
	if (len > UINT32_MAX) {
		RedisModule_LogIOError(io, REDISMODULE_LOGLEVEL_WARNING, RDB_EMALF);
		RedisModule_Free(rrset->rdata);
		RedisModule_Free(rrset);
		return NULL;
	}
	rrset->size = len;

	return rrset;
}

static void rdb_geoip_save(RedisModuleIO *io, void *value)
{
	geoip_v *rrset = (geoip_v *)value;

	RedisModule_SaveUnsigned(io, rrset->count);
	RedisModule_SaveStringBuffer(io, (const char *)rrset->rdata, rrset->size);
}

static size_t rdb_geoip_mem_usage(const void *value)
{
	const geoip_v *rrset = (const geoip_v *)value;
	if (value == NULL) {
		return 0UL;
	}
	return sizeof(*rrset) + rrset->size;
}

static void rdb_geoip_rewrite(RedisModuleIO *io, RedisModuleString *key, void *value)
{
	size_t key_strlen = 0;
	const geoip_v *rrset = (const geoip_v *)value;
	const uint8_t *key_str = (const uint8_t *)RedisModule_StringPtrLen(key, &key_strlen);
	RedisModule_EmitAOF(io, "KNOT_BIN.AOF.GEOPI", "blb",
	                    key_str, key_strlen,
	                    (long long)rrset->count,
	                    rrset->rdata, rrset->size);
}

static void rdb_geoip_free(void *value)
{
	geoip_v *rrset = (geoip_v *)value;
	RedisModule_Free(rrset->rdata);
	RedisModule_Free(rrset);
}

static int geoip_aof_rewrite(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	// TODO
	if (argc != 4) {
		return RedisModule_WrongArity(ctx);
	}

	geoip_v *rrset = RedisModule_Calloc(1, sizeof(geoip_v));
	if (rrset == NULL) {
		return RedisModule_ReplyWithError(ctx, RDB_EALLOC);
	}

	RedisModuleKey *rrset_key = RedisModule_OpenKey(ctx, argv[1], REDISMODULE_READ | REDISMODULE_WRITE);


	long long count_val = 0;
	int ret = RedisModule_StringToLongLong(argv[2], &count_val);
	if (ret != REDISMODULE_OK) {
		RedisModule_CloseKey(rrset_key);
		return RedisModule_ReplyWithError(ctx, RDB_EMALF);
	} else if (count_val < 0 || count_val > UINT16_MAX) {
		RedisModule_CloseKey(rrset_key);
		return RedisModule_ReplyWithError(ctx, RDB_EMALF);
	}
	rrset->count = count_val;

	size_t rdataset_strlen = 0;
	const char *rdataset_str = RedisModule_StringPtrLen(argv[3], &rdataset_strlen);
	if (rdataset_strlen > UINT32_MAX) {
		RedisModule_CloseKey(rrset_key);
		return RedisModule_ReplyWithError(ctx, RDB_EMALF);
	} else if (rdataset_strlen != 0) {
		rrset->rdata = RedisModule_Alloc(rdataset_strlen);
		rrset->size = rdataset_strlen;
		memcpy(rrset->rdata, rdataset_str, rdataset_strlen);
	} else {
		rrset->rdata = NULL;
		rrset->size = 0;
	}

	RedisModule_ModuleTypeSetValue(rrset_key, rdb_geoip_t, rrset);
	RedisModule_CloseKey(rrset_key);

	return RedisModule_ReplyWithNull(ctx);
}

RedisModuleTypeMethods geoip_tm = {
	.version = REDISMODULE_TYPE_METHOD_VERSION,
	.rdb_load = rdb_geoip_load,
	.rdb_save = rdb_geoip_save,
	.mem_usage = rdb_geoip_mem_usage,
	.aof_rewrite = rdb_geoip_rewrite,
	.free = rdb_geoip_free
};
