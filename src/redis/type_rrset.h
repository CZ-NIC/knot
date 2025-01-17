/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: LGPL-2.1-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#define RRSET_ENCODING_VERSION	1
#define RRSET_NAME		"KnotRRset"

typedef struct {
	knot_rdataset_t rrs;
	uint32_t ttl;
} rrset_v;

static RedisModuleType *rdb_rrset_t;

static void *rrset_load(RedisModuleIO *rdb, int encver)
{
	if (encver != RRSET_ENCODING_VERSION) {
		// TODO ignore or version compatibility layers
		return NULL;
	}

	rrset_v *rrset = RedisModule_Alloc(sizeof(rrset_v));
	if (rrset == NULL) {
		return NULL;
	}
	size_t len = 0;
	rrset->rrs.count = RedisModule_LoadUnsigned(rdb);
	rrset->rrs.rdata = (knot_rdata_t *)RedisModule_LoadStringBuffer(rdb, &len);
	if (len > UINT32_MAX) {
		RedisModule_Free(rrset->rrs.rdata);
		RedisModule_Free(rrset);
		return NULL;
	}
	rrset->rrs.size = len;

	rrset->ttl = RedisModule_LoadUnsigned(rdb);

	return rrset;
}

static void rrset_save(RedisModuleIO *rdb, void *value)
{
	rrset_v *rrset = (rrset_v *)value;

	RedisModule_SaveUnsigned(rdb, rrset->rrs.count);
	RedisModule_SaveStringBuffer(rdb, (const char *)rrset->rrs.rdata, rrset->rrs.size);

	RedisModule_SaveUnsigned(rdb, rrset->ttl);
}

static size_t rrset_mem_usage(const void *value)
{
	const rrset_v *rrset = (const rrset_v *)value;
	if (value == NULL) {
		return 0UL;
	}
	return sizeof(*rrset) + rrset->rrs.size;
}

static void rrset_rewrite(RedisModuleIO *aof, RedisModuleString *key, void *value)
{
	size_t key_strlen = 0;
	const rrset_v *rrset = (const rrset_v *)value;
	const uint8_t *key_str = (const uint8_t *)RedisModule_StringPtrLen(key, &key_strlen);
	RedisModule_EmitAOF(aof, "KNOT_BIN.AOF.RRSET", "blbl",
	                    key_str, key_strlen,
	                    (long long)rrset->rrs.count,
	                    rrset->rrs.rdata, rrset->rrs.size,
	                    (long long)rrset->ttl);
}

static void rrset_free(void *value)
{
	rrset_v *rrset = (rrset_v *)value;
	RedisModule_Free(rrset->rrs.rdata);
	RedisModule_Free(rrset);
}

static int rrset_aof_rewrite(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 5) {
		return RedisModule_WrongArity(ctx);
	}

	rrset_v *rrset = RedisModule_Calloc(1, sizeof(rrset_v));
	if (rrset == NULL) {
		return RedisModule_ReplyWithError(ctx, "ERR Cannot allocate memory");
	}

	RedisModuleKey *rrset_key = RedisModule_OpenKey(ctx, argv[1], REDISMODULE_READ | REDISMODULE_WRITE);

	long long count_val = 0;
	int ret = RedisModule_StringToLongLong(argv[3], &count_val);
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

	long long ttl_val = 0;
	ret = RedisModule_StringToLongLong(argv[2], &ttl_val);
	if (ret != REDISMODULE_OK) {
		RedisModule_CloseKey(rrset_key);
		return RedisModule_ReplyWithError(ctx, "ERR Not a number");
	} else if (ttl_val < 0 || ttl_val > UINT32_MAX) {
		RedisModule_CloseKey(rrset_key);
		return RedisModule_ReplyWithError(ctx, "ERR Value out of range");
	}
	rrset->ttl = ttl_val;

	RedisModule_ModuleTypeSetValue(rrset_key, rdb_rrset_t, rrset);
	RedisModule_CloseKey(rrset_key);

	return RedisModule_ReplyWithNull(ctx);
}

RedisModuleTypeMethods rrset_tm = {
	.version = REDISMODULE_TYPE_METHOD_VERSION,
	.rdb_load = rrset_load,
	.rdb_save = rrset_save,
	.mem_usage = rrset_mem_usage,
	.aof_rewrite = rrset_rewrite,
	.free = rrset_free
};
