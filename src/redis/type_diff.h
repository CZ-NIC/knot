/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: LGPL-2.1-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#define DIFF_ENCODING_VERSION	1
#define DIFF_NAME		"KnotRdiff"

typedef struct {
	knot_rdataset_t add_rrs;
	knot_rdataset_t rem_rrs;
	uint32_t add_ttl;
	uint32_t rem_ttl;
} diff_v;

static RedisModuleType *rdb_diff_t;

static void *diff_load(RedisModuleIO *io, int encver)
{
	if (encver != DIFF_ENCODING_VERSION) {
		RedisModule_LogIOError(io, REDISMODULE_LOGLEVEL_WARNING, RDB_ECOMPAT);
		return NULL;
	}

	diff_v *diff = RedisModule_Alloc(sizeof(diff_v));
	if (diff == NULL) {
		RedisModule_LogIOError(io, REDISMODULE_LOGLEVEL_WARNING, RDB_EALLOC);
		return NULL;
	}
	size_t len = 0;
	diff->add_rrs.count = RedisModule_LoadUnsigned(io);
	diff->add_rrs.rdata = (knot_rdata_t *)RedisModule_LoadStringBuffer(io, &len);
	if (len > UINT32_MAX) {
		RedisModule_LogIOError(io, REDISMODULE_LOGLEVEL_WARNING, RDB_EMALF);
		RedisModule_Free(diff->add_rrs.rdata);
		RedisModule_Free(diff);
		return NULL;
	}
	diff->add_rrs.size = len;

	diff->rem_rrs.count = RedisModule_LoadUnsigned(io);
	diff->rem_rrs.rdata = (knot_rdata_t *)RedisModule_LoadStringBuffer(io, &len);
	if (len > UINT32_MAX) {
		RedisModule_LogIOError(io, REDISMODULE_LOGLEVEL_WARNING, RDB_EMALF);
		RedisModule_Free(diff->add_rrs.rdata);
		RedisModule_Free(diff->rem_rrs.rdata);
		RedisModule_Free(diff);
		return NULL;
	}
	diff->rem_rrs.size = len;

	diff->add_ttl = RedisModule_LoadUnsigned(io);
	diff->rem_ttl = RedisModule_LoadUnsigned(io);

	return diff;
}

static void diff_save(RedisModuleIO *io, void *value)
{
	diff_v *diff = (diff_v *)value;

	RedisModule_SaveUnsigned(io, diff->add_rrs.count);
	RedisModule_SaveStringBuffer(io, (const char *)diff->add_rrs.rdata, diff->add_rrs.size);

	RedisModule_SaveUnsigned(io, diff->rem_rrs.count);
	RedisModule_SaveStringBuffer(io, (const char *)diff->rem_rrs.rdata, diff->rem_rrs.size);

	RedisModule_SaveUnsigned(io, diff->add_ttl);
	RedisModule_SaveUnsigned(io, diff->rem_ttl);
}

static size_t diff_mem_usage(const void *value)
{
	const diff_v *diff = (const diff_v *)value;
	if (value == NULL) {
		return 0UL;
	}
	return sizeof(*diff) + diff->add_rrs.size + diff->rem_rrs.size;
}

static void diff_rewrite(RedisModuleIO *io, RedisModuleString *key, void *value)
{
	size_t key_strlen = 0;
	const diff_v *diff = (const diff_v *)value;
	const uint8_t *key_str = (const uint8_t *)RedisModule_StringPtrLen(key, &key_strlen);
	RedisModule_EmitAOF(io, "KNOT_BIN.AOF.DIFF", "blblbll",
	                    key_str, key_strlen,
	                    (long long)diff->add_rrs.count,
	                    diff->add_rrs.rdata, (long long)diff->add_rrs.size,
	                    (long long)diff->rem_rrs.count,
	                    diff->rem_rrs.rdata, (long long)diff->rem_rrs.size,
	                    (long long)diff->add_ttl,
	                    (long long)diff->rem_ttl);
}

static void diff_free(void *value)
{
	diff_v *diff = (diff_v *)value;
	RedisModule_Free(diff->add_rrs.rdata);
	RedisModule_Free(diff->rem_rrs.rdata);
	RedisModule_Free(diff);
}

static int diff_aof_rewrite(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 7) {
		return RedisModule_WrongArity(ctx);
	}

	diff_v *diff = RedisModule_Calloc(1, sizeof(diff_v));
	if (diff == NULL) {
		return RedisModule_ReplyWithError(ctx, RDB_EALLOC);
	}

	RedisModuleKey *diff_key = RedisModule_OpenKey(ctx, argv[1], REDISMODULE_READ | REDISMODULE_WRITE);

	long long add_rrs_count_val = 0;
	int ret = RedisModule_StringToLongLong(argv[2], &add_rrs_count_val);
	if (ret != REDISMODULE_OK) {
		RedisModule_CloseKey(diff_key);
		return RedisModule_ReplyWithError(ctx, RDB_EMALF);
	} else if (add_rrs_count_val < 0 || add_rrs_count_val > UINT16_MAX) {
		RedisModule_CloseKey(diff_key);
		return RedisModule_ReplyWithError(ctx, RDB_EMALF);
	}
	diff->add_rrs.count = add_rrs_count_val;

	size_t add_rrs_len = 0;
	diff->add_rrs.rdata = (knot_rdata_t *)RedisModule_StringPtrLen(argv[3], &add_rrs_len);
	if (add_rrs_len > UINT32_MAX) {
		RedisModule_CloseKey(diff_key);
		return RedisModule_ReplyWithError(ctx, RDB_EMALF);
	}
	diff->add_rrs.size = add_rrs_len;

	long long rem_rrs_count_val = 0;
	ret = RedisModule_StringToLongLong(argv[4], &rem_rrs_count_val);
	if (ret != REDISMODULE_OK) {
		RedisModule_CloseKey(diff_key);
		return RedisModule_ReplyWithError(ctx, RDB_EMALF);
	} else if (rem_rrs_count_val < 0 || rem_rrs_count_val > UINT16_MAX) {
		RedisModule_CloseKey(diff_key);
		return RedisModule_ReplyWithError(ctx, RDB_EMALF);
	}
	diff->rem_rrs.count = rem_rrs_count_val;

	size_t rem_rrs_len = 0;
	diff->rem_rrs.rdata = (knot_rdata_t *)RedisModule_StringPtrLen(argv[5], &rem_rrs_len);
	if (rem_rrs_len > UINT32_MAX) {
		RedisModule_CloseKey(diff_key);
		return RedisModule_ReplyWithError(ctx, RDB_EMALF);
	}
	diff->rem_rrs.size = rem_rrs_len;

	long long ttl_val = 0;
	ret = RedisModule_StringToLongLong(argv[6], &ttl_val);
	if (ret != REDISMODULE_OK) {
		RedisModule_CloseKey(diff_key);
		return RedisModule_ReplyWithError(ctx, RDB_EMALF);
	} else if (ttl_val < 0 || ttl_val > UINT32_MAX) {
		RedisModule_CloseKey(diff_key);
		return RedisModule_ReplyWithError(ctx, RDB_EMALF);
	}
	diff->add_ttl = ttl_val;

	ttl_val = 0;
	ret = RedisModule_StringToLongLong(argv[7], &ttl_val);
	if (ret != REDISMODULE_OK) {
		RedisModule_CloseKey(diff_key);
		return RedisModule_ReplyWithError(ctx, RDB_EMALF);
	} else if (ttl_val < 0 || ttl_val > UINT32_MAX) {
		RedisModule_CloseKey(diff_key);
		return RedisModule_ReplyWithError(ctx, RDB_EMALF);
	}
	diff->rem_ttl = ttl_val;

	RedisModule_ModuleTypeSetValue(diff_key, rdb_diff_t, diff);
	RedisModule_CloseKey(diff_key);

	return RedisModule_ReplyWithNull(ctx);
}

RedisModuleTypeMethods diff_tm = {
	.version = REDISMODULE_TYPE_METHOD_VERSION,
	.rdb_load = diff_load,
	.rdb_save = diff_save,
	.mem_usage = diff_mem_usage,
	.aof_rewrite = diff_rewrite,
	.free = diff_free
};
