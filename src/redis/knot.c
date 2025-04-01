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

#include "libknot/rdataset.c"
#include "libknot/mm_ctx.h"
#include "libknot/rrtype/soa.h"
#include "libknot/dname.c"
#include "contrib/mempattern.c"
#include "contrib/string.c"
#include "contrib/ucw/mempool.c"

#define KNOT_ZONE_RRSET_ENCODING_VERSION 0

#define KNOT_DNAME_MAXLEN 255
#define KNOT_RRSET_KEY_MAXLEN (1 + KNOT_DNAME_MAXLEN + KNOT_DNAME_MAXLEN + sizeof(uint16_t))
#define KNOT_EVENT_MAX_SIZE 10

#define RRTYPE_SOA 6

#define KNOT_SCORE_SOA     0.
#define KNOT_SCORE_DEFAULT 1.

#define foreach_in_zset_subset(key, min, max) \
	for (RedisModule_ZsetFirstInScoreRange(key, min, max, 0, 0); \
	     RedisModule_ZsetRangeEndReached(key) == 0; \
	     RedisModule_ZsetRangeNext(key))
#define foreach_in_zset(key) foreach_in_zset_subset(key, REDISMODULE_NEGATIVE_INFINITE, REDISMODULE_POSITIVE_INFINITE)

typedef enum {
	EVENTS,
	ZONE_INDEX,
	RRSET
} knot_type_id;

typedef struct {
	uint32_t ttl;
	knot_rdataset_t rrs;
} knot_zone_rrset_v;

static RedisModuleType *knot_zone_rrset_t;

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
	rrset->rrs.rdata = (knot_rdata_t *)RedisModule_LoadStringBuffer(rdb, &len);
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

static size_t knot_zone_rrset_mem_usage(const void *value)
{
	const knot_zone_rrset_v *rrset = (const knot_zone_rrset_v *)value;
	if (value == NULL) {
		return 0UL;
	}
	return sizeof(*rrset) + rrset->rrs.size;
}

static void knot_zone_rrset_rewrite(RedisModuleIO *aof, RedisModuleString *key, void *value)
{
	size_t key_strlen = 0;
	const knot_zone_rrset_v *rrset = (const knot_zone_rrset_v *)value;
	const uint8_t *key_str = (const uint8_t *)RedisModule_StringPtrLen(key, &key_strlen);
	RedisModule_EmitAOF(aof, "KNOT.RRSET.AOF_REWRITE", "bllb",
	                    key_str, key_strlen,
	                    (long long)rrset->ttl,
	                    (long long)rrset->rrs.count,
	                    rrset->rrs.rdata, rrset->rrs.size);
}

static void knot_zone_rrset_free(void *value)
{
	knot_zone_rrset_v *rrset = (knot_zone_rrset_v *)value;
	RedisModule_Free(rrset->rrs.rdata);
	RedisModule_Free(rrset);
}

static RedisModuleKey *find_zone_index(RedisModuleCtx *ctx, const uint8_t *origin, size_t origin_len, int rights)
{
	RedisModule_Assert(ctx != NULL);

	static const uint8_t prefix = ZONE_INDEX;
	RedisModuleString *keyname = RedisModule_CreateString(ctx, (const char *)&prefix, sizeof(prefix));
	RedisModule_StringAppendBuffer(ctx, keyname, (const char *)origin, origin_len);
	RedisModuleKey *key = RedisModule_OpenKey(ctx, keyname, rights);
	RedisModule_FreeString(ctx, keyname);

	return key;
}

static int knot_zone_exists(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 2) {
		return RedisModule_WrongArity(ctx);
	}

	size_t origin_len = 0;
	const uint8_t *origin_str = (const uint8_t *)RedisModule_StringPtrLen(argv[1], &origin_len);

	RedisModuleKey *zone_key = find_zone_index(ctx, origin_str, origin_len, REDISMODULE_READ);
	if (zone_key == NULL) {
		return RedisModule_ReplyWithLongLong(ctx, -1);
	}
	int zone_keytype = RedisModule_KeyType(zone_key);
	if (zone_keytype == REDISMODULE_KEYTYPE_EMPTY) {
		RedisModule_CloseKey(zone_key);
		return RedisModule_ReplyWithError(ctx, "ERR Does not exist");
	} else if (zone_keytype != REDISMODULE_KEYTYPE_ZSET) {
		RedisModule_CloseKey(zone_key);
		return RedisModule_ReplyWithError(ctx, "ERR Bad data");
	}

	foreach_in_zset_subset(zone_key, KNOT_SCORE_SOA, KNOT_SCORE_SOA) {
		double score = 0.0;
		RedisModuleString *el = RedisModule_ZsetRangeCurrentElement(zone_key, &score);
		if (el == NULL) {
			break;
		}

		RedisModuleKey *rrset_key = RedisModule_OpenKey(ctx, el, REDISMODULE_READ);
		if (rrset_key == NULL) {
			continue;
		}

		knot_zone_rrset_v *rrset = RedisModule_ModuleTypeGetValue(rrset_key);
		uint32_t serial = knot_soa_serial(rrset->rrs.rdata);

		RedisModule_CloseKey(rrset_key);
		RedisModule_ZsetRangeStop(zone_key);
		RedisModule_CloseKey(zone_key);

		return RedisModule_ReplyWithLongLong(ctx, serial);
	}
	RedisModule_ZsetRangeStop(zone_key);
	RedisModule_CloseKey(zone_key);

	return RedisModule_ReplyWithLongLong(ctx, -1);
}

static int knot_zone_load(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 2) {
		return RedisModule_WrongArity(ctx);
	}

	size_t origin_len = 0;
	const uint8_t *origin_str = (const uint8_t *)RedisModule_StringPtrLen(argv[1], &origin_len);

	RedisModuleKey *zone_key = find_zone_index(ctx, origin_str, origin_len, REDISMODULE_READ);
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
		if (rrset_key == NULL) {
			continue;
		}
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

static int knot_commit_event(RedisModuleCtx *ctx, const int event, ...)
{
	RedisModule_Assert(ctx != NULL);

	static const uint8_t prefix = EVENTS;
	RedisModuleString *keyname = RedisModule_CreateString(ctx, (const char *)&prefix, sizeof(prefix));
	RedisModuleKey *stream_key = RedisModule_OpenKey(ctx, keyname, REDISMODULE_READ | REDISMODULE_WRITE);
	RedisModule_FreeString(ctx, keyname);

	int zone_stream_type = RedisModule_KeyType(stream_key);
	if (zone_stream_type != REDISMODULE_KEYTYPE_EMPTY && zone_stream_type != REDISMODULE_KEYTYPE_STREAM) {
		RedisModule_CloseKey(stream_key);
		return RedisModule_ReplyWithError(ctx, "ERR Bad data");
	}

	RedisModuleString *_event[KNOT_EVENT_MAX_SIZE] = {
		RedisModule_CreateString(ctx, "event", sizeof("event") - 1),
		RedisModule_CreateStringFromLongLong(ctx, event),
	};

	va_list args;
	va_start(args, event);
	RedisModuleString **_event_it = _event + 2;
	while (_event_it != _event + KNOT_EVENT_MAX_SIZE) {
		*_event_it = va_arg(args, RedisModuleString *);
		if (*_event_it == NULL) {
			break;
		}
		_event_it += 1;
	}
	int64_t size = _event_it - _event;
	if (size % 2) {
		return RedisModule_ReplyWithError(ctx, "ERR Wrong number of arguments");
	}
	va_end(args);

	RedisModuleStreamID ts;
	RedisModule_StreamAdd(stream_key, REDISMODULE_STREAM_ADD_AUTOID, &ts, _event, size / 2);

	// TODO choose right time, no older events will be available
	ts.ms = ts.ms - 60000; // 1 minute
	ts.seq = 0;
	// NOTE Trimming with REDISMODULE_STREAM_TRIM_APPROX improves preformance
	long long removed_cnt = RedisModule_StreamTrimByID(stream_key, REDISMODULE_STREAM_TRIM_APPROX, &ts);
	if (removed_cnt) {
		RedisModule_Log(ctx, REDISMODULE_LOGLEVEL_NOTICE, "stream trimmed %lld old events", removed_cnt);
	}
	RedisModule_CloseKey(stream_key);

	RedisModule_FreeString(ctx, _event[0]);
	RedisModule_FreeString(ctx, _event[1]);

	return REDISMODULE_OK;
}

static int knot_zone_purge(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 2) {
		return RedisModule_WrongArity(ctx);
	}

	size_t origin_len = 0;
	const uint8_t *origin_str = (const uint8_t *)RedisModule_StringPtrLen(argv[1], &origin_len);

	RedisModuleKey *zone_key = find_zone_index(ctx, origin_str, origin_len, REDISMODULE_READ | REDISMODULE_WRITE);
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

	RedisModuleString *origin_k = RedisModule_CreateString(ctx, "origin", sizeof("origin") - 1);
	(void)knot_commit_event(ctx, ZONE_PURGED, origin_k, argv[1], NULL);
	RedisModule_FreeString(ctx, origin_k);

	RedisModule_ReplyWithEmptyString(ctx);

	return REDISMODULE_OK;
}


static int knot_zone_increment(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 2) {
		return RedisModule_WrongArity(ctx);
	}

	size_t origin_len = 0;
	const uint8_t *origin_str = (const uint8_t *)RedisModule_StringPtrLen(argv[1], &origin_len);

	RedisModuleKey *zone_key = find_zone_index(ctx, origin_str, origin_len, REDISMODULE_READ);
	if (zone_key == NULL) {
		return RedisModule_ReplyWithLongLong(ctx, -1);
	}
	int zone_keytype = RedisModule_KeyType(zone_key);
	if (zone_keytype == REDISMODULE_KEYTYPE_EMPTY) {
		RedisModule_CloseKey(zone_key);
		return RedisModule_ReplyWithError(ctx, "ERR Does not exist");
	} else if (zone_keytype != REDISMODULE_KEYTYPE_ZSET) {
		RedisModule_CloseKey(zone_key);
		return RedisModule_ReplyWithError(ctx, "ERR Bad data");
	}

	foreach_in_zset_subset(zone_key, KNOT_SCORE_SOA, KNOT_SCORE_SOA) {
		double score = 0.0;
		RedisModuleString *el = RedisModule_ZsetRangeCurrentElement(zone_key, &score);
		if (el == NULL) {
			break;
		}

		RedisModuleKey *rrset_key = RedisModule_OpenKey(ctx, el, REDISMODULE_READ | REDISMODULE_WRITE);
		if (rrset_key == NULL) {
			continue;
		}
		knot_zone_rrset_v *rrset = RedisModule_ModuleTypeGetValue(rrset_key);
		if (rrset == NULL) {
			continue;
		}

		uint32_t serial = knot_soa_serial(rrset->rrs.rdata) + 1;
		knot_soa_serial_set(rrset->rrs.rdata, serial);

		RedisModule_CloseKey(rrset_key);
		RedisModule_ZsetRangeStop(zone_key);
		RedisModule_CloseKey(zone_key);

		RedisModuleString *origin_k = RedisModule_CreateString(ctx, "origin", sizeof("origin") - 1);
		RedisModuleString *serial_k = RedisModule_CreateString(ctx, "serial", sizeof("serial") - 1);
		RedisModuleString *serial_v = RedisModule_CreateStringFromLongLong(ctx, serial);
		(void)knot_commit_event(ctx, ZONE_UPDATED, origin_k, argv[1], serial_k, serial_v, NULL);
		RedisModule_FreeString(ctx, origin_k);
		RedisModule_FreeString(ctx, serial_k);
		RedisModule_FreeString(ctx, serial_v);

		return RedisModule_ReplyWithLongLong(ctx, serial);
	}
	RedisModule_ZsetRangeStop(zone_key);
	RedisModule_CloseKey(zone_key);

	return RedisModule_ReplyWithLongLong(ctx, -1);
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
static RedisModuleString *construct_rrset_key(RedisModuleCtx *ctx, const uint8_t *origin, size_t origin_len, const uint8_t *owner, size_t owner_len, uint16_t rtype)
{
	uint8_t key_data[KNOT_RRSET_KEY_MAXLEN];
	uint8_t *key_ptr = key_data;
	key_ptr[0] = RRSET;
	key_ptr = memcpy(key_ptr + 1, origin, origin_len);
	key_ptr = memcpy(key_ptr + origin_len, owner, owner_len);
	key_ptr = memcpy(key_ptr + owner_len, &rtype, sizeof(rtype));
	key_ptr += sizeof(rtype);
	return RedisModule_CreateString(ctx, (const char *)key_data, key_ptr - key_data);
}

static int knot_rrset_store(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 7) {
		return RedisModule_WrongArity(ctx);
	}

	size_t origin_len = 0;
	const uint8_t *origin_str = (const uint8_t *)RedisModule_StringPtrLen(argv[1], &origin_len);

	size_t owner_strlen = 0;
	const uint8_t *owner_str = (const uint8_t *)RedisModule_StringPtrLen(argv[2], &owner_strlen);

	long long rtype_val = 0;
	int ret = RedisModule_StringToLongLong(argv[3], &rtype_val);
	if (ret != REDISMODULE_OK) {
		return RedisModule_ReplyWithError(ctx, "ERR Not a number");
	} else if (rtype_val < 0 || rtype_val > UINT16_MAX) {
		return RedisModule_ReplyWithError(ctx, "ERR Value out of range");
	}
	uint16_t rtype = rtype_val;

	RedisModuleKey *zone_key = find_zone_index(ctx, origin_str, origin_len, REDISMODULE_READ | REDISMODULE_WRITE);
	int zone_keytype = RedisModule_KeyType(zone_key);
	if (zone_keytype == REDISMODULE_KEYTYPE_EMPTY) {
		RedisModuleString *origin_k = RedisModule_CreateString(ctx, "origin", sizeof("origin") - 1);
		(void)knot_commit_event(ctx, ZONE_CREATED, origin_k, argv[1], NULL);
		RedisModule_FreeString(ctx, origin_k);
	} else if (zone_keytype != REDISMODULE_KEYTYPE_ZSET) {
		RedisModule_CloseKey(zone_key);
		return RedisModule_ReplyWithError(ctx, "ERR Bad data");
	}

	RedisModuleString *rrset_keystr = construct_rrset_key(ctx, origin_str, origin_len, owner_str, owner_strlen, rtype);

	RedisModule_ZsetAdd(zone_key, evaluate_score(rtype), rrset_keystr, NULL);
	RedisModule_CloseKey(zone_key);

	RedisModuleKey *rrset_key = RedisModule_OpenKey(ctx, rrset_keystr, REDISMODULE_READ | REDISMODULE_WRITE);
	RedisModule_FreeString(ctx, rrset_keystr);

	knot_zone_rrset_v *rrset = RedisModule_Calloc(1, sizeof(knot_zone_rrset_v));
	if (rrset == NULL) {
		return RedisModule_ReplyWithError(ctx, "ERR Cannot allocate memory");
	}

	long long ttl_val = 0;
	ret = RedisModule_StringToLongLong(argv[4], &ttl_val);
	if (ret != REDISMODULE_OK) {
		RedisModule_CloseKey(rrset_key);
		return RedisModule_ReplyWithError(ctx, "ERR Not a number");
	} else if (ttl_val < 0 || ttl_val > UINT32_MAX) {
		RedisModule_CloseKey(rrset_key);
		return RedisModule_ReplyWithError(ctx, "ERR Value out of range");
	}
	rrset->ttl = ttl_val;

	long long count_val = 0;
	ret = RedisModule_StringToLongLong(argv[5], &count_val);
	if (ret != REDISMODULE_OK) {
		RedisModule_CloseKey(rrset_key);
		return RedisModule_ReplyWithError(ctx, "ERR Not a number");
	} else if (count_val < 0 || count_val > UINT16_MAX) {
		RedisModule_CloseKey(rrset_key);
		return RedisModule_ReplyWithError(ctx, "ERR Value out of range");
	}
	rrset->rrs.count = count_val;

	size_t rdataset_strlen;
	const char *rdataset_str = RedisModule_StringPtrLen(argv[6], &rdataset_strlen);
	if (rdataset_strlen != 0) {
		rrset->rrs.rdata = RedisModule_Alloc(rdataset_strlen);
		if (rrset->rrs.rdata == NULL) {
			RedisModule_CloseKey(rrset_key);
			return RedisModule_ReplyWithError(ctx, "ERR Cannot allocate memory");
		}
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
static void *redismodule_alloc(void *ptr, size_t bytes)
{
	return RedisModule_Alloc(bytes);
}

static void redismodule_free(void *ptr)
{
	RedisModule_Free(ptr);
}

static knot_mm_t mm = {
	.alloc = redismodule_alloc,
	.ctx = NULL,
	.free = redismodule_free
};
static int knot_rrset_add(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 5) {
		return RedisModule_WrongArity(ctx);
	}

	size_t origin_len = 0;
	const uint8_t *origin_str = (const uint8_t *)RedisModule_StringPtrLen(argv[1], &origin_len);

	size_t owner_strlen = 0;
	const uint8_t *owner_str = (const uint8_t *)RedisModule_StringPtrLen(argv[2], &owner_strlen);

	long long rtype_val = 0;
	int ret = RedisModule_StringToLongLong(argv[3], &rtype_val);
	if (ret != REDISMODULE_OK) {
		return RedisModule_ReplyWithError(ctx, "ERR Not a number");
	} else if (rtype_val < 0 || rtype_val > UINT16_MAX) {
		return RedisModule_ReplyWithError(ctx, "ERR Value out of range");
	}
	uint16_t rtype = rtype_val;

	RedisModuleKey *zone_key = find_zone_index(ctx, origin_str, origin_len, REDISMODULE_READ);
	if (RedisModule_KeyType(zone_key) != REDISMODULE_KEYTYPE_ZSET) {
		RedisModule_CloseKey(zone_key);
		return RedisModule_ReplyWithError(ctx, "ERR Bad data");
	}

	RedisModuleString *rrset_keystr = construct_rrset_key(ctx, origin_str, origin_len, owner_str, owner_strlen, rtype);

	double score = .0;
	ret = RedisModule_ZsetScore(zone_key, rrset_keystr, &score);
	if (ret != REDISMODULE_OK) {
		RedisModule_CloseKey(zone_key);
		return RedisModule_ReplyWithError(ctx, "ERR Bad data");
	}
	RedisModule_CloseKey(zone_key);

	RedisModuleKey *rrset_key = RedisModule_OpenKey(ctx, rrset_keystr, REDISMODULE_READ | REDISMODULE_WRITE);
	RedisModule_FreeString(ctx, rrset_keystr);
	if (RedisModule_ModuleTypeGetType(rrset_key) != knot_zone_rrset_t) {
		RedisModule_CloseKey(rrset_key);
		return RedisModule_ReplyWithError(ctx, "ERR Bad data");
	}
	knot_zone_rrset_v *rrset = RedisModule_ModuleTypeGetValue(rrset_key);
	if (rrset == NULL) {
		RedisModule_CloseKey(rrset_key);
		return RedisModule_ReplyWithError(ctx, "ERR Bad data");
	}

	size_t rdataset_strlen;
	const knot_rdata_t *rdataset_str = (const knot_rdata_t *)RedisModule_StringPtrLen(argv[4], &rdataset_strlen);
	if (rdataset_strlen == 0) {
		RedisModule_CloseKey(rrset_key);
		return RedisModule_ReplyWithError(ctx, "ERR Invalid value");
	}

	uint16_t old_count = rrset->rrs.count;
	ret = knot_rdataset_add(&rrset->rrs, rdataset_str, &mm);
	if (ret != KNOT_EOK) {
		RedisModule_CloseKey(rrset_key);
		return RedisModule_ReplyWithError(ctx, "ERR Unable to add");
	}

	if (old_count != rrset->rrs.count) {
		RedisModuleString *origin_k = RedisModule_CreateString(ctx, "origin", sizeof("origin") - 1);
		(void)knot_commit_event(ctx, RRSET_UPDATED, origin_k, argv[1], NULL);
		RedisModule_FreeString(ctx, origin_k);
	}
	RedisModule_CloseKey(rrset_key);

	RedisModule_ReplyWithNull(ctx);

	return REDISMODULE_OK;
}

static int knot_rrset_remove(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 5) {
		return RedisModule_WrongArity(ctx);
	}

	size_t origin_len = 0;
	const uint8_t *origin_str = (const uint8_t *)RedisModule_StringPtrLen(argv[1], &origin_len);

	size_t owner_strlen;
	const uint8_t *owner_str = (const uint8_t *)RedisModule_StringPtrLen(argv[2], &owner_strlen);

	long long rtype_val = 0;
	int ret = RedisModule_StringToLongLong(argv[3], &rtype_val);
	if (ret != REDISMODULE_OK) {
		return RedisModule_ReplyWithError(ctx, "ERR Not a number");
	} else if (rtype_val < 0 || rtype_val > UINT16_MAX) {
		return RedisModule_ReplyWithError(ctx, "ERR Value out of range");
	}
	uint16_t rtype = rtype_val;

	RedisModuleKey *zone_key = find_zone_index(ctx, origin_str, origin_len, REDISMODULE_READ);
	if (RedisModule_KeyType(zone_key) != REDISMODULE_KEYTYPE_ZSET) {
		RedisModule_CloseKey(zone_key);
		return RedisModule_ReplyWithError(ctx, "ERR Bad data");
	}

	RedisModuleString *rrset_keystr = construct_rrset_key(ctx, origin_str, origin_len, owner_str, owner_strlen, rtype);

	double score = .0;
	ret = RedisModule_ZsetScore(zone_key, rrset_keystr, &score);
	if (ret != REDISMODULE_OK) {
		RedisModule_CloseKey(zone_key);
		return RedisModule_ReplyWithError(ctx, "ERR Bad data");
	}
	RedisModule_CloseKey(zone_key);

	RedisModuleKey *rrset_key = RedisModule_OpenKey(ctx, rrset_keystr, REDISMODULE_READ | REDISMODULE_WRITE);
	RedisModule_FreeString(ctx, rrset_keystr);
	if (RedisModule_ModuleTypeGetType(rrset_key) != knot_zone_rrset_t) {
		RedisModule_CloseKey(rrset_key);
		return RedisModule_ReplyWithError(ctx, "ERR Bad data");
	}
	knot_zone_rrset_v *rrset = RedisModule_ModuleTypeGetValue(rrset_key);
	if (rrset == NULL) {
		RedisModule_CloseKey(rrset_key);
		return RedisModule_ReplyWithError(ctx, "ERR Bad data");
	}

	size_t rdataset_strlen;
	const knot_rdata_t *rdataset_str = (const knot_rdata_t *)RedisModule_StringPtrLen(argv[4], &rdataset_strlen);
	if (rdataset_strlen == 0) {
		RedisModule_CloseKey(rrset_key);
		return RedisModule_ReplyWithError(ctx, "ERR Invalid value");
	}

	uint16_t old_count = rrset->rrs.count;
	ret = knot_rdataset_remove(&rrset->rrs, rdataset_str, &mm);
	if (ret != KNOT_EOK) {
		RedisModule_CloseKey(rrset_key);
		return RedisModule_ReplyWithError(ctx, "ERR Unable to remove");
	}

	if (old_count != rrset->rrs.count) {
		RedisModuleString *origin_k = RedisModule_CreateString(ctx, "origin", sizeof("origin") - 1);
		(void)knot_commit_event(ctx, RRSET_UPDATED, origin_k, argv[1], NULL);
		RedisModule_FreeString(ctx, origin_k);
	}
	RedisModule_CloseKey(rrset_key);

	RedisModule_ReplyWithNull(ctx);

	return REDISMODULE_OK;
}

static int knot_rrset_aof_rewrite(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 5) {
		return RedisModule_WrongArity(ctx);
	}

	knot_zone_rrset_v *rrset = RedisModule_Calloc(1, sizeof(knot_zone_rrset_v));
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

int RedisModule_OnLoad(RedisModuleCtx *ctx)
{
	RedisModuleTypeMethods tm = {
		.version = REDISMODULE_TYPE_METHOD_VERSION,
		.rdb_load = knot_zone_rrset_load,
		.rdb_save = knot_zone_rrset_save,
		.mem_usage = knot_zone_rrset_mem_usage,
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

	if (	RedisModule_CreateCommand(ctx, "knot.zone.exists",       knot_zone_exists,       "readonly", 1, 1, 1) == REDISMODULE_ERR ||
		RedisModule_CreateCommand(ctx, "knot.zone.load",         knot_zone_load,         "readonly", 1, 1, 1) == REDISMODULE_ERR ||
		RedisModule_CreateCommand(ctx, "knot.zone.purge",        knot_zone_purge,        "write",    1, 1, 1) == REDISMODULE_ERR ||
		RedisModule_CreateCommand(ctx, "knot.zone.increment",    knot_zone_increment,    "write",    1, 1, 1) == REDISMODULE_ERR ||
		RedisModule_CreateCommand(ctx, "knot.rrset.store",       knot_rrset_store,       "write",    1, 1, 1) == REDISMODULE_ERR ||
		RedisModule_CreateCommand(ctx, "knot.rrset.add",         knot_rrset_add,         "write",    1, 1, 1) == REDISMODULE_ERR ||
		RedisModule_CreateCommand(ctx, "knot.rrset.remove",      knot_rrset_remove,      "write",    1, 1, 1) == REDISMODULE_ERR ||
		RedisModule_CreateCommand(ctx, "knot.rrset.aof_rewrite", knot_rrset_aof_rewrite, "write",    1, 1, 1) == REDISMODULE_ERR
	) {
		RedisModule_Log(ctx, REDISMODULE_LOGLEVEL_WARNING, "ERR 'knot' module already loaded");
		RedisModule_ReplyWithError(ctx, "ERR 'knot' module already loaded");
		return REDISMODULE_ERR;
	}

	return REDISMODULE_OK;
}
