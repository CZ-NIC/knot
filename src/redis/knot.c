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

#include <arpa/inet.h>
#include <stdbool.h>
#include <string.h>
#include <strings.h>

#include "contrib/redis/redismodule.h"
#include "libdnssec/random.h"
#include "libknot/descriptor.h"
#include "libknot/dname.h"
#include "libknot/errcode.h"
#include "libknot/rdataset.h"

#define KNOT_ZONE_RRSET_ENCODING_VERSION 0

#define KNOT_ZONE_KEY_MAXLEN  (1 + KNOT_DNAME_MAXLEN)
#define KNOT_RRSET_KEY_MAXLEN (1 + sizeof(uint32_t) + KNOT_DNAME_MAXLEN + sizeof(uint16_t))

#define KNOT_SCORE_SOA     0.
#define KNOT_SCORE_DEFAULT 1.

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

enum select_field {
	EMPTY = 0,
	TTL = 1 << 0,
	RDATA = 1 << 1
};

enum select_operation {
	NONE,
	GET,
	SET,
	INSERT,
	REMOVE
};

typedef struct {
	uint32_t ttl;
	knot_rdataset_t rrs;
}  knot_zone_rrset_v;

struct rrset_list_ctx {
	RedisModuleString *origin;
	long ctr;
	uint32_t lookup_id;
};

static void* redis_alloc(void *ctx, size_t len);
static void redis_free(void *ptr);

static RedisModuleType *knot_zone_rrset_t;

static knot_mm_t redis_mm = {
	.alloc = redis_alloc,
	.ctx = NULL,
	.free = redis_free
};

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

static int knot_zone_insert(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 2) {
		return RedisModule_WrongArity(ctx);
	}

	uint8_t origin[KNOT_DNAME_MAXLEN];
	size_t origin_strlen;
	const char *origin_str = RedisModule_StringPtrLen(argv[1], &origin_strlen);
	knot_dname_t *origin_dname = knot_dname_from_str(origin, origin_str, sizeof(origin));
	if (origin_dname == NULL) {
		return RedisModule_ReplyWithError(ctx, "ERR Wrong origin format");
	}

	RedisModuleKey *zone_key = find_zone(ctx, origin_dname, REDISMODULE_READ | REDISMODULE_WRITE);
	if (zone_key == NULL) {
		return RedisModule_ReplyWithError(ctx, "ERR Unable find");
	}
	else if (RedisModule_KeyType(zone_key) != REDISMODULE_KEYTYPE_EMPTY) {
		RedisModule_CloseKey(zone_key);
		return RedisModule_ReplyWithError(ctx, "ERR Already exists");
	}

	uint32_t id = dnssec_random_uint32_t();
	RedisModuleString *zone_id = RedisModule_CreateString(ctx, (const char*)&id, sizeof(id));
	RedisModule_StringSet(zone_key, zone_id);
	RedisModule_CloseKey(zone_key);

	RedisModule_ReplyWithString(ctx, zone_id);
	RedisModule_FreeString(ctx, zone_id);

	return REDISMODULE_OK;
}

static void zone_list_cb(RedisModuleCtx *ctx, RedisModuleString *keyname, RedisModuleKey *key, void *privdata)
{
	size_t len = 0;
	const char *keyname_str = RedisModule_StringPtrLen(keyname, &len);
	if (keyname_str[0] != ZONE) {
		return; // NOTE just filtering out non-zone records
	}

	char origin[KNOT_DNAME_TXT_MAXLEN];
	if (knot_dname_to_str(origin, (const knot_dname_t *)(keyname_str + 1), KNOT_DNAME_TXT_MAXLEN) == NULL) {
		RedisModule_ReplyWithError(ctx, "ERR Bad data");
		return;
	}

	RedisModule_ReplyWithStringBuffer(ctx, origin, strlen(origin));
	++(*(long *)privdata);
}

static int knot_zone_list(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 1) {
		return RedisModule_WrongArity(ctx);
	}

	long ctr = 0;
	RedisModule_ReplyWithArray(ctx, REDISMODULE_POSTPONED_ARRAY_LEN);

	RedisModuleScanCursor *cursor = RedisModule_ScanCursorCreate();
	while (RedisModule_Scan(ctx, cursor, zone_list_cb, &ctr) != 0);
	RedisModule_ScanCursorDestroy(cursor);

	RedisModule_ReplySetArrayLength(ctx, ctr);
	return REDISMODULE_OK;
}

static int knot_zone_read(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 2) {
		return RedisModule_WrongArity(ctx);
	}

	uint8_t origin[KNOT_DNAME_MAXLEN];
	size_t origin_strlen;
	const char *origin_str = RedisModule_StringPtrLen(argv[1], &origin_strlen);
	knot_dname_t *origin_dname = knot_dname_from_str(origin, origin_str, sizeof(origin));
	if (origin_dname == NULL) {
		return RedisModule_ReplyWithError(ctx, "ERR Wrong origin format");
	}

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

		char owner_buffer[KNOT_DNAME_TXT_MAXLEN];
		const char *owner = knot_dname_to_str(owner_buffer, (const knot_dname_t *)(rrset_str + 5), KNOT_DNAME_TXT_MAXLEN);

		char rtype_str[32];
		knot_rrtype_to_string(rtype, rtype_str, sizeof(rtype_str));

		RedisModule_ReplyWithArray(ctx, 4 + rrset->rrs.count);
		RedisModule_ReplyWithStringBuffer(ctx, owner, strlen(owner));
		RedisModule_ReplyWithStringBuffer(ctx, rtype_str, strlen(rtype_str));
		RedisModule_ReplyWithLongLong(ctx, rrset->ttl);
		RedisModule_ReplyWithLongLong(ctx, rrset->rrs.count);
		knot_rdata_t *rdata = rrset->rrs.rdata;
		for (uint16_t idx = 0; idx < rrset->rrs.count; ++idx) {
			RedisModule_ReplyWithStringBuffer(ctx, (const char *)rdata->data, rdata->len);
			rdata = knot_rdataset_next(rdata);
		}

		++count;
	}
	RedisModule_ZsetRangeStop(zone_index_key);
	RedisModule_CloseKey(zone_index_key);
	RedisModule_ReplySetArrayLength(ctx, count);

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

	uint8_t key_data[KNOT_RRSET_KEY_MAXLEN];
	uint8_t *key_ptr = key_data;
	key_data[0] = RRSET;
	key_ptr = memcpy(key_ptr + 1, zoneid_str, sizeof(uint32_t));
	if (key_ptr == NULL) {
		return NULL;
	}
	key_ptr = knot_dname_from_str(key_ptr + sizeof(uint32_t), owner_str, sizeof(key_data) - (sizeof(uint32_t) + 1));
	if (key_ptr == NULL) {
		return NULL;
	}
	key_ptr += knot_dname_size(key_ptr);

	uint16_t rtype;
	int ret = knot_rrtype_from_string(type_str, &rtype);
	if (ret != KNOT_EOK) {
		return NULL;
	}

	memcpy(key_ptr, &rtype, sizeof(rtype));
	key_ptr += sizeof(rtype);

	RedisModuleString *key_str = RedisModule_CreateString(ctx, (const char *)key_data, key_ptr - key_data);
	RedisModuleKey *key = RedisModule_OpenKey(ctx, key_str, rights);
	RedisModule_FreeString(ctx, key_str);
	return key;
}

static enum select_field select_field_from_str(RedisModuleString *arg)
{
	size_t arg_len = 0;
	const char *arg_data = RedisModule_StringPtrLen(arg, &arg_len);

	if (arg_data == NULL || arg_len == 0) {
		return NONE;
	}

	if (strncasecmp(arg_data, "TTL", arg_len) == 0) {
		return TTL;
	} else if (strncasecmp(arg_data, "RDATA", arg_len) == 0) {
		return RDATA;
	} else {
		return EMPTY;
	}
}

static void* redis_alloc(void *ctx, size_t len)
{
	return RedisModule_Alloc(len);
}

static void redis_free(void *ptr)
{
	RedisModule_Free(ptr);
}

static int rdataset_add(RedisModuleCtx *ctx, knot_rdataset_t *rrs, RedisModuleString *val)
{
	size_t data_len;
	const uint8_t *data = (const uint8_t *)RedisModule_StringPtrLen(val, &data_len);
	if (data_len > UINT16_MAX) {
		return KNOT_ERANGE;
	}

	uint8_t rdata[knot_rdata_size(data_len)];
	knot_rdata_init((knot_rdata_t *)rdata, data_len, data);
	return knot_rdataset_add(rrs, (const knot_rdata_t *)rdata, &redis_mm);
}

static double evaluate_score(uint16_t rtype)
{
	switch (rtype) {
	case KNOT_RRTYPE_SOA:
		return KNOT_SCORE_SOA;
	default:
		return KNOT_SCORE_DEFAULT;
	}
}

static int read_zone_id(RedisModuleKey *key, uint32_t *id)
{
	if (RedisModule_KeyType(key) != REDISMODULE_KEYTYPE_STRING) {
		return KNOT_EMALF;
	}
	size_t len = 0;
	const uint32_t *val = (const uint32_t *)RedisModule_StringDMA(key, &len, REDISMODULE_READ);
	if (len != sizeof(uint32_t)) {
		return KNOT_EMALF;
	}
	memcpy(id, val, sizeof(uint32_t));
	return KNOT_EOK;
}

static int knot_rrset_insert(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc < 4) {
		return RedisModule_WrongArity(ctx);
	}

	uint8_t origin[KNOT_DNAME_MAXLEN];
	size_t origin_strlen;
	const char *origin_str = RedisModule_StringPtrLen(argv[1], &origin_strlen);
	knot_dname_t *origin_dname = knot_dname_from_str(origin, origin_str, sizeof(origin));
	if (origin_dname == NULL) {
		return RedisModule_ReplyWithError(ctx, "ERR Wrong origin format");
	}

	RedisModuleString *origin_id = NULL;
	RedisModuleKey *zone_key = find_zone(ctx, origin_dname, REDISMODULE_READ | REDISMODULE_WRITE);
	if (zone_key == NULL) {
		return RedisModule_ReplyWithError(ctx, "ERR Unable find");
	}
	int key_type = RedisModule_KeyType(zone_key);
	if (key_type != REDISMODULE_KEYTYPE_EMPTY) {
		uint32_t id = 0;
		int ret = read_zone_id(zone_key, &id);
		if (ret == KNOT_EMALF) {
			RedisModule_CloseKey(zone_key);
			return RedisModule_ReplyWithError(ctx, "ERR Bad data");
		}
		origin_id = RedisModule_CreateString(ctx, (const char *)&id, sizeof(id));
	} else {
		uint32_t id = dnssec_random_uint32_t();
		origin_id = RedisModule_CreateString(ctx, (const char *)&id, sizeof(id));
		RedisModule_StringSet(zone_key, origin_id);
	}
	RedisModule_CloseKey(zone_key);

	RedisModuleKey *rrset_key = find_rrset(ctx, origin_id, argv[2], argv[3], REDISMODULE_READ | REDISMODULE_WRITE);
	RedisModule_FreeString(ctx, origin_id);
	if (rrset_key == NULL) {
		return RedisModule_ReplyWithError(ctx, "ERR Unable find");
	} else if (RedisModule_KeyType(rrset_key) != REDISMODULE_KEYTYPE_EMPTY) {
		RedisModule_CloseKey(rrset_key);
		return RedisModule_ReplyWithError(ctx, "ERR Already exists");
	}

	knot_zone_rrset_v *rrset = RedisModule_Alloc(sizeof(knot_zone_rrset_v));
	rrset->ttl = 0;
	knot_rdataset_init(&rrset->rrs);
	for (int arg_idx = 4; arg_idx < argc; ++arg_idx) {
		enum select_field field = select_field_from_str(argv[arg_idx]);
		if (field == TTL) {
			++arg_idx;
			if (arg_idx >= argc) {
				return RedisModule_WrongArity(ctx);
			}
			long long v;
			if (RedisModule_StringToLongLong(argv[arg_idx], &v) != REDISMODULE_OK) {
				return RedisModule_ReplyWithError(ctx, "ERR Expected number");
			}
			if (v < 0 || v > UINT32_MAX) {
				return RedisModule_ReplyWithError(ctx, "ERR Value out of range");
			}
			rrset->ttl = v;
		} else if (field == RDATA) {
			++arg_idx;
			if (arg_idx >= argc) {
				return RedisModule_WrongArity(ctx);
			}

			int ret = rdataset_add(ctx, &rrset->rrs, argv[arg_idx]);
			if (ret == KNOT_ERANGE) {
				return RedisModule_ReplyWithError(ctx, "ERR Value out of range");
			} else if (ret == KNOT_ENOMEM || ret == KNOT_ESPACE) {
				return RedisModule_ReplyWithError(ctx, "ERR Not enough memory");
			} else if (ret != KNOT_EOK) {
				return RedisModule_ReplyWithError(ctx, "ERR Failed to add RDATA");
			}
			break;
		}
	}

	RedisModule_ModuleTypeSetValue(rrset_key, knot_zone_rrset_t, rrset);

	// NOTE remove this when testing legacy rrset scanning (without ZONE_INDEX)
	uint16_t rtype;
	size_t rrtype_len = 0;
	const RedisModuleString *rrset_keyname = RedisModule_GetKeyNameFromModuleKey(rrset_key);
	const char *rrset_keyname_str =RedisModule_StringPtrLen(rrset_keyname, &rrtype_len);
	memcpy(&rtype, rrset_keyname_str + rrtype_len - 1 - sizeof(uint16_t),  sizeof(uint16_t));
	static const uint8_t zone_index_prefix = ZONE_INDEX;
	RedisModuleString *list_key_str =  RedisModule_CreateString(ctx, (const char *)(&zone_index_prefix), sizeof(zone_index_prefix));
	RedisModule_StringAppendBuffer(ctx, list_key_str, (const char *)origin_dname, origin_strlen);
	RedisModuleKey *zone_list_key = RedisModule_OpenKey(ctx, list_key_str, REDISMODULE_READ | REDISMODULE_WRITE);
	RedisModule_ZsetAdd(zone_list_key, evaluate_score(rtype), list_key_str, NULL);
	RedisModule_FreeString(ctx, list_key_str);
	RedisModule_CloseKey(zone_list_key);
	// END OF BLOCK

	RedisModule_CloseKey(rrset_key);

	RedisModule_ReplyWithEmptyString(ctx);

	return REDISMODULE_OK;
}

static enum select_operation select_op_from_str(RedisModuleString *arg)
{
	size_t arg_len = 0;
	const char *arg_data = RedisModule_StringPtrLen(arg, &arg_len);

	if (arg_data == NULL || arg_len == 0) {
		return NONE;
	}

	if (strncasecmp(arg_data, "GET", arg_len) == 0) {
		return GET;
	} else if (strncasecmp(arg_data, "SET", arg_len) == 0) {
		return SET;
	} else if (strncasecmp(arg_data, "INSERT", arg_len) == 0) {
		return INSERT;
	} else if (strncasecmp(arg_data, "REMOVE", arg_len) == 0) {
		return REMOVE;
	} else {
		return NONE;
	}
}

static int rdataset_remove(RedisModuleCtx *ctx, knot_rdataset_t *rrs, RedisModuleString *val)
{
	size_t data_len;
	const uint8_t *data = (const uint8_t *)RedisModule_StringPtrLen(val, &data_len);
	if (data_len > UINT16_MAX) {
		return KNOT_ERANGE;
	}
	uint8_t rdata[knot_rdata_size(data_len)];
	knot_rdata_init((knot_rdata_t *)rdata, data_len, data);
	return knot_rdataset_remove(rrs, (const knot_rdata_t *)rdata, &redis_mm);
}

static int knot_rrset_select(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc < 4) {
		return RedisModule_WrongArity(ctx);
	}

	int getter = 0;

	uint8_t origin[KNOT_DNAME_MAXLEN];
	size_t zone_str_len;
	const char *origin_str = RedisModule_StringPtrLen(argv[1], &zone_str_len);
	knot_dname_t *origin_dname = knot_dname_from_str(origin, origin_str, sizeof(origin));
	if (origin_dname == NULL) {
		return RedisModule_ReplyWithError(ctx, "ERR Wrong origin format");
	}

	RedisModuleKey *zone_key = find_zone(ctx, origin_dname, REDISMODULE_READ);
	if (zone_key == NULL) {
		return RedisModule_ReplyWithError(ctx, "ERR Unable find");
	}
	int key_type = RedisModule_KeyType(zone_key);
	if (key_type == REDISMODULE_KEYTYPE_EMPTY) {
		RedisModule_CloseKey(zone_key);
		return RedisModule_ReplyWithError(ctx, "ERR Does not exist");
	}
	if (key_type != REDISMODULE_KEYTYPE_STRING) {
		RedisModule_CloseKey(zone_key);
		return RedisModule_ReplyWithError(ctx, "ERR Bad data");
	}

	uint32_t id = 0;
	int ret = read_zone_id(zone_key, &id);
	if (ret == KNOT_EMALF) {
		RedisModule_CloseKey(zone_key);
		return RedisModule_ReplyWithError(ctx, "ERR Bad data");
	}
	RedisModuleString *zone_id = RedisModule_CreateString(ctx, (const char *)&id, sizeof(id));
	RedisModule_CloseKey(zone_key);

	RedisModuleKey *rrset_key = find_rrset(ctx, zone_id, argv[2], argv[3], REDISMODULE_READ);
	if (RedisModule_KeyType(rrset_key) == REDISMODULE_KEYTYPE_EMPTY) {
		RedisModule_FreeString(ctx, zone_id);
		return RedisModule_ReplyWithError(ctx, "ERR Does not exist");
	}
	RedisModule_FreeString(ctx, zone_id);

	if (RedisModule_ModuleTypeGetType(rrset_key) != knot_zone_rrset_t) {
		return RedisModule_ReplyWithError(ctx, "ERR Wrong type");
	}

	knot_zone_rrset_v *rrset = RedisModule_ModuleTypeGetValue(rrset_key);

	bool store = false;
	for (int arg_idx = 4; arg_idx < argc; ++arg_idx) {
		enum select_operation op = select_op_from_str(argv[arg_idx]);
		if (op == NONE) {
			return RedisModule_ReplyWithError(ctx, "ERR Unknown operation");
		}
		++arg_idx;
		if (arg_idx >= argc) {
			return RedisModule_WrongArity(ctx);
		}

		ret = KNOT_EOK;
		enum select_field field = NONE;
		switch (op) {
		case GET:
			field = select_field_from_str(argv[arg_idx]);
			if (field == EMPTY) {
				return RedisModule_ReplyWithError(ctx, "ERR Unknown field");
			}
			getter |= field;
			continue;
		case SET:
			field = select_field_from_str(argv[arg_idx]);
			if (field == EMPTY) {
				return RedisModule_ReplyWithError(ctx, "ERR Unknown field");
			}
			++arg_idx;
			if (arg_idx >= argc) {
				return RedisModule_WrongArity(ctx);
			}

			if (field == TTL) {
				long long v;
				if (RedisModule_StringToLongLong(argv[arg_idx], &v) != REDISMODULE_OK) {
					return RedisModule_ReplyWithError(ctx, "ERR Expected number");
				}
				if (v < 0 || v > UINT32_MAX) {
					return RedisModule_ReplyWithError(ctx, "ERR Value out of range");
				}
				rrset->ttl = v;
			} else {
				return RedisModule_ReplyWithError(ctx, "ERR Unknown field");
			}
			break;
		case INSERT:
			ret = rdataset_add(ctx, &rrset->rrs, argv[arg_idx]);
			if (ret == KNOT_ERANGE) {
				return RedisModule_ReplyWithError(ctx, "ERR Value out of range");
			} else if (ret == KNOT_ENOMEM || ret == KNOT_ESPACE) {
				return RedisModule_ReplyWithError(ctx, "ERR Not enough memory");
			} else if (ret != KNOT_EOK) {
				return RedisModule_ReplyWithError(ctx, "ERR Failed to add RDATA");
			}
			break;
		case REMOVE:
			ret = rdataset_remove(ctx, &rrset->rrs, argv[arg_idx]);
			if (ret != KNOT_EOK) {
				return RedisModule_ReplyWithError(ctx, "ERR Failed to remove RDATA");
			}
			break;
		default:
			return RedisModule_ReplyWithError(ctx, "ERR Unknown operation");
		}
	}

	if (store) {
		RedisModule_ModuleTypeSetValue(rrset_key, knot_zone_rrset_t, rrset);
	}
	RedisModule_CloseKey(rrset_key);

	if (getter) {
		RedisModule_ReplyWithArray(ctx, REDISMODULE_POSTPONED_ARRAY_LEN);
		size_t array_len = 0;
		if (getter & TTL) {
			RedisModule_ReplyWithArray(ctx, 2);
			RedisModule_ReplyWithStringBuffer(ctx, "TTL", 3);
			RedisModule_ReplyWithLongLong(ctx, rrset->ttl);
			array_len++;
		}
		if (getter & RDATA) {
			RedisModule_ReplyWithArray(ctx, 2);
			RedisModule_ReplyWithStringBuffer(ctx, "RDATA", 5);
			RedisModule_ReplyWithArray(ctx, rrset->rrs.count);
			knot_rdata_t *rdata = rrset->rrs.rdata;
			for (uint16_t idx = 0; idx < rrset->rrs.count; ++idx) {
				RedisModule_ReplyWithStringBuffer(ctx, (const char *)rdata->data, rdata->len);
				rdata = knot_rdataset_next(rdata);
			}
			array_len++;

		}
		RedisModule_ReplySetArrayLength(ctx, array_len);
	} else {
		RedisModule_ReplyWithEmptyString(ctx);
	}

	return REDISMODULE_OK;
}

static int knot_rrset_remove(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 4) {
		return RedisModule_WrongArity(ctx);
	}

	uint8_t origin[KNOT_DNAME_MAXLEN];
	size_t origin_strlen;
	const char *origin_str = RedisModule_StringPtrLen(argv[1], &origin_strlen);
	knot_dname_t *origin_dname = knot_dname_from_str(origin, origin_str, sizeof(origin));
	if (origin_dname == NULL) {
		return RedisModule_ReplyWithError(ctx, "ERR Wrong origin format");
	}

	RedisModuleKey *zone_key = find_zone(ctx, origin_dname, REDISMODULE_READ);
	if (zone_key == NULL) {
		return RedisModule_ReplyWithError(ctx, "ERR Unable find");
	}
	// TODO maybe delete whole zone, when it's the last stored rrset (??)
	if (RedisModule_KeyType(zone_key) == REDISMODULE_KEYTYPE_EMPTY) {
		RedisModule_CloseKey(zone_key);
		return RedisModule_ReplyWithError(ctx, "ERR Does not exist");
	}

	uint32_t id = 0;
	int ret = read_zone_id(zone_key, &id);
	RedisModule_CloseKey(zone_key);
	if (ret == KNOT_EMALF) {
		return RedisModule_ReplyWithError(ctx, "ERR Bad data");
	}
	RedisModuleString *zone_id = RedisModule_CreateString(ctx, (const char *)&id, sizeof(id));

	RedisModuleKey *rrset_key = find_rrset(ctx, zone_id, argv[2], argv[3], REDISMODULE_READ | REDISMODULE_WRITE);
	RedisModule_FreeString(ctx, zone_id);
	if (rrset_key == NULL) {
		return RedisModule_ReplyWithError(ctx, "ERR Unable find");
	} else if (RedisModule_KeyType(rrset_key) == REDISMODULE_KEYTYPE_EMPTY) {
		RedisModule_CloseKey(rrset_key);
		return RedisModule_ReplyWithError(ctx, "ERR Does not exist");
	}

	if (RedisModule_DeleteKey(rrset_key) != REDISMODULE_OK) {
		RedisModule_CloseKey(rrset_key);
		return RedisModule_ReplyWithError(ctx, "ERR Unable to remove");
	}
	RedisModule_CloseKey(rrset_key);

	RedisModule_ReplyWithEmptyString(ctx);
	return REDISMODULE_OK;
}

static void rrset_list_cb(RedisModuleCtx *ctx, RedisModuleString *keyname, RedisModuleKey *key, void *privdata)
{
	struct rrset_list_ctx *list_ctx = privdata;
	uint8_t prefix[5];
	prefix[0] = RRSET;
	memcpy(prefix + 1, &list_ctx->lookup_id, sizeof(list_ctx->lookup_id));

	size_t key_strlen = 0;
	const char *key_str = RedisModule_StringPtrLen(keyname, &key_strlen);
	if (memcmp(key_str, prefix, sizeof(prefix)) != 0) {
		return; // NOTE just filtering out not matching keys
	}

	knot_zone_rrset_v *rrset = RedisModule_ModuleTypeGetValue(key);

	uint16_t rtype = 0;
	memcpy(&rtype, key_str + key_strlen - sizeof(uint16_t), sizeof(uint16_t));

	RedisModule_ReplyWithArray(ctx, 5);
	RedisModule_ReplyWithStringBuffer(ctx, key_str + sizeof(prefix), key_strlen - (sizeof(prefix) + 2));
	RedisModule_ReplyWithLongLong(ctx, rtype);
	RedisModule_ReplyWithLongLong(ctx, rrset->ttl);
	RedisModule_ReplyWithLongLong(ctx, rrset->rrs.count);
	RedisModule_ReplyWithStringBuffer(ctx, (const char *)rrset->rrs.rdata, rrset->rrs.size);

	list_ctx->ctr += 1;
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

static int knot_rrset_load_slow(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 2) {
		return RedisModule_WrongArity(ctx);
	}

	size_t origin_strlen;
	const knot_dname_t *origin_dname = (const knot_dname_t *)RedisModule_StringPtrLen(argv[1], &origin_strlen);

	RedisModuleKey *zone_key = find_zone(ctx, origin_dname, REDISMODULE_READ);
	if (zone_key == NULL) {
		return RedisModule_ReplyWithError(ctx, "ERR Unable find");
	}
	if (RedisModule_KeyType(zone_key) == REDISMODULE_KEYTYPE_EMPTY) {
		RedisModule_CloseKey(zone_key);
		return RedisModule_ReplyWithError(ctx, "ERR Does not exist");
	}

	struct rrset_list_ctx lookup_ctx = {
		.origin = argv[1],
		.ctr = 0
	};

	int ret = read_zone_id(zone_key, &lookup_ctx.lookup_id);
	if (ret == KNOT_EMALF) {
		RedisModule_CloseKey(zone_key);
		return RedisModule_ReplyWithError(ctx, "ERR Bad data");
	}

	RedisModule_ReplyWithArray(ctx, REDISMODULE_POSTPONED_ARRAY_LEN);
	RedisModuleScanCursor *cursor = RedisModule_ScanCursorCreate();
	while (RedisModule_Scan(ctx, cursor, rrset_list_cb, &lookup_ctx) != 0);
	RedisModule_ScanCursorDestroy(cursor);
	RedisModule_ReplySetArrayLength(ctx, lookup_ctx.ctr);

	return REDISMODULE_OK;
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
		if (ret == KNOT_EMALF) {
			RedisModule_CloseKey(zone_key);
			return RedisModule_ReplyWithError(ctx, "ERR Bad data");
		}
		zone_id = RedisModule_CreateString(ctx, (const char *)&id, sizeof(id));
	} else {
		uint32_t id = dnssec_random_uint32_t();
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

	knot_zone_rrset_v *rrset = RedisModule_Alloc(sizeof(knot_zone_rrset_v));
	long long ttl_val = 0;
	ret = RedisModule_StringToLongLong(argv[4], &ttl_val);
	if (ttl_val < 0 || type > UINT32_MAX) {
		RedisModule_CloseKey(rrset_key);
		return RedisModule_ReplyWithError(ctx, "ERR Value out of range");
	}
	rrset->ttl = ttl_val;
	knot_rdataset_init(&rrset->rrs);

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

	if (	/* human api */
		RedisModule_CreateCommand(ctx, "knot.zone.insert", knot_zone_insert, "write", 1, 1, 1) == REDISMODULE_ERR ||
		RedisModule_CreateCommand(ctx, "knot.zone.list", knot_zone_list, "readonly", 1, 1, 1) == REDISMODULE_ERR ||
		RedisModule_CreateCommand(ctx, "knot.zone.read", knot_zone_read, "readonly", 1, 1, 1) == REDISMODULE_ERR ||
		RedisModule_CreateCommand(ctx, "knot.rrset.insert", knot_rrset_insert, "write", 1, 1, 1) == REDISMODULE_ERR ||
		RedisModule_CreateCommand(ctx, "knot.rrset.select", knot_rrset_select, "write", 1, 1, 1) == REDISMODULE_ERR ||
		RedisModule_CreateCommand(ctx, "knot.rrset.remove", knot_rrset_remove, "write", 1, 1, 1) == REDISMODULE_ERR ||
		/* binary api */
		RedisModule_CreateCommand(ctx, "knot.zone.exists", knot_zone_exists, "readonly", 1, 1, 1) == REDISMODULE_ERR ||
		RedisModule_CreateCommand(ctx, "knot.zone.load.l", knot_rrset_load_slow, "readonly", 1, 1, 1) == REDISMODULE_ERR ||
		RedisModule_CreateCommand(ctx, "knot.zone.load.u", knot_zone_load, "readonly", 1, 1, 1) == REDISMODULE_ERR ||
		RedisModule_CreateCommand(ctx, "knot.zone.purge", knot_zone_purge, "write", 1, 1, 1) == REDISMODULE_ERR ||
		RedisModule_CreateCommand(ctx, "knot.rrset.store", knot_rrset_store, "write", 1, 1, 1) == REDISMODULE_ERR
	) {
		RedisModule_Log(ctx, REDISMODULE_LOGLEVEL_WARNING, "ERR 'knot' module already loaded");
		RedisModule_ReplyWithError(ctx, "ERR 'knot' module already loaded");
		return REDISMODULE_ERR;
	}

	return REDISMODULE_OK;
}
