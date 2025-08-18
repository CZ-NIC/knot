/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#define INSTANCE_MIN		1
#define INSTANCE_MAX		8
#define TXN_MIN			0
#define TXN_MAX			8
#define TXN_MAX_COUNT		(TXN_MAX - TXN_MIN + 1)
#define TXN_ID_ACTIVE		UINT8_MAX

static uint32_t rdb_default_ttl = 600;
static uint32_t rdb_event_age = 1200;

typedef enum {
	DUMP_BIN,
	DUMP_TXT,
	DUMP_COMPACT
} dump_mode_t;

typedef struct {
	const uint8_t *data;
	uint8_t len;
	// Next items are used if the dname was parsed from TXT.
	const char *txt;
	knot_dname_storage_t buff;
} arg_dname_t;

#define ARG_DUMP_TXT(out) { \
	out = DUMP_TXT; \
	if (argc > 1) { \
		size_t len; \
		if (strcmp(RedisModule_StringPtrLen(argv[1], &len), "--compact") == 0) { \
			mode = DUMP_COMPACT; \
			argc--; \
			argv++; \
		} else if (strncmp(RedisModule_StringPtrLen(argv[1], &len), "--", 2) == 0) { \
			return RedisModule_ReplyWithError(ctx, "ERR invalid option"); \
		} \
	} \
}

#define ARG_INST(arg, out) { \
	size_t len; \
	const uint8_t *ptr = (const uint8_t *)RedisModule_StringPtrLen(arg, &len); \
	if (len != 1 || ptr[0] < INSTANCE_MIN || ptr[0] > INSTANCE_MAX) { \
		return RedisModule_ReplyWithError(ctx, RDB_EINST); \
	} \
	out.instance = ptr[0]; \
	out.id = TXN_ID_ACTIVE; \
}

#define ARG_INST_TXT(arg, out) { \
	size_t len; \
	const uint8_t *ptr = (const uint8_t *)RedisModule_StringPtrLen(arg, &len); \
	if (len != 1 || ptr[0] < '0' + INSTANCE_MIN || ptr[0] > '0' + INSTANCE_MAX) { \
		return RedisModule_ReplyWithError(ctx, RDB_EINST); \
	} \
	out.instance = ptr[0] - '0'; \
	out.id = TXN_ID_ACTIVE; \
}

#define ARG_TXN(arg, out) { \
	size_t len; \
	const uint8_t *ptr = (const uint8_t *)RedisModule_StringPtrLen(arg, &len); \
	if (len != 2 || ptr[0] < INSTANCE_MIN || ptr[0] > INSTANCE_MAX  \
	             || ptr[1] < TXN_MIN || ptr[1] > TXN_MAX) { \
		return RedisModule_ReplyWithError(ctx, RDB_ETXN); \
	} \
	memcpy(&out, ptr, len); \
}

#define ARG_TXN_TXT(arg, out) { \
	size_t len; \
	const char *ptr = RedisModule_StringPtrLen(arg, &len); \
	if (len != 2 || ptr[0] < '0' + INSTANCE_MIN || ptr[0] > '0' + INSTANCE_MAX  \
	             || ptr[1] < '0' + TXN_MIN || ptr[1] > '0' + TXN_MAX) { \
		return RedisModule_ReplyWithError((ctx), RDB_ETXN); \
	} \
	out.instance = ptr[0] - '0'; \
	out.id = ptr[1] - '0'; \
}

#define ARG_INST_TXN(arg, out) { \
	out.id = TXN_ID_ACTIVE; \
	size_t len; \
	const char *ptr = RedisModule_StringPtrLen(arg, &len); \
	switch (len) { \
	case 2: \
		if (ptr[1] < TXN_MIN || ptr[1] > TXN_MAX) { \
			return RedisModule_ReplyWithError((ctx), RDB_ETXN); \
		} \
		out.id = ptr[1]; \
	case 1: /* FALLTHROUGH */ \
		if (ptr[0] < INSTANCE_MIN || ptr[0] > INSTANCE_MAX) { \
			return RedisModule_ReplyWithError(ctx, RDB_EINST); \
		} \
		out.instance = ptr[0]; \
		break; \
	default: \
		return RedisModule_ReplyWithError(ctx, RDB_ETXN); \
	} \
}

#define ARG_INST_TXN_TXT(arg, out) { \
	out.id = TXN_ID_ACTIVE; \
	size_t len; \
	const char *ptr = RedisModule_StringPtrLen(arg, &len); \
	switch (len) { \
	case 2: \
		if (ptr[1] < '0' - TXN_MIN || ptr[1] > '0' + TXN_MAX) { \
			return RedisModule_ReplyWithError((ctx), RDB_ETXN); \
		} \
		out.id = ptr[1] - '0'; \
	case 1: /* FALLTHROUGH */ \
		if (ptr[0] < '0' + INSTANCE_MIN || ptr[0] > '0' + INSTANCE_MAX) { \
			return RedisModule_ReplyWithError(ctx, RDB_EINST); \
		} \
		out.instance = ptr[0] - '0'; \
		break; \
	default: \
		return RedisModule_ReplyWithError(ctx, RDB_ETXN); \
	} \
}

#define ARG_NUM(arg, out, name) { \
	long long val; \
	long long max = (1ULL << (sizeof(out) * 8)) - 1; \
	if (RedisModule_StringToLongLong(arg, &val) != REDISMODULE_OK || val > max) { \
		return RedisModule_ReplyWithError(ctx, "ERR invalid " name); \
	} \
	out = val; \
}

#define ARG_DATA(arg, out_len, out, name) { \
	if ((out = (uint8_t *)RedisModule_StringPtrLen(arg, &out_len)) == NULL) { \
		return RedisModule_ReplyWithError(ctx, "ERR invalid " name); \
	} \
}

#define ARG_DNAME(arg, out, name) { \
	size_t len; \
	const uint8_t *ptr = (const uint8_t *)RedisModule_StringPtrLen(arg, &len); \
	int ret = knot_dname_wire_check(ptr, ptr + len, NULL); \
	if (ret < 1 || ret != len) { \
		return RedisModule_ReplyWithError(ctx, "ERR invalid " name); \
	} \
	/* We assume the dname is properly lowercased! */ \
	out.data = ptr; \
	out.len = ret; \
}

#define ARG_DNAME_TXT(arg, out, origin, name) { \
	size_t len; \
	out.txt = RedisModule_StringPtrLen(arg, &len); \
	if (dname_from_str(out.txt, len, out.buff, origin) == NULL) { \
		return RedisModule_ReplyWithError(ctx, "ERR invalid " name); \
	} \
	out.data = out.buff; \
	out.len = knot_dname_size(out.data); \
}

#define ARG_RTYPE_TXT(arg, out) { \
	size_t len; \
	const char *ptr = RedisModule_StringPtrLen(arg, &len); \
	if (knot_rrtype_from_string(ptr, &out) != 0) { \
		return RedisModule_ReplyWithError(ctx, "ERR invalid record type"); \
	} \
}

static knot_dname_t *dname_from_str(const char *ptr, size_t len, uint8_t *out, arg_dname_t *origin)
{
	assert(ptr != NULL && out != NULL);

	if (knot_dname_from_str(out, ptr, KNOT_DNAME_MAXLEN) == NULL) {
		return NULL;
	}
	knot_dname_to_lower(out);

	if (origin != NULL) {
		bool fqdn = false;
		size_t prefix_len = 0;

		if (len > 0 && (len != 1 || ptr[0] != '@')) {
			// Check if the owner is FQDN.
			if (ptr[len - 1] == '.') {
				fqdn = true;
			}

			prefix_len = knot_dname_size(out);
			if (prefix_len == 0) {
				return NULL;
			}

			// Ignore trailing dot.
			prefix_len--;
		}

		// Append the origin.
		if (!fqdn) {
			if (origin->len == 0 || origin->len > KNOT_DNAME_MAXLEN - prefix_len) {
				return NULL;
			}
			memcpy(out + prefix_len, origin->data, origin->len);
		}
	}

	return out;
}
