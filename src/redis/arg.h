/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

typedef struct {
	const uint8_t *data;
	uint8_t len;
	// Next items are used if the dname was parsed from TXT.
	const char *txt;
	knot_dname_storage_t buff;
} arg_dname_t;

#define ARG_TXN(arg, out, ctx, origin) { \
	size_t len; \
	const uint8_t *ptr = (const uint8_t *)RedisModule_StringPtrLen(arg, &len); \
	if (len != sizeof(rdb_txn_t)) { \
		return RedisModule_ReplyWithError(ctx, "ERR invalid transaction"); \
	} \
	memcpy(&out, ptr, len); \
	if (!txn_is_open2(ctx, &origin, &txn)) { \
		return RedisModule_ReplyWithError(ctx, "ERR non-existent transaction"); \
	} \
}

#define ARG_TXN_TXT(arg, out, ctx, origin) { \
	size_t len; \
	const char *ptr = RedisModule_StringPtrLen(arg, &len); \
	if (len != 2 || ptr[0] < '0' || ptr[0] > '9' || ptr[1] < '0' || ptr[1] > '9') { \
		return RedisModule_ReplyWithError(ctx, "ERR invalid transaction"); \
	} \
	out.instance = ptr[0] - '0'; \
	out.id = ptr[1] - '0'; \
	if (!txn_is_open2(ctx, &origin, &txn)) { \
		return RedisModule_ReplyWithError(ctx, "ERR non-existent transaction"); \
	} \
}

#define ARG_NUM(arg, out, name) { \
	long long val; \
	if (RedisModule_StringToLongLong(arg, &val) != REDISMODULE_OK || val > sizeof(out)) { \
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
