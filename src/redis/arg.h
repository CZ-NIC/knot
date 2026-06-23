/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "contrib/strtonum.h"

#define INSTANCE_MIN		1
#define INSTANCE_MAX		8
#define TXN_MIN			0
#define TXN_MAX			8
#define TXN_MAX_COUNT		(TXN_MAX - TXN_MIN + 1)
#define TXN_ID_ACTIVE		UINT8_MAX

static uint32_t rdb_default_ttl = 600;
static uint32_t rdb_event_age = 1200;
static uint32_t rdb_upd_history_len = 20;

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

typedef struct {
	uint8_t len;
	const char *str;
} arg_string_t;

#define ARG_OPT_TXT(out, name, dflt, value) { \
	out = dflt; \
	if (argc > 1) { \
		size_t len; \
		if (strcmp(RedisModule_StringPtrLen(argv[1], &len), "--" name) == 0) { \
			out = value; \
			argc--; \
			argv++; \
		} else if (strncmp(RedisModule_StringPtrLen(argv[1], &len), "--", 2) == 0) { \
			return RedisModule_ReplyWithError(ctx, RDB_E("invalid option")); \
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
	uint8_t shift = sizeof(out) < 8 ? sizeof(out) * 8 : 63; \
	long long max = (1ULL << shift) - 1; \
	if (RedisModule_StringToLongLong(arg, &val) != REDISMODULE_OK || val > max) { \
		return RedisModule_ReplyWithError(ctx, RDB_E("invalid " name)); \
	} \
	out = val; \
}

#define ARG_DATA(arg, out_len, out, name) { \
	if ((out = (uint8_t *)RedisModule_StringPtrLen(arg, &out_len)) == NULL) { \
		return RedisModule_ReplyWithError(ctx, RDB_E("invalid " name)); \
	} \
}

#define ARG_STREAM_ID(arg, out) { \
	size_t len; \
	const uint8_t *ptr = (const uint8_t *)RedisModule_StringPtrLen(arg, &len); \
	wire_ctx_t w = wire_ctx_init_const(ptr, len); \
	out.ms = wire_ctx_read_u64(&w); \
	out.seq = wire_ctx_read_u64(&w); \
	if (w.error != KNOT_EOK || wire_ctx_available(&w) != 0) { \
		return RedisModule_ReplyWithError(ctx, RDB_E("invalid stream ID")); \
	} \
}

#define ARG_DNAME(arg, out, name) { \
	size_t len; \
	const uint8_t *ptr = (const uint8_t *)RedisModule_StringPtrLen(arg, &len); \
	int ret = knot_dname_wire_check(ptr, ptr + len, NULL); \
	if (ret < 1 || ret != len) { \
		return RedisModule_ReplyWithError(ctx, RDB_E("invalid " name)); \
	} \
	/* We assume the dname is properly lowercased! */ \
	out.data = ptr; \
	out.len = ret; \
}

#define ARG_MODULENAME(arg, out, name) { \
	size_t len; \
	const char *ptr = RedisModule_StringPtrLen(arg, &len); \
	/* TODO test alphanum */ \
	if (len == 0 || len > 255) { \
		return RedisModule_ReplyWithError(ctx, RDB_E("invalid " name)); \
	} \
	out.str = ptr; \
	out.len = len; \
}

#define ARG_GEO_TYPE_TXT(arg, out, name) { \
	size_t len; \
	const char *ptr = RedisModule_StringPtrLen(arg, &len); \
	if (len == 3 && strncmp(ptr, "geo", 3) == 0) { \
		out.type = MODE_GEODB; \
	} else if (len == 3 && strncmp(ptr, "net", 3) == 0) { \
		out.type = MODE_SUBNET; \
	} else if (len == 6 && strncmp(ptr, "weight", 6) == 0) { \
		out.type = MODE_WEIGHTED; \
	} else { \
		return RedisModule_ReplyWithError(ctx, RDB_E("malformed " name)); \
	} \
}

#define ARG_GEO_TYPEVAL_TXT(arg, out, name) { \
	size_t len; int ret = KNOT_EOK; \
	const char *ptr = RedisModule_StringPtrLen(arg, &len); \
	if (len > 4 && strncmp(ptr, "net:", 4) == 0) { \
		ptr += 4; len -= 4; out.type = MODE_SUBNET; \
		ret = subnet_bin(&out.val, &out.val_size, ptr, len); \
	} else if (len > 4 && strncmp(ptr, "geo:", 4) == 0) { \
		ptr += 4; len -= 4; out.type = MODE_GEODB; \
		ret = geo_bin(&out.val, &out.val_size, ptr, len); \
	}else if (len > 7 && strncmp(ptr, "weight:", 7) == 0) { \
		ptr += 7; len -= 7; out.type = MODE_WEIGHTED; \
		weight_bin(&out.val, &out.val_size, ptr, len); \
	} else { \
		return RedisModule_ReplyWithError(ctx, RDB_E("malformed " name)); \
	} \
	if (ret != KNOT_EOK) { \
		return RedisModule_ReplyWithError(ctx, RDB_E("malformed")); \
	} \
	/* TODO deal with longer GEODB strings */ \
	/* TODO delete */ \
	if (len < 0 || len >= 256) { \
		return RedisModule_ReplyWithError(ctx, RDB_E("invalid " name)); \
	} \
}

#define ARG_FLAG(arg, out, flag) { \
	size_t len; \
	const char *ptr = RedisModule_StringPtrLen(arg, &len); \
	if (strcmp(ptr, flag) != 0) { \
		return RedisModule_ReplyWithError(ctx, RDB_E("invalid flag")); \
	} \
	out = true; \
}

#define ARG_DNAME_TXT(arg, out, origin, name) { \
	size_t len; \
	out.txt = RedisModule_StringPtrLen(arg, &len); \
	if (dname_from_str(out.txt, len, out.buff, origin) == NULL) { \
		return RedisModule_ReplyWithError(ctx, RDB_E("invalid " name)); \
	} \
	out.data = out.buff; \
	out.len = knot_dname_size(out.data); \
}

#define ARG_RTYPE_TXT(arg, out) { \
	size_t len; \
	const char *ptr = RedisModule_StringPtrLen(arg, &len); \
	if (knot_rrtype_from_string(ptr, &out) != 0) { \
		return RedisModule_ReplyWithError(ctx, RDB_E("invalid record type")); \
	} \
}

#define WIRE_STREAM_ID(id) \
	(RedisModuleStreamID){ .ms = htobe64(id->ms), .seq = htobe64(id->seq) }; \
	RedisModule_Assert(sizeof(RedisModuleStreamID) == 16);

static knot_dname_t *dname_from_str(const char *ptr, size_t len, uint8_t *out, arg_dname_t *origin)
{
	RedisModule_Assert(ptr != NULL && out != NULL);

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

static int geo_bin(void **output, uint8_t *output_len, const char *input, size_t input_len)
{
	// TODO - for longer you need more "length" bytes
	if (input_len > 0xFF) {
		return KNOT_EMALF;
	}
	char *buf = RedisModule_Strdup(input);
	if (buf == NULL) {
		return KNOT_ENOMEM;
	}

	*output = buf;
	*output_len = input_len;

	return KNOT_EOK;
}

static int subnet_bin(void **output, uint8_t *output_len, const char *input, size_t input_len)
{
	// RedisModule_Assert(output != NULL && *output == NULL && \
	//                    output_len != NULL && input != NULL && input_len > 0);

	struct sockaddr_storage ss;
	uint8_t prefix = 0;
	char *tmp_input = RedisModule_Strdup(input);
	if (tmp_input == NULL) {
		return KNOT_ENOMEM;
	}

	char *slash = strchr(tmp_input, '/');
	if (slash == NULL) {
		slash = tmp_input + input_len;
	}
	*slash = '\0';

	// Try to parse as IPv4.
	int ret = sockaddr_set(&ss, AF_INET, tmp_input, 0);
	prefix = 32;
	if (ret != KNOT_EOK) {
		// Try to parse as IPv6.
		ret = sockaddr_set(&ss, AF_INET6, tmp_input, 0);
		prefix = 128;
	}
	if (ret != KNOT_EOK) {
		RedisModule_Free(tmp_input);
		return KNOT_EMALF;
	}

	// Parse subnet prefix.
	if (slash < tmp_input + input_len - 1) {
		ret = str_to_u8(slash + 1, &prefix);
		if (ret != KNOT_EOK) {
			RedisModule_Free(tmp_input);
			return ret;
		}
		if (ss.ss_family == AF_INET && prefix > 32) {
			prefix = 32;
		} else if (ss.ss_family == AF_INET6 && prefix > 128) {
			prefix = 128;
		}
	}
	RedisModule_Free(tmp_input);

	// Parse address.
	uint8_t size = ((prefix - 1) / 8) + 1;
	size_t olen = sizeof(uint8_t) + sizeof(uint8_t) + size;
	uint8_t *buf = (uint8_t *)RedisModule_Calloc(1, olen);
	if (buf == NULL) {
		return KNOT_ENOMEM;
	}

	buf[0] = prefix;
	buf[1] = ss.ss_family;
	if (ss.ss_family == AF_INET) {
		memcpy(buf + 2, &((struct sockaddr_in *)&ss)->sin_addr, size);
	} else if (ss.ss_family == AF_INET6) {
		memcpy(buf + 2, &((struct sockaddr_in6 *)&ss)->sin6_addr, size);
	} else {
		RedisModule_Free(buf);
		return KNOT_EMALF;
	}
	buf[olen - 1] &= 0xFF << ((8 - (prefix % 8)) % 8);

	*output = buf;
	*output_len = olen;

	return KNOT_EOK;
}

static int weight_bin(void **output, uint8_t *output_len, const char *input, size_t input_len)
{
	uint16_t *buf = RedisModule_Calloc(1, sizeof(uint16_t));
	if (buf == NULL) {
		return KNOT_ENOMEM;
	}
	if (str_to_u16(input, buf) != KNOT_EOK) {
		RedisModule_Free(buf);
		return KNOT_EMALF;
	}

	*output = buf;
	*output_len = sizeof(uint16_t);

	return KNOT_EOK;
}

#define ALIGN_RDATASET(rdataset) { \
	if (((uintptr_t)rdataset.rdata % 2) != 0) { \
		uint8_t *tmp = alloca(rdataset.size); \
		if (tmp != NULL) { \
			memcpy(tmp, (void *)rdataset.rdata, rdataset.size); \
			rdataset.rdata = (knot_rdata_t *)tmp; \
		} \
	} \
}
