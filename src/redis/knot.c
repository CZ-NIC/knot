/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: LGPL-2.1-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define REDISMODULE_MAIN // Fixes loading error undefined symbol: RedisModule_ReplySetArrayLength.
#include "contrib/redis/redismodule.h"
#include "redis/knot.h"
#include "redis/error.h"
#include "redis/libs.h"
#include "redis/arg.h"
#include "redis/type_diff.h"
#include "redis/type_rrset.h"
#include "redis/internal.h"

#define register_command_txt(name, cb, rights) \
	RedisModule_CreateCommand(ctx, name, cb, rights, 1, 1, 1) == REDISMODULE_ERR || \
	(cmd = RedisModule_GetCommand(ctx, name)) == NULL || \
	RedisModule_SetCommandInfo(cmd, &cb##_info) == REDISMODULE_ERR

#define register_command_bin(name, cb, rights) \
	RedisModule_CreateCommand(ctx, name, cb, rights, 1, 1, 1) == REDISMODULE_ERR

static RedisModuleCommandArg origin_instance_info_args[] = {
	{"origin",   REDISMODULE_ARG_TYPE_STRING,  -1, NULL, NULL, NULL, REDISMODULE_CMD_ARG_NONE},
	{"instance", REDISMODULE_ARG_TYPE_INTEGER, -1, NULL, NULL, NULL, REDISMODULE_CMD_ARG_NONE},
	{ 0 }
};

static RedisModuleCommandArg origin_transaction_info_args[] = {
	{"origin",      REDISMODULE_ARG_TYPE_STRING,  -1, NULL, NULL, NULL, REDISMODULE_CMD_ARG_NONE},
	{"transaction", REDISMODULE_ARG_TYPE_INTEGER, -1, NULL, NULL, NULL, REDISMODULE_CMD_ARG_NONE},
	{ 0 }
};

static RedisModuleCommandArg store_txt_info_args[] = {
	{"origin",      REDISMODULE_ARG_TYPE_STRING,  -1, NULL, NULL, NULL, REDISMODULE_CMD_ARG_NONE},
	{"transaction", REDISMODULE_ARG_TYPE_INTEGER, -1, NULL, NULL, NULL, REDISMODULE_CMD_ARG_NONE},
	{"data",        REDISMODULE_ARG_TYPE_STRING,  -1, NULL, NULL, NULL, REDISMODULE_CMD_ARG_NONE},
	{ 0 }
};

static RedisModuleCommandArg upd_load_txt_info_args[] = {
	{"opt",      REDISMODULE_ARG_TYPE_PURE_TOKEN, -1, "--compact", NULL, NULL, REDISMODULE_CMD_ARG_OPTIONAL},
	{"origin",   REDISMODULE_ARG_TYPE_STRING,     -1, NULL, NULL, NULL, REDISMODULE_CMD_ARG_NONE},
	{"instance", REDISMODULE_ARG_TYPE_INTEGER,    -1, NULL, NULL, NULL, REDISMODULE_CMD_ARG_NONE},
	{"serial",   REDISMODULE_ARG_TYPE_INTEGER,    -1, NULL, NULL, NULL, REDISMODULE_CMD_ARG_NONE},
	{"owner",    REDISMODULE_ARG_TYPE_STRING,     -1, NULL, NULL, NULL, REDISMODULE_CMD_ARG_OPTIONAL},
	{"rtype",    REDISMODULE_ARG_TYPE_STRING,     -1, NULL, NULL, NULL, REDISMODULE_CMD_ARG_OPTIONAL},
	{ 0 }
};

static RedisModuleCommandArg zone_load_txt_info_args[] = {
	{"opt",      REDISMODULE_ARG_TYPE_PURE_TOKEN, -1, "--compact", NULL, NULL, REDISMODULE_CMD_ARG_OPTIONAL},
	{"origin",   REDISMODULE_ARG_TYPE_STRING,     -1, NULL,        NULL, NULL, REDISMODULE_CMD_ARG_NONE},
	{"instance", REDISMODULE_ARG_TYPE_INTEGER,    -1, NULL,        NULL, NULL, REDISMODULE_CMD_ARG_NONE},
	{"owner",    REDISMODULE_ARG_TYPE_STRING,     -1, NULL,        NULL, NULL, REDISMODULE_CMD_ARG_OPTIONAL},
	{"rtype",    REDISMODULE_ARG_TYPE_STRING,     -1, NULL,        NULL, NULL, REDISMODULE_CMD_ARG_OPTIONAL},
	{ 0 }
};

static const RedisModuleCommandInfo zone_begin_txt_info = {
	.version = REDISMODULE_COMMAND_INFO_VERSION,
	.summary = "Creates zone editing transaction",
	.complexity = "O(1)",
	.since = "7.0.0",
	.arity = 3,
	.args = origin_instance_info_args,
};

static const RedisModuleCommandInfo zone_store_txt_info = {
	.version = REDISMODULE_COMMAND_INFO_VERSION,
	.summary = "Store records to zone transaction",
	.complexity = "O(1)",
	.since = "7.0.0",
	.arity = 4,
	.args = store_txt_info_args,
};

static const RedisModuleCommandInfo zone_commit_txt_info = {
	.version = REDISMODULE_COMMAND_INFO_VERSION,
	.summary = "Store zone transaction",
	.complexity = "Up to O(m), where m is number of rrsets and diffs updates of zone",
	.since = "7.0.0",
	.arity = 3,
	.args = origin_transaction_info_args,
};

static const RedisModuleCommandInfo zone_abort_txt_info = {
	.version = REDISMODULE_COMMAND_INFO_VERSION,
	.summary = "Abort zone transaction",
	.complexity = "Up to O(l), where l is number of rrsets in zone",
	.since = "7.0.0",
	.arity = 3,
	.args = origin_transaction_info_args,
};

static const RedisModuleCommandInfo zone_load_txt_info = {
	.version = REDISMODULE_COMMAND_INFO_VERSION,
	.summary = "Print zone instance or transaction",
	.complexity = "Up to O(l), where l is number of rrsets in zone",
	.since = "7.0.0",
	.arity = -3,
	.args = zone_load_txt_info_args,
};

static const RedisModuleCommandInfo zone_purge_txt_info = {
	.version = REDISMODULE_COMMAND_INFO_VERSION,
	.summary = "Purge zone instance",
	.complexity = "Up to O(m), where m is number of rrsets and diffs updates of zone",
	.since = "7.0.0",
	.arity = 3,
	.args = origin_instance_info_args,
};

static const RedisModuleCommandInfo zone_list_txt_info = {
	.version = REDISMODULE_COMMAND_INFO_VERSION,
	.summary = "Print zones stored in database",
	.complexity = "O(j), where j is number of zones",
	.since = "7.0.0",
	.arity = 1,
	.args = zone_load_txt_info_args,
};

static const RedisModuleCommandInfo upd_begin_txt_info = {
	.version = REDISMODULE_COMMAND_INFO_VERSION,
	.summary = "Creates update editing transaction",
	.complexity = "O(1)",
	.since = "7.0.0",
	.arity = 3,
	.args = origin_instance_info_args,
};

static const RedisModuleCommandInfo upd_add_txt_info = {
	.version = REDISMODULE_COMMAND_INFO_VERSION,
	.summary = "Add record to the zone with update",
	.complexity = "O(1)",
	.since = "7.0.0",
	.arity = 4,
	.args = store_txt_info_args,
};

static const RedisModuleCommandInfo upd_remove_txt_info = {
	.version = REDISMODULE_COMMAND_INFO_VERSION,
	.summary = "Remove record from the zone with update",
	.complexity = "O(1)",
	.since = "7.0.0",
	.arity = 4,
	.args = store_txt_info_args,
};

static const RedisModuleCommandInfo upd_commit_txt_info = {
	.version = REDISMODULE_COMMAND_INFO_VERSION,
	.summary = "Commit update to the zone",
	.complexity = "O(k), where k is number of rrsets in update",
	.since = "7.0.0",
	.arity = 3,
	.args = origin_transaction_info_args,
};

static const RedisModuleCommandInfo upd_abort_txt_info = {
	.version = REDISMODULE_COMMAND_INFO_VERSION,
	.summary = "Abort update transaction",
	.complexity = "O(k), where k is number of rrsets in update",
	.since = "7.0.0",
	.arity = 3,
	.args = origin_transaction_info_args,
};

static const RedisModuleCommandInfo upd_diff_txt_info = {
	.version = REDISMODULE_COMMAND_INFO_VERSION,
	.summary = "Print state of update transaction",
	.complexity = "O(k), where k is number of rrsets in update",
	.since = "7.0.0",
	.arity = -3,
	.args = zone_load_txt_info_args,
};

static const RedisModuleCommandInfo upd_load_txt_info = {
	.version = REDISMODULE_COMMAND_INFO_VERSION,
	.summary = "Print updates since specified serial",
	.complexity = "O(k), where k is number of rrsets in update",
	.since = "7.0.0",
	.arity = -4,
	.args = upd_load_txt_info_args,
};

static int zone_begin_txt(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	arg_dname_t origin;
	ARG_DNAME_TXT(argv[1], origin, NULL, "origin");

	rdb_txn_t txn;
	ARG_INST_TXT(argv[2], txn);

	zone_begin_txt_format(ctx, &txn, &origin);

	return REDISMODULE_OK;
}

static int zone_begin_bin(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 3) {
		return RedisModule_WrongArity(ctx);
	}

	arg_dname_t origin;
	ARG_DNAME(argv[1], origin, "origin");

	rdb_txn_t txn;
	ARG_INST(argv[2], txn);

	zone_begin_bin_format(ctx, &txn, &origin);

	return REDISMODULE_OK;
}

static int zone_store_txt(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	arg_dname_t origin;
	ARG_DNAME_TXT(argv[1], origin, NULL, "origin");

	rdb_txn_t txn;
	ARG_TXN_TXT(argv[2], txn);

	void *zone_data;
	size_t data_len;
	ARG_DATA(argv[3], data_len, zone_data, "zone data");

	zone_store_txt_format(ctx, &origin, &txn, zone_data, data_len);

	return REDISMODULE_OK;
}

static int zone_store_bin(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 8) {
		return RedisModule_WrongArity(ctx);
	}

	arg_dname_t origin;
	ARG_DNAME(argv[1], origin, "origin");

	rdb_txn_t txn;
	ARG_TXN(argv[2], txn);

	arg_dname_t owner;
	ARG_DNAME(argv[3], owner, "owner");

	uint16_t rtype;
	ARG_NUM(argv[4], rtype, "record type");

	uint32_t ttl;
	ARG_NUM(argv[5], ttl, "TTL");

	uint16_t rcount;
	ARG_NUM(argv[6], rcount, "record count");

	uint8_t *rdataset;
	size_t rdataset_len;
	ARG_DATA(argv[7], rdataset_len, rdataset, "rdataset");

	zone_store_bin_format(ctx, &origin, &txn, &owner, rtype, ttl, rcount, rdataset, rdataset_len);

	return REDISMODULE_OK;
}

static int zone_commit_txt(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	arg_dname_t origin;
	ARG_DNAME_TXT(argv[1], origin, NULL, "origin");

	rdb_txn_t txn;
	ARG_TXN_TXT(argv[2], txn);

	zone_commit(ctx, &origin, &txn);
	return REDISMODULE_OK;
}

static int zone_commit_bin(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 3) {
		return RedisModule_WrongArity(ctx);
	}

	arg_dname_t origin;
	ARG_DNAME(argv[1], origin, "origin");

	rdb_txn_t txn;
	ARG_TXN(argv[2], txn);

	zone_commit(ctx, &origin, &txn);
	return REDISMODULE_OK;
}

static int zone_abort_txt(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	arg_dname_t origin;
	ARG_DNAME_TXT(argv[1], origin, NULL, "origin");

	rdb_txn_t txn;
	ARG_TXN_TXT(argv[2], txn);

	zone_abort(ctx, &origin, &txn);
	return REDISMODULE_OK;
}

static int zone_abort_bin(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 3) {
		return RedisModule_WrongArity(ctx);
	}

	arg_dname_t origin;
	ARG_DNAME(argv[1], origin, "origin");

	rdb_txn_t txn;
	ARG_TXN(argv[2], txn);

	zone_abort(ctx, &origin, &txn);
	return REDISMODULE_OK;
}

static int zone_exists_bin(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 3) {
		return RedisModule_WrongArity(ctx);
	}

	arg_dname_t origin;
	ARG_DNAME(argv[1], origin, "origin");

	rdb_txn_t txn;
	ARG_INST(argv[2], txn);

	zone_exists(ctx, &origin, &txn);

	return REDISMODULE_OK;
}

static int zone_load_txt(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	dump_mode_t mode;
	ARG_DUMP_TXT(mode);

	arg_dname_t origin;
	ARG_DNAME_TXT(argv[1], origin, NULL, "origin");

	rdb_txn_t txn;
	ARG_INST_TXN_TXT(argv[2], txn);

	arg_dname_t owner;
	if (argc > 3) {
		ARG_DNAME_TXT(argv[3], owner, &origin, "owner");
	}

	uint16_t rtype;
	if (argc > 4) {
		ARG_RTYPE_TXT(argv[4], rtype);
	}

	if (argc > 5) {
		return RedisModule_WrongArity(ctx);
	}

	zone_load(ctx, &origin, &txn, (argc >= 4) ? &owner : NULL,
	          (argc >= 5) ? &rtype : NULL, mode);
	return REDISMODULE_OK;
}

static int zone_load_bin(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc < 3) {
		return RedisModule_WrongArity(ctx);
	}

	arg_dname_t origin;
	ARG_DNAME(argv[1], origin, "origin");

	rdb_txn_t txn;
	ARG_INST_TXN(argv[2], txn);

	arg_dname_t owner;
	if (argc > 3) {
		ARG_DNAME(argv[3], owner, "owner");
	}

	uint16_t rtype;
	if (argc > 4) {
		ARG_NUM(argv[4], rtype, "record type");
	}

	if (argc > 5) {
		return RedisModule_WrongArity(ctx);
	}

	zone_load(ctx, &origin, &txn, (argc >= 4) ? &owner : NULL,
	          (argc >= 5) ? &rtype : NULL, DUMP_BIN);
	return REDISMODULE_OK;
}

static int zone_purge_txt(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	arg_dname_t origin;
	ARG_DNAME_TXT(argv[1], origin, NULL, "origin");

	rdb_txn_t txn;
	ARG_INST_TXT(argv[2], txn);

	zone_purge(ctx, &origin, &txn);
	return REDISMODULE_OK;
}

static int zone_purge_bin(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 3) {
		return RedisModule_WrongArity(ctx);
	}

	arg_dname_t origin;
	ARG_DNAME(argv[1], origin, "origin");

	rdb_txn_t txn;
	ARG_INST(argv[2], txn);

	zone_purge(ctx, &origin, &txn);
	return REDISMODULE_OK;
}

static int zone_list_txt(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	zone_list(ctx, true);
	return REDISMODULE_OK;
}

static int zone_list_bin(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	zone_list(ctx, false);
	return REDISMODULE_OK;
}

static int upd_begin_txt(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	arg_dname_t origin;
	ARG_DNAME_TXT(argv[1], origin, NULL, "origin");

	rdb_txn_t txn;
	ARG_INST_TXT(argv[2], txn);

	if (upd_begin(ctx, &txn, &origin) != KNOT_EOK) {
		return REDISMODULE_OK;
	}

	return RedisModule_ReplyWithLongLong(ctx, serialize_transaction(&txn));
}

static int upd_begin_bin(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 3) {
		return RedisModule_WrongArity(ctx);
	}

	arg_dname_t origin;
	ARG_DNAME(argv[1], origin, "origin");

	rdb_txn_t txn;
	ARG_INST(argv[2], txn);

	if (upd_begin(ctx, &txn, &origin) != KNOT_EOK) {
		return REDISMODULE_OK;
	}

	return RedisModule_ReplyWithStringBuffer(ctx, (const char *)&txn, sizeof(txn));
}

static int upd_add_txt(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	arg_dname_t origin;
	ARG_DNAME_TXT(argv[1], origin, NULL, "origin");

	rdb_txn_t txn;
	ARG_TXN_TXT(argv[2], txn);

	void *zone_data;
	size_t data_len;
	ARG_DATA(argv[3], data_len, zone_data, "zone data");

	scanner_ctx_t s_ctx = { ctx, &txn, rdb_default_ttl, ADD };
	if (run_scanner(&s_ctx, &origin, zone_data, data_len) == 0) {
		return RedisModule_ReplyWithSimpleString(ctx, RDB_RETURN_OK);
	}

	return REDISMODULE_OK;
}

static int upd_add_bin(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 8) {
		return RedisModule_WrongArity(ctx);
	}

	arg_dname_t origin;
	ARG_DNAME(argv[1], origin, "origin");

	rdb_txn_t txn;
	ARG_TXN(argv[2], txn);

	arg_dname_t owner;
	ARG_DNAME(argv[3], owner, "owner");

	uint16_t rtype;
	ARG_NUM(argv[4], rtype, "record type");

	uint32_t ttl;
	ARG_NUM(argv[5], ttl, "TTL");

	uint16_t rcount;
	ARG_NUM(argv[6], rcount, "record count");

	uint8_t *rdata;
	size_t rdata_len;
	ARG_DATA(argv[7], rdata_len, rdata, "rdata");

	knot_rdataset_t rdataset = {
		.count = rcount,
		.size = rdata_len,
		.rdata = (knot_rdata_t *)rdata
	};

	knot_upd_add_bin(ctx, &origin, &txn, &owner, ttl, rtype, &rdataset);

	return RedisModule_ReplyWithSimpleString(ctx, RDB_RETURN_OK);
}

static int upd_remove_txt(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	arg_dname_t origin;
	ARG_DNAME_TXT(argv[1], origin, NULL, "origin");

	rdb_txn_t txn;
	ARG_TXN_TXT(argv[2], txn);

	void *zone_data;
	size_t data_len;
	ARG_DATA(argv[3], data_len, zone_data, "zone data");

	scanner_ctx_t s_ctx = { ctx, &txn, TTL_EMPTY, REM };
	if (run_scanner(&s_ctx, &origin, zone_data, data_len) == 0) {
		return RedisModule_ReplyWithSimpleString(ctx, RDB_RETURN_OK);
	}

	return REDISMODULE_OK;
}

static int upd_remove_bin(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 8) {
		return RedisModule_WrongArity(ctx);
	}

	arg_dname_t origin;
	ARG_DNAME(argv[1], origin, "origin");

	rdb_txn_t txn;
	ARG_TXN(argv[2], txn);

	arg_dname_t owner;
	ARG_DNAME(argv[3], owner, "owner");

	uint16_t rtype;
	ARG_NUM(argv[4], rtype, "record type");

	uint32_t ttl;
	ARG_NUM(argv[5], ttl, "TTL");

	uint16_t rcount;
	ARG_NUM(argv[6], rcount, "record count");

	uint8_t *rdata;
	size_t rdata_len;
	ARG_DATA(argv[7], rdata_len, rdata, "rdata");

	knot_rdataset_t rdataset = {
		.count = rcount,
		.size = rdata_len,
		.rdata = (knot_rdata_t *)rdata
	};

	knot_upd_remove_bin(ctx, &origin, &txn, &owner, ttl, rtype, &rdataset);

	return RedisModule_ReplyWithSimpleString(ctx, RDB_RETURN_OK);
}

static int upd_commit_txt(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	arg_dname_t origin;
	ARG_DNAME_TXT(argv[1], origin, NULL, "origin");

	rdb_txn_t txn;
	ARG_TXN_TXT(argv[2], txn);

	if (upd_commit(ctx, &origin, &txn, false) != KNOT_EOK) {
		return REDISMODULE_OK;
	}

	return RedisModule_ReplyWithSimpleString(ctx, RDB_RETURN_OK);
}

static int upd_commit_bin(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 3) {
		return RedisModule_WrongArity(ctx);
	}

	arg_dname_t origin;
	ARG_DNAME(argv[1], origin, "origin");

	rdb_txn_t txn;
	ARG_TXN(argv[2], txn)

	if (upd_commit(ctx, &origin, &txn, true) != KNOT_EOK) {
		return REDISMODULE_OK;
	}

	return RedisModule_ReplyWithSimpleString(ctx, RDB_RETURN_OK);
}

static int upd_abort_txt(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	arg_dname_t origin;
	ARG_DNAME_TXT(argv[1], origin, NULL, "origin");

	rdb_txn_t txn;
	ARG_TXN_TXT(argv[2], txn);

	if (upd_abort(ctx, &origin, &txn) != KNOT_EOK) {
		return REDISMODULE_OK;
	}

	return RedisModule_ReplyWithSimpleString(ctx, RDB_RETURN_OK);
}

static int upd_abort_bin(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 3) {
		return RedisModule_WrongArity(ctx);
	}

	arg_dname_t origin;
	ARG_DNAME(argv[1], origin, "origin");

	rdb_txn_t txn;
	ARG_TXN(argv[2], txn)

	if (upd_abort(ctx, &origin, &txn) != KNOT_EOK) {
		return REDISMODULE_OK;
	}

	return RedisModule_ReplyWithSimpleString(ctx, RDB_RETURN_OK);
}

static int upd_diff_txt(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	dump_mode_t mode;
	ARG_DUMP_TXT(mode);

	arg_dname_t origin;
	ARG_DNAME_TXT(argv[1], origin, NULL, "origin");

	rdb_txn_t txn;
	ARG_TXN_TXT(argv[2], txn);

	arg_dname_t owner;
	if (argc > 3) {
		ARG_DNAME_TXT(argv[3], owner, &origin, "owner");
	}

	uint16_t rtype;
	if (argc > 4) {
		ARG_RTYPE_TXT(argv[4], rtype);
	}

	if (argc > 5) {
		return RedisModule_WrongArity(ctx);
	}

	return upd_diff(ctx, &origin, &txn, (argc >= 4) ? &owner : NULL,
	                (argc >= 5) ? &rtype : NULL, mode);
}

static int upd_diff_bin(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc < 3) {
		return RedisModule_WrongArity(ctx);
	}

	arg_dname_t origin;
	ARG_DNAME(argv[1], origin, "origin");

	rdb_txn_t txn;
	ARG_TXN(argv[2], txn);

	arg_dname_t owner;
	if (argc > 3) {
		ARG_DNAME(argv[3], owner, "owner");
	}

	uint16_t rtype;
	if (argc > 4) {
		ARG_NUM(argv[4], rtype, "record type");
	}

	if (argc > 5) {
		return RedisModule_WrongArity(ctx);
	}

	return upd_diff(ctx, &origin, &txn, (argc >= 4) ? &owner : NULL,
	                (argc >= 5) ? &rtype : NULL, DUMP_BIN);
}

static int upd_load_txt(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	dump_mode_t mode;
	ARG_DUMP_TXT(mode);

	arg_dname_t origin;
	ARG_DNAME_TXT(argv[1], origin, NULL, "origin");

	rdb_txn_t txn;
	ARG_INST_TXT(argv[2], txn);

	uint32_t serial;
	ARG_NUM(argv[3], serial, "serial");

	arg_dname_t owner;
	if (argc > 4) {
		ARG_DNAME_TXT(argv[3], owner, &origin, "owner");
	}

	uint16_t rtype;
	if (argc > 5) {
		ARG_RTYPE_TXT(argv[4], rtype);
	}

	if (argc > 6) {
		return RedisModule_WrongArity(ctx);
	}

	return upd_load(ctx, &origin, &txn, serial,
	                (argc >= 5) ? &owner : NULL,
	                (argc >= 6) ? &rtype : NULL, mode);
}

static int upd_load_bin(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc < 3) {
		return RedisModule_WrongArity(ctx);
	}

	arg_dname_t origin;
	ARG_DNAME(argv[1], origin, "origin");

	rdb_txn_t txn;
	ARG_INST(argv[2], txn);

	uint32_t serial;
	ARG_NUM(argv[3], serial, "serial");

	arg_dname_t owner;
	if (argc > 4) {
		ARG_DNAME(argv[3], owner, "owner");
	}

	uint16_t rtype;
	if (argc > 5) {
		ARG_NUM(argv[4], rtype, "record type");
	}

	if (argc > 6) {
		return RedisModule_WrongArity(ctx);
	}

	return upd_load(ctx, &origin, &txn, serial,
	                (argc >= 5) ? &owner : NULL,
	                (argc >= 6) ? &rtype : NULL, DUMP_BIN);
}

#define LOAD_ERROR(ctx, msg) { \
	RedisModule_Log(ctx, REDISMODULE_LOGLEVEL_WARNING, "ERR " msg); \
	RedisModule_ReplyWithError(ctx, "ERR " msg); \
	return REDISMODULE_ERR; \
}

__attribute__((visibility("default")))
int RedisModule_OnLoad(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (RedisModule_Init(ctx, "knot", 1, REDISMODULE_APIVER_1) == REDISMODULE_ERR) {
		LOAD_ERROR(ctx, "module already loaded");
	}

	for (int i = 0; i < argc; i += 2) {
		long long num;
		size_t key_len;
		const char *key = RedisModule_StringPtrLen(argv[i], &key_len);
		if (i + 1 >= argc) {
			LOAD_ERROR(ctx, "missing configuration option value");
		}
		if (strcmp(key, RDB_PARAM_DFLT_TTL) == 0) {
			if (RedisModule_StringToLongLong(argv[i + 1], &num) == REDISMODULE_OK &&
			    num <= INT32_MAX) {
				rdb_default_ttl = num;
			} else {
				LOAD_ERROR(ctx, "invalid value of " RDB_PARAM_DFLT_TTL);
			}
		} else if (strcmp(key, RDB_PARAM_EVENT_AGE) == 0) {
			if (RedisModule_StringToLongLong(argv[i + 1], &num) == REDISMODULE_OK) {
				rdb_event_age = num;
			} else {
				LOAD_ERROR(ctx, "invalid value of " RDB_PARAM_EVENT_AGE);
			}
		} else {
			LOAD_ERROR(ctx, "unknown configuration option");
		}
	}

	rdb_rrset_t = RedisModule_CreateDataType(ctx, RRSET_NAME, RRSET_ENCODING_VERSION, &rrset_tm);
	if (rdb_rrset_t == NULL) {
		LOAD_ERROR(ctx, "failed to load type " RRSET_NAME);
	}

	rdb_diff_t = RedisModule_CreateDataType(ctx, DIFF_NAME, DIFF_ENCODING_VERSION, &diff_tm);
	if (rdb_diff_t == NULL) {
		LOAD_ERROR(ctx, "failed to load type " DIFF_NAME);
	}

	RedisModuleCommand *cmd = NULL;
	if (register_command_txt("KNOT.ZONE.BEGIN",    zone_begin_txt,    "write fast") ||
	    register_command_txt("KNOT.ZONE.STORE",    zone_store_txt,    "write fast") ||
	    register_command_txt("KNOT.ZONE.COMMIT",   zone_commit_txt,   "write")      ||
	    register_command_txt("KNOT.ZONE.ABORT",    zone_abort_txt,    "write")      ||
	    register_command_txt("KNOT.ZONE.LOAD",     zone_load_txt,     "readonly")   ||
	    register_command_txt("KNOT.ZONE.PURGE",    zone_purge_txt,    "write")      ||
	    register_command_txt("KNOT.ZONE.LIST",     zone_list_txt,     "readonly")   ||
	    register_command_txt("KNOT.UPD.BEGIN",     upd_begin_txt,     "write fast") ||
	    register_command_txt("KNOT.UPD.ADD",       upd_add_txt,       "write fast") ||
	    register_command_txt("KNOT.UPD.REMOVE",    upd_remove_txt,    "write fast") ||
	    register_command_txt("KNOT.UPD.COMMIT",    upd_commit_txt,    "write")      ||
	    register_command_txt("KNOT.UPD.ABORT",     upd_abort_txt,     "write")      ||
	    register_command_txt("KNOT.UPD.DIFF",      upd_diff_txt,      "readonly")   ||
	    register_command_txt("KNOT.UPD.LOAD",      upd_load_txt,      "readonly")   ||
	    register_command_bin(RDB_CMD_ZONE_EXISTS,  zone_exists_bin,   "readonly")   ||
	    register_command_bin(RDB_CMD_ZONE_BEGIN,   zone_begin_bin,    "write")      ||
	    register_command_bin(RDB_CMD_ZONE_STORE,   zone_store_bin,    "write")      ||
	    register_command_bin(RDB_CMD_ZONE_COMMIT,  zone_commit_bin,   "write")      ||
	    register_command_bin(RDB_CMD_ZONE_ABORT,   zone_abort_bin,    "write")      ||
	    register_command_bin(RDB_CMD_ZONE_LOAD,    zone_load_bin,     "readonly")   ||
	    register_command_bin(RDB_CMD_ZONE_PURGE,   zone_purge_bin,    "write")      ||
	    register_command_bin(RDB_CMD_ZONE_LIST,    zone_list_bin,     "readonly")   ||
	    register_command_bin(RDB_CMD_UPD_BEGIN,    upd_begin_bin,     "write")      ||
	    register_command_bin(RDB_CMD_UPD_ADD,      upd_add_bin,       "write")      ||
	    register_command_bin(RDB_CMD_UPD_REMOVE,   upd_remove_bin,    "write")      ||
	    register_command_bin(RDB_CMD_UPD_COMMIT,   upd_commit_bin,    "write")      ||
	    register_command_bin(RDB_CMD_UPD_ABORT,    upd_abort_bin,     "write")      ||
	    register_command_bin(RDB_CMD_UPD_DIFF,     upd_diff_bin,      "readonly")   ||
	    register_command_bin(RDB_CMD_UPD_LOAD,     upd_load_bin,      "readonly")   ||
	    register_command_bin("KNOT_BIN.AOF.RRSET", rrset_aof_rewrite, "write")      || // Add "internal" with newer Redis.
	    register_command_bin("KNOT_BIN.AOF.DIFF",  diff_aof_rewrite,  "write"))        // Add "internal" with newer Redis.
	{
		LOAD_ERROR(ctx, "failed to load commands");
	}

	RedisModule_Log(ctx, REDISMODULE_LOGLEVEL_NOTICE, "loaded with %s=%u %s=%u",
	                RDB_PARAM_DFLT_TTL, rdb_default_ttl, RDB_PARAM_EVENT_AGE, rdb_event_age);

	return REDISMODULE_OK;
}
