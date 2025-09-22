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

static RedisModuleCommandArg instance_info_args[] = {
	{"zone",     REDISMODULE_ARG_TYPE_STRING,  -1, NULL, NULL, NULL, REDISMODULE_CMD_ARG_NONE},
	{"instance", REDISMODULE_ARG_TYPE_INTEGER, -1, NULL, NULL, NULL, REDISMODULE_CMD_ARG_NONE},
	{ 0 }
};

static RedisModuleCommandArg transaction_info_args[] = {
	{"zone",        REDISMODULE_ARG_TYPE_STRING,  -1, NULL, NULL, NULL, REDISMODULE_CMD_ARG_NONE},
	{"transaction", REDISMODULE_ARG_TYPE_INTEGER, -1, NULL, NULL, NULL, REDISMODULE_CMD_ARG_NONE},
	{ 0 }
};

static RedisModuleCommandArg store_txt_info_args[] = {
	{"zone",        REDISMODULE_ARG_TYPE_STRING,  -1, NULL, NULL, NULL, REDISMODULE_CMD_ARG_NONE},
	{"transaction", REDISMODULE_ARG_TYPE_INTEGER, -1, NULL, NULL, NULL, REDISMODULE_CMD_ARG_NONE},
	{"data",        REDISMODULE_ARG_TYPE_STRING,  -1, NULL, NULL, NULL, REDISMODULE_CMD_ARG_NONE},
	{ 0 }
};

static RedisModuleCommandArg upd_load_txt_info_args[] = {
	{"opt",      REDISMODULE_ARG_TYPE_PURE_TOKEN, -1, "--compact", NULL, NULL, REDISMODULE_CMD_ARG_OPTIONAL},
	{"zone",     REDISMODULE_ARG_TYPE_STRING,     -1, NULL,        NULL, NULL, REDISMODULE_CMD_ARG_NONE},
	{"instance", REDISMODULE_ARG_TYPE_INTEGER,    -1, NULL,        NULL, NULL, REDISMODULE_CMD_ARG_NONE},
	{"serial",   REDISMODULE_ARG_TYPE_INTEGER,    -1, NULL,        NULL, NULL, REDISMODULE_CMD_ARG_NONE},
	{"owner",    REDISMODULE_ARG_TYPE_STRING,     -1, NULL,        NULL, NULL, REDISMODULE_CMD_ARG_OPTIONAL},
	{"rtype",    REDISMODULE_ARG_TYPE_STRING,     -1, NULL,        NULL, NULL, REDISMODULE_CMD_ARG_OPTIONAL},
	{ 0 }
};

static RedisModuleCommandArg zone_load_txt_info_args[] = {
	{"opt",      REDISMODULE_ARG_TYPE_PURE_TOKEN, -1, "--compact", NULL, NULL, REDISMODULE_CMD_ARG_OPTIONAL},
	{"zone",     REDISMODULE_ARG_TYPE_STRING,     -1, NULL,        NULL, NULL, REDISMODULE_CMD_ARG_NONE},
	{"instance", REDISMODULE_ARG_TYPE_INTEGER,    -1, NULL,        NULL, NULL, REDISMODULE_CMD_ARG_NONE},
	{"owner",    REDISMODULE_ARG_TYPE_STRING,     -1, NULL,        NULL, NULL, REDISMODULE_CMD_ARG_OPTIONAL},
	{"rtype",    REDISMODULE_ARG_TYPE_STRING,     -1, NULL,        NULL, NULL, REDISMODULE_CMD_ARG_OPTIONAL},
	{ 0 }
};

static RedisModuleCommandArg zone_list_txt_info_args[] = {
	{"opt", REDISMODULE_ARG_TYPE_PURE_TOKEN, -1, "--instances", NULL, NULL, REDISMODULE_CMD_ARG_OPTIONAL},
	{ 0 }
};

static RedisModuleCommandArg zone_info_txt_info_args[] = {
	{"zone",     REDISMODULE_ARG_TYPE_STRING,     -1, NULL, NULL, NULL, REDISMODULE_CMD_ARG_OPTIONAL},
	{"instance", REDISMODULE_ARG_TYPE_INTEGER,    -1, NULL, NULL, NULL, REDISMODULE_CMD_ARG_OPTIONAL},
	{ 0 }
};

static const RedisModuleCommandInfo zone_begin_txt_info = {
	.version = REDISMODULE_COMMAND_INFO_VERSION,
	.summary = "Create a zone full transaction",
	.complexity = "O(1)",
	.since = "7.0.0",
	.arity = 3,
	.args = instance_info_args,
};

static const RedisModuleCommandInfo zone_store_txt_info = {
	.version = REDISMODULE_COMMAND_INFO_VERSION,
	.summary = "Store records in a zone full transaction",
	.complexity = "O(m), where m is the number of stored records",
	.since = "7.0.0",
	.arity = 4,
	.args = store_txt_info_args,
};

static const RedisModuleCommandInfo zone_commit_txt_info = {
	.version = REDISMODULE_COMMAND_INFO_VERSION,
	.summary = "Commit a zone full transaction",
	.complexity = "O(1)",
	.since = "7.0.0",
	.arity = 3,
	.args = transaction_info_args,
};

static const RedisModuleCommandInfo zone_abort_txt_info = {
	.version = REDISMODULE_COMMAND_INFO_VERSION,
	.summary = "Abort a zone full transaction",
	.complexity = "O(n), where n is the number of records in the transaction",
	.since = "7.0.0",
	.arity = 3,
	.args = transaction_info_args,
};

static const RedisModuleCommandInfo zone_load_txt_info = {
	.version = REDISMODULE_COMMAND_INFO_VERSION,
	.summary = "Load a zone instance or full transaction",
	.complexity = "O(n), where n is the number of records in the zone",
	.since = "7.0.0",
	.arity = -3,
	.args = zone_load_txt_info_args,
};

static const RedisModuleCommandInfo zone_purge_txt_info = {
	.version = REDISMODULE_COMMAND_INFO_VERSION,
	.summary = "Purge a zone instance",
	.complexity = "O(n), where n is the number of records in the zone and its updates",
	.since = "7.0.0",
	.arity = 3,
	.args = instance_info_args,
};

static const RedisModuleCommandInfo zone_list_txt_info = {
	.version = REDISMODULE_COMMAND_INFO_VERSION,
	.summary = "List zones stored in the database",
	.complexity = "O(z), where z is the number of zones",
	.since = "7.0.0",
	.arity = -1,
	.args = zone_list_txt_info_args,
};

static const RedisModuleCommandInfo zone_info_txt_info = {
	.version = REDISMODULE_COMMAND_INFO_VERSION,
	.summary = "List zones stored in the database showing serials and updates",
	.complexity = "O(z), where z is the number of zones",
	.since = "7.0.0",
	.arity = -1,
	.args = zone_info_txt_info_args,
};

static const RedisModuleCommandInfo upd_begin_txt_info = {
	.version = REDISMODULE_COMMAND_INFO_VERSION,
	.summary = "Create an zone update transaction",
	.complexity = "O(1)",
	.since = "7.0.0",
	.arity = 3,
	.args = instance_info_args,
};

static const RedisModuleCommandInfo upd_add_txt_info = {
	.version = REDISMODULE_COMMAND_INFO_VERSION,
	.summary = "Add records to a zone update transaction",
	.complexity = "O(m), where m is the number of added records",
	.since = "7.0.0",
	.arity = 4,
	.args = store_txt_info_args,
};

static const RedisModuleCommandInfo upd_remove_txt_info = {
	.version = REDISMODULE_COMMAND_INFO_VERSION,
	.summary = "Remove records from a zone update transaction",
	.complexity = "O(m), where m is the number of removed records",
	.since = "7.0.0",
	.arity = 4,
	.args = store_txt_info_args,
};

static const RedisModuleCommandInfo upd_commit_txt_info = {
	.version = REDISMODULE_COMMAND_INFO_VERSION,
	.summary = "Commit a zone update transaction to a zone",
	.complexity = "O(u), where u is the number of records in the update",
	.since = "7.0.0",
	.arity = 3,
	.args = transaction_info_args,
};

static const RedisModuleCommandInfo upd_abort_txt_info = {
	.version = REDISMODULE_COMMAND_INFO_VERSION,
	.summary = "Abort a zone update transaction",
	.complexity = "O(u), where u is the number of records in the update",
	.since = "7.0.0",
	.arity = 3,
	.args = transaction_info_args,
};

static const RedisModuleCommandInfo upd_diff_txt_info = {
	.version = REDISMODULE_COMMAND_INFO_VERSION,
	.summary = "Load the contents of a zone update transaction",
	.complexity = "O(u), where u is the number of records in the update",
	.since = "7.0.0",
	.arity = -3,
	.args = zone_load_txt_info_args,
};

static const RedisModuleCommandInfo upd_load_txt_info = {
	.version = REDISMODULE_COMMAND_INFO_VERSION,
	.summary = "Load zone updates since a specified serial",
	.complexity = "O(u), where u is the number of records in the retrieved updates",
	.since = "7.0.0",
	.arity = -4,
	.args = upd_load_txt_info_args,
};

static int zone_begin_txt(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	arg_dname_t origin;
	ARG_DNAME_TXT(argv[1], origin, NULL, "zone origin");

	rdb_txn_t txn;
	ARG_INST_TXT(argv[2], txn);

	zone_begin_txt_format(ctx, &origin, &txn);
	return REDISMODULE_OK;
}

static int zone_begin_bin(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 3) {
		return RedisModule_WrongArity(ctx);
	}

	arg_dname_t origin;
	ARG_DNAME(argv[1], origin, "zone origin");

	rdb_txn_t txn;
	ARG_INST(argv[2], txn);

	zone_begin_bin_format(ctx, &origin, &txn);
	return REDISMODULE_OK;
}

static int zone_store_txt(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	arg_dname_t origin;
	ARG_DNAME_TXT(argv[1], origin, NULL, "zone origin");

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
	ARG_DNAME(argv[1], origin, "zone origin");

	rdb_txn_t txn;
	ARG_TXN(argv[2], txn);

	arg_dname_t owner;
	ARG_DNAME(argv[3], owner, "record owner");

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
	ARG_DNAME_TXT(argv[1], origin, NULL, "zone origin");

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
	ARG_DNAME(argv[1], origin, "zone origin");

	rdb_txn_t txn;
	ARG_TXN(argv[2], txn);

	zone_commit(ctx, &origin, &txn);
	return REDISMODULE_OK;
}

static int zone_abort_txt(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	arg_dname_t origin;
	ARG_DNAME_TXT(argv[1], origin, NULL, "zone origin");

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
	ARG_DNAME(argv[1], origin, "zone origin");

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
	ARG_DNAME(argv[1], origin, "zone origin");

	rdb_txn_t txn;
	ARG_INST(argv[2], txn);

	zone_exists(ctx, &origin, &txn);
	return REDISMODULE_OK;
}

static int zone_load_txt(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	dump_mode_t mode;
	ARG_OPT_TXT(mode, "compact", DUMP_TXT, DUMP_COMPACT);

	arg_dname_t origin;
	ARG_DNAME_TXT(argv[1], origin, NULL, "zone origin");

	rdb_txn_t txn;
	ARG_INST_TXN_TXT(argv[2], txn);

	arg_dname_t owner;
	if (argc > 3) {
		ARG_DNAME_TXT(argv[3], owner, &origin, "record owner");
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
	ARG_DNAME(argv[1], origin, "zone origin");

	rdb_txn_t txn;
	ARG_INST_TXN(argv[2], txn);

	arg_dname_t owner;
	if (argc > 3) {
		ARG_DNAME(argv[3], owner, "record owner");
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
	ARG_DNAME_TXT(argv[1], origin, NULL, "zone origin");

	rdb_txn_t txn;
	ARG_INST_TXT(argv[2], txn);

	zone_purge_v(ctx, &origin, &txn);
	return REDISMODULE_OK;
}

static int zone_purge_bin(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 3) {
		return RedisModule_WrongArity(ctx);
	}

	arg_dname_t origin;
	ARG_DNAME(argv[1], origin, "zone origin");

	rdb_txn_t txn;
	ARG_INST(argv[2], txn);

	zone_purge_v(ctx, &origin, &txn);
	return REDISMODULE_OK;
}

static int zone_list_txt(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	bool instances;
	ARG_OPT_TXT(instances, "instances", false, true);

	zone_list(ctx, instances, true);
	return REDISMODULE_OK;
}

static int zone_list_bin(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 1) {
		return RedisModule_WrongArity(ctx);
	}

	zone_list(ctx, true, false);
	return REDISMODULE_OK;
}

static int zone_info_txt(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	arg_dname_t origin;
	if (argc >= 2) {
		ARG_DNAME_TXT(argv[1], origin, NULL, "zone origin");
	}

	rdb_txn_t txn;
	if (argc >= 3) {
		ARG_INST_TXT(argv[2], txn);
	}

	zone_info(ctx, (argc >= 2) ? &origin : NULL, (argc >= 3) ? &txn : NULL);
	return REDISMODULE_OK;
}

static int upd_begin_txt(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	arg_dname_t origin;
	ARG_DNAME_TXT(argv[1], origin, NULL, "zone origin");

	rdb_txn_t txn;
	ARG_INST_TXT(argv[2], txn);

	upd_begin_txt_format(ctx, &origin, &txn);
	return REDISMODULE_OK;
}

static int upd_begin_bin(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 3) {
		return RedisModule_WrongArity(ctx);
	}

	arg_dname_t origin;
	ARG_DNAME(argv[1], origin, "zone origin");

	rdb_txn_t txn;
	ARG_INST(argv[2], txn);

	upd_begin_bin_format(ctx, &origin, &txn);
	return REDISMODULE_OK;
}

static int upd_add_txt(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	arg_dname_t origin;
	ARG_DNAME_TXT(argv[1], origin, NULL, "zone origin");

	rdb_txn_t txn;
	ARG_TXN_TXT(argv[2], txn);

	void *zone_data;
	size_t data_len;
	ARG_DATA(argv[3], data_len, zone_data, "zone data");

	scanner_ctx_t s_ctx = {
		.ctx = ctx,
		.txn = &txn,
		.dflt_ttl = rdb_default_ttl,
		.mode = ADD
	};

	run_scanner(&s_ctx, &origin, zone_data, data_len);
	return REDISMODULE_OK;
}

static int upd_add_bin(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 8) {
		return RedisModule_WrongArity(ctx);
	}

	arg_dname_t origin;
	ARG_DNAME(argv[1], origin, "zone origin");

	rdb_txn_t txn;
	ARG_TXN(argv[2], txn);

	arg_dname_t owner;
	ARG_DNAME(argv[3], owner, "record owner");

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

	upd_add_bin_format(ctx, &origin, &txn, &owner, ttl, rtype, &rdataset);
	return REDISMODULE_OK;
}

static int upd_remove_txt(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	arg_dname_t origin;
	ARG_DNAME_TXT(argv[1], origin, NULL, "zone origin");

	rdb_txn_t txn;
	ARG_TXN_TXT(argv[2], txn);

	void *zone_data;
	size_t data_len;
	ARG_DATA(argv[3], data_len, zone_data, "zone data");

	scanner_ctx_t s_ctx = {
		.ctx = ctx,
		.txn = &txn,
		.dflt_ttl = TTL_EMPTY,
		.mode = REM
	};

	run_scanner(&s_ctx, &origin, zone_data, data_len);
	return REDISMODULE_OK;
}

static int upd_remove_bin(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 8) {
		return RedisModule_WrongArity(ctx);
	}

	arg_dname_t origin;
	ARG_DNAME(argv[1], origin, "zone origin");

	rdb_txn_t txn;
	ARG_TXN(argv[2], txn);

	arg_dname_t owner;
	ARG_DNAME(argv[3], owner, "record owner");

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

	upd_remove_bin_format(ctx, &origin, &txn, &owner, ttl, rtype, &rdataset);
	return REDISMODULE_OK;
}

static int upd_commit_txt(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	arg_dname_t origin;
	ARG_DNAME_TXT(argv[1], origin, NULL, "zone origin");

	rdb_txn_t txn;
	ARG_TXN_TXT(argv[2], txn);

	upd_commit(ctx, &origin, &txn);
	return REDISMODULE_OK;
}

static int upd_commit_bin(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 3) {
		return RedisModule_WrongArity(ctx);
	}

	arg_dname_t origin;
	ARG_DNAME(argv[1], origin, "zone origin");

	rdb_txn_t txn;
	ARG_TXN(argv[2], txn)

	upd_commit(ctx, &origin, &txn);
	return REDISMODULE_OK;
}

static int upd_abort_txt(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	arg_dname_t origin;
	ARG_DNAME_TXT(argv[1], origin, NULL, "zone origin");

	rdb_txn_t txn;
	ARG_TXN_TXT(argv[2], txn);

	upd_abort_v(ctx, &origin, &txn);
	return REDISMODULE_OK;
}

static int upd_abort_bin(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc != 3) {
		return RedisModule_WrongArity(ctx);
	}

	arg_dname_t origin;
	ARG_DNAME(argv[1], origin, "zone origin");

	rdb_txn_t txn;
	ARG_TXN(argv[2], txn)

	upd_abort_v(ctx, &origin, &txn);
	return REDISMODULE_OK;
}

static int upd_diff_txt(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	dump_mode_t mode;
	ARG_OPT_TXT(mode, "compact", DUMP_TXT, DUMP_COMPACT);

	arg_dname_t origin;
	ARG_DNAME_TXT(argv[1], origin, NULL, "zone origin");

	rdb_txn_t txn;
	ARG_TXN_TXT(argv[2], txn);

	arg_dname_t owner;
	if (argc > 3) {
		ARG_DNAME_TXT(argv[3], owner, &origin, "record owner");
	}

	uint16_t rtype;
	if (argc > 4) {
		ARG_RTYPE_TXT(argv[4], rtype);
	}

	if (argc > 5) {
		return RedisModule_WrongArity(ctx);
	}

	upd_diff(ctx, &origin, &txn, (argc >= 4) ? &owner : NULL,
	         (argc >= 5) ? &rtype : NULL, mode);
	return REDISMODULE_OK;
}

static int upd_diff_bin(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc < 3) {
		return RedisModule_WrongArity(ctx);
	}

	arg_dname_t origin;
	ARG_DNAME(argv[1], origin, "zone origin");

	rdb_txn_t txn;
	ARG_TXN(argv[2], txn);

	arg_dname_t owner;
	if (argc > 3) {
		ARG_DNAME(argv[3], owner, "record owner");
	}

	uint16_t rtype;
	if (argc > 4) {
		ARG_NUM(argv[4], rtype, "record type");
	}

	if (argc > 5) {
		return RedisModule_WrongArity(ctx);
	}

	upd_diff(ctx, &origin, &txn, (argc >= 4) ? &owner : NULL,
	         (argc >= 5) ? &rtype : NULL, DUMP_BIN);
	return REDISMODULE_OK;
}

static int upd_load_txt(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	dump_mode_t mode;
	ARG_OPT_TXT(mode, "compact", DUMP_TXT, DUMP_COMPACT);

	arg_dname_t origin;
	ARG_DNAME_TXT(argv[1], origin, NULL, "zone origin");

	rdb_txn_t txn;
	ARG_INST_TXT(argv[2], txn);

	uint32_t serial;
	ARG_NUM(argv[3], serial, "zone SOA serial");

	arg_dname_t owner;
	if (argc > 4) {
		ARG_DNAME_TXT(argv[3], owner, &origin, "record owner");
	}

	uint16_t rtype;
	if (argc > 5) {
		ARG_RTYPE_TXT(argv[4], rtype);
	}

	if (argc > 6) {
		return RedisModule_WrongArity(ctx);
	}

	upd_load(ctx, &origin, &txn, serial, (argc >= 5) ? &owner : NULL,
	         (argc >= 6) ? &rtype : NULL, mode);
	return REDISMODULE_OK;
}

static int upd_load_bin(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	if (argc < 3) {
		return RedisModule_WrongArity(ctx);
	}

	arg_dname_t origin;
	ARG_DNAME(argv[1], origin, "zone origin");

	rdb_txn_t txn;
	ARG_INST(argv[2], txn);

	uint32_t serial;
	ARG_NUM(argv[3], serial, "zone SOA serial");

	arg_dname_t owner;
	if (argc > 4) {
		ARG_DNAME(argv[3], owner, "record owner");
	}

	uint16_t rtype;
	if (argc > 5) {
		ARG_NUM(argv[4], rtype, "record type");
	}

	if (argc > 6) {
		return RedisModule_WrongArity(ctx);
	}

	upd_load(ctx, &origin, &txn, serial, (argc >= 5) ? &owner : NULL,
	         (argc >= 6) ? &rtype : NULL, DUMP_BIN);
	return REDISMODULE_OK;
}

#define LOAD_ERROR(ctx, msg) { \
	RedisModule_Log(ctx, REDISMODULE_LOGLEVEL_WARNING, RDB_E(msg)); \
	RedisModule_ReplyWithError(ctx, RDB_E(msg)); \
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
		} else if (strcmp(key, RDB_PARAM_UPD_DEPTH) == 0) {
			if (RedisModule_StringToLongLong(argv[i + 1], &num) == REDISMODULE_OK) {
				rdb_upd_history_len = num;
			} else {
				LOAD_ERROR(ctx, "invalid value of " RDB_PARAM_UPD_DEPTH);
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
	    register_command_txt("KNOT.ZONE.INFO",     zone_info_txt,     "readonly")   ||
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

	RedisModule_Log(ctx, REDISMODULE_LOGLEVEL_NOTICE, "%s loaded with %s=%u %s=%u %s=%u",
	                PACKAGE_VERSION,
	                RDB_PARAM_DFLT_TTL, rdb_default_ttl,
	                RDB_PARAM_EVENT_AGE, rdb_event_age,
	                RDB_PARAM_UPD_DEPTH, rdb_upd_history_len);

	return REDISMODULE_OK;
}
