/*  Copyright (C) 2024 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "contrib/time.h"
#include "knot/include/module.h"
#include "knot/modules/rrl/functions.h"
#include "knot/modules/rrl/kru.h"

#define MOD_RATE_LIMIT		"\x0A""rate-limit"
#define MOD_INST_LIMIT		"\x0D""instant-limit"
#define MOD_T_RATE_LIMIT	"\x0F""time-rate-limit"
#define MOD_T_INST_LIMIT	"\x12""time-instant-limit"
#define MOD_SLIP		"\x04""slip"
#define MOD_TBL_SIZE		"\x0A""table-size"
#define MOD_WHITELIST		"\x09""whitelist"
#define MOD_LOG_PERIOD		"\x0A""log-period"
#define MOD_DRY_RUN		"\x07""dry-run"

const yp_item_t rrl_conf[] = {
	{ MOD_INST_LIMIT,    YP_TINT, YP_VINT = { 1,  (1ll << 32) / 768 - 1, 50 } },
	{ MOD_RATE_LIMIT,    YP_TINT, YP_VINT = { 0, ((1ll << 32) / 768 - 1) * 1000, 20 } },
	{ MOD_T_INST_LIMIT,  YP_TINT, YP_VINT = { 1, 1000000, 5000 } },
	{ MOD_T_RATE_LIMIT,  YP_TINT, YP_VINT = { 0, 1000000000, 4000 } },
	{ MOD_SLIP,          YP_TINT, YP_VINT = { 0, 100, 1 } },
	{ MOD_TBL_SIZE,      YP_TINT, YP_VINT = { 1, INT32_MAX, 524288 } },
	{ MOD_WHITELIST,     YP_TNET, YP_VNONE, YP_FMULTI },
	{ MOD_LOG_PERIOD,    YP_TINT, YP_VINT = { 0, INT32_MAX, 0 } },
	{ MOD_DRY_RUN,       YP_TBOOL, YP_VNONE },
	{ NULL }
};

int rrl_conf_check(knotd_conf_check_args_t *args)
{
	knotd_conf_t rate_limit = knotd_conf_check_item(args, MOD_RATE_LIMIT);
	knotd_conf_t inst_limit = knotd_conf_check_item(args, MOD_INST_LIMIT);
	if (rate_limit.single.integer > 1000ll * inst_limit.single.integer) {
		args->err_str = "rate limit is higher than 1000 times instant rate limit";
		return KNOT_EINVAL;
	}

	knotd_conf_t t_rate_limit = knotd_conf_check_item(args, MOD_T_RATE_LIMIT);
	knotd_conf_t t_inst_limit = knotd_conf_check_item(args, MOD_T_INST_LIMIT);
	if (t_rate_limit.single.integer > 1000ll * t_inst_limit.single.integer) {
		args->err_str = "time rate limit is higher than 1000 times time instant limit";
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

typedef struct {
	ALIGNED_CPU_CACHE // Ensures that one thread context occupies one cache line.
	struct timespec start_time; // Start time of the measurement.
	bool whitelist_checked; // Indication whether whitelist check took place.
	bool skip; // Skip the rest of the module callbacks.
} thrd_ctx_t;

typedef struct {
	rrl_table_t *rate_table;
	rrl_table_t *time_table;
	thrd_ctx_t *thrd_ctx;
	int slip;
	bool dry_run;
	knotd_conf_t whitelist;
} rrl_ctx_t;

static uint32_t time_diff_us(const struct timespec *begin, const struct timespec *end)
{
	struct timespec result = time_diff(begin, end);
	return (result.tv_sec * 1000000) + (result.tv_nsec / 1000);
}

static knotd_proto_state_t protolimit_start(knotd_proto_state_t state,
                                            knotd_qdata_params_t *params,
                                            knotd_mod_t *mod)
{
	rrl_ctx_t *ctx = knotd_mod_ctx(mod);
	thrd_ctx_t *thrd = &ctx->thrd_ctx[params->thread_id];
	thrd->skip = false;

	// Check if a whitelisted client.
	thrd->whitelist_checked = true;
	if (knotd_conf_addr_range_match(&ctx->whitelist, params->remote)) {
		thrd->skip = true;
		return state;
	}

	// UDP time limiting not implemented (source address can be forged).
	if (params->proto == KNOTD_QUERY_PROTO_UDP) {
		return state;
	}

	// Check if the packet is limited.
	if (rrl_query(ctx->time_table, params->remote, mod) != KNOT_EOK) {
		thrd->skip = true;
		knotd_mod_stats_incr(mod, params->thread_id, 2, 0, 1);
		return ctx->dry_run ? state : KNOTD_PROTO_STATE_BLOCK;
	} else {
		clock_gettime(CLOCK_THREAD_CPUTIME_ID, &thrd->start_time);
		return state; // Not limited.
	}
}

static knotd_proto_state_t protolimit_end(knotd_proto_state_t state,
                                          knotd_qdata_params_t *params,
                                          knotd_mod_t *mod)
{
	rrl_ctx_t *ctx = knotd_mod_ctx(mod);
	thrd_ctx_t *thrd = &ctx->thrd_ctx[params->thread_id];

	if (thrd->skip || params->proto == KNOTD_QUERY_PROTO_UDP) {
		return state;
	}

	// Update the time table.
	struct timespec end_time;
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &end_time);
	uint64_t diff = time_diff_us(&thrd->start_time, &end_time);
	if (diff > 0) { // Zero KRU update is NOOP.
		rrl_update(ctx->time_table, params->remote, diff);
	}

	return state;
}

static knotd_state_t ratelimit_apply(knotd_state_t state, knot_pkt_t *pkt,
                                     knotd_qdata_t *qdata, knotd_mod_t *mod)
{
	assert(pkt && qdata && mod);

	rrl_ctx_t *ctx = knotd_mod_ctx(mod);
	thrd_ctx_t *thrd = &ctx->thrd_ctx[qdata->params->thread_id];

	if (thrd->skip) {
		return state;
	}

	// Don't limit authorized operations.
	if (qdata->params->flags & KNOTD_QUERY_FLAG_AUTHORIZED) {
		thrd->skip = true;
		return state;
	}

	// Rate limit is applied to UDP only.
	if (qdata->params->proto != KNOTD_QUERY_PROTO_UDP) {
		return state;
	}

	// Check for whitelisted client IF PER-ZONE module (no proto callbacks).
	if (!thrd->whitelist_checked &&
	    knotd_conf_addr_range_match(&ctx->whitelist, qdata->params->remote)) {
		thrd->skip = true;
		return state;
	}

	// Rate limit is not applied to responses with a valid cookie.
	if (qdata->params->flags & KNOTD_QUERY_FLAG_COOKIE) {
		return state;
	}

	if (rrl_query(ctx->rate_table, knotd_qdata_remote_addr(qdata), mod) == KNOT_EOK) {
		// Rate limiting not applied.
		return state;
	}

	if (rrl_slip_roll(ctx->slip)) {
		// Slip the answer.
		knotd_mod_stats_incr(mod, qdata->params->thread_id, 0, 0, 1);
		qdata->err_truncated = true;
		return ctx->dry_run ? state : KNOTD_STATE_FAIL;
	} else {
		// Drop the answer.
		knotd_mod_stats_incr(mod, qdata->params->thread_id, 1, 0, 1);
		return ctx->dry_run ? state : KNOTD_STATE_NOOP;
	}
}

static void ctx_free(rrl_ctx_t *ctx)
{
	assert(ctx);

	free(ctx->thrd_ctx);
	rrl_destroy(ctx->rate_table);
	rrl_destroy(ctx->time_table);
	knotd_conf_free(&ctx->whitelist);
	free(ctx);
}

int rrl_load(knotd_mod_t *mod)
{
	rrl_ctx_t *ctx = calloc(1, sizeof(rrl_ctx_t));
	if (ctx == NULL) {
		return KNOT_ENOMEM;
	}

	ctx->dry_run = knotd_conf_mod(mod, MOD_DRY_RUN).single.boolean;
	ctx->whitelist = knotd_conf_mod(mod, MOD_WHITELIST);

	ctx->thrd_ctx = calloc(knotd_mod_threads(mod), sizeof(*ctx->thrd_ctx));
	if (ctx->thrd_ctx == NULL) {
		ctx_free(ctx);
		return KNOT_ENOMEM;
	}

	size_t size = knotd_conf_mod(mod, MOD_TBL_SIZE).single.integer;
	uint32_t log_period = knotd_conf_mod(mod, MOD_LOG_PERIOD).single.integer;

	uint32_t rate_limit = knotd_conf_mod(mod, MOD_RATE_LIMIT).single.integer;
	if (rate_limit > 0) {
		uint32_t inst_limit = knotd_conf_mod(mod, MOD_INST_LIMIT).single.integer;
		ctx->rate_table = rrl_create(size, inst_limit, rate_limit, true, log_period);
		if (ctx->rate_table == NULL) {
			ctx_free(ctx);
			return KNOT_ENOMEM;
		}
		ctx->slip = knotd_conf_mod(mod, MOD_SLIP).single.integer;
	}

	uint32_t time_limit = knotd_conf_mod(mod, MOD_T_RATE_LIMIT).single.integer;
	if (time_limit > 0) {
		uint32_t inst_limit = knotd_conf_mod(mod, MOD_T_INST_LIMIT).single.integer;
		ctx->time_table = rrl_create(size, inst_limit, time_limit, false, log_period);
		if (ctx->time_table == NULL) {
			ctx_free(ctx);
			return KNOT_ENOMEM;
		}
	}

	int ret = knotd_mod_stats_add(mod, "slipped", 1, NULL);
	if (ret != KNOT_EOK) {
		ctx_free(ctx);
		return ret;
	}
	ret = knotd_mod_stats_add(mod, "dropped", 1, NULL);
	if (ret != KNOT_EOK) {
		ctx_free(ctx);
		return ret;
	}
	ret = knotd_mod_stats_add(mod, "dropped-time", 1, NULL);
	if (ret != KNOT_EOK) {
		ctx_free(ctx);
		return ret;
	}

	/* The explicit reference of the AVX2 variant ensures the optimized
	 * code isn't removed by linker if linking statically.
	 * Check: nm ./src/.libs/knotd | grep KRU_
	 * https://stackoverflow.com/a/28663156/587396
	 */
	knotd_mod_log(mod, LOG_DEBUG, "using %s implementation",
	              KRU.limited == KRU_AVX2.limited ? "optimized" : "generic");

	knotd_mod_ctx_set(mod, ctx);

	if (rate_limit > 0) {
		knotd_mod_hook(mod, KNOTD_STAGE_BEGIN, ratelimit_apply);
	}

	if (time_limit > 0) {
		// Note that these two callbacks aren't executed IF PER-ZONE module!
		knotd_mod_proto_hook(mod, KNOTD_STAGE_PROTO_BEGIN, protolimit_start);
		knotd_mod_proto_hook(mod, KNOTD_STAGE_PROTO_END, protolimit_end);
	}

	return KNOT_EOK;
}

void rrl_unload(knotd_mod_t *mod)
{
	ctx_free(knotd_mod_ctx(mod));
}

KNOTD_MOD_API(rrl, KNOTD_MOD_FLAG_SCOPE_ANY | KNOTD_MOD_FLAG_OPT_CONF,
              rrl_load, rrl_unload, rrl_conf, rrl_conf_check);
