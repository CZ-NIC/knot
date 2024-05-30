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
#define MOD_TIME_LIMIT		"\x0A""time-limit"
#define MOD_INSTANT_LIMIT	"\x0D""instant-limit"
#define MOD_SLIP		"\x04""slip"
#define MOD_TBL_SIZE		"\x0A""table-size"
#define MOD_WHITELIST		"\x09""whitelist"
#define MOD_LOG_PERIOD		"\x0A""log-period"
#define MOD_DRY_RUN		"\x07""dry-run"

const yp_item_t rrl_conf[] = {
	{ MOD_INSTANT_LIMIT, YP_TINT, YP_VINT = { 1, 1000000, 5000 } },
	{ MOD_TIME_LIMIT,    YP_TINT, YP_VINT = { 1, 1000000, 4000 } },
	{ MOD_RATE_LIMIT,    YP_TINT, YP_VINT = { 1, INT32_MAX, 100 } },
	{ MOD_SLIP,          YP_TINT, YP_VINT = { 0, 100, 1 } },
	{ MOD_TBL_SIZE,      YP_TINT, YP_VINT = { 1, INT32_MAX, 524288 } },
	{ MOD_WHITELIST,     YP_TNET, YP_VNONE, YP_FMULTI },
	{ MOD_LOG_PERIOD,    YP_TINT, YP_VINT = { 0, INT32_MAX, 0 } },
	{ MOD_DRY_RUN,       YP_TBOOL, YP_VNONE },
	{ NULL }
};

int rrl_conf_check(knotd_conf_check_args_t *args)
{
	knotd_conf_t time_limit = knotd_conf_check_item(args, MOD_TIME_LIMIT);
	knotd_conf_t instant_limit = knotd_conf_check_item(args, MOD_INSTANT_LIMIT);
	if (time_limit.single.integer > 1000ll * instant_limit.single.integer) {
		args->err_str = "time limit per millisecond is higher than instant limit";
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

typedef struct {
	rrl_table_t *time_table;
	rrl_table_t *udp_table;
	struct timespec *start_time;
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

	// Exempt clients.
	if (knotd_conf_addr_range_match(&ctx->whitelist, params->remote)) {
		ctx->start_time[params->thread_id].tv_sec = 0;
		return state;
	}

	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ctx->start_time[params->thread_id]);

	if (params->proto == KNOTD_QUERY_PROTO_UDP) {
		return state; // UDP classification is later (after mod-cookies processing).
	}

	if (rrl_query(ctx->time_table, params->remote, mod) == KNOT_EOK) {
		// Rate limiting not applied.
		return state;
	}

	//knotd_mod_stats_incr(mod, params->thread_id, 1, 0, 1); // TODO
	return ctx->dry_run ? state : KNOTD_PROTO_STATE_BLOCK;
}

static knotd_proto_state_t protolimit_end(knotd_proto_state_t state,
                                          knotd_qdata_params_t *params,
                                          knotd_mod_t *mod)
{
	rrl_ctx_t *ctx = knotd_mod_ctx(mod);

	if (ctx->start_time[params->thread_id].tv_sec == 0) {
		return state;
	}

	struct timespec end_time;
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &end_time);
	uint64_t diff = time_diff_us(&ctx->start_time[params->thread_id], &end_time);

	if (params->proto == KNOTD_QUERY_PROTO_UDP &&
	    (params->flags & KNOTD_QUERY_FLAG_COOKIE) == 0) {
		rrl_update(ctx->udp_table, params->remote, diff);
	} else {
		rrl_update(ctx->time_table, params->remote, diff);
	}

	return state;
}

static knotd_state_t ratelimit_apply(knotd_state_t state, knot_pkt_t *pkt,
                                     knotd_qdata_t *qdata, knotd_mod_t *mod)
{
	assert(pkt && qdata && mod);

	rrl_ctx_t *ctx = knotd_mod_ctx(mod);

	if (ctx->start_time[qdata->params->thread_id].tv_sec == 0) {
		return state;
	}

	// Don't limit authorized operations.
	if (qdata->params->flags & KNOTD_QUERY_FLAG_AUTHORIZED) {
		ctx->start_time[qdata->params->thread_id].tv_sec = 0;
		return state;
	}

	// Rate limit is applied to pure UDP only.
	if (qdata->params->proto != KNOTD_QUERY_PROTO_UDP) {
		return state;
	}

	// Rate limit is not applied to responses with a valid cookie.
	if (qdata->params->flags & KNOTD_QUERY_FLAG_COOKIE) {
		return state;
	}

	if (rrl_query(ctx->udp_table, qdata->params->remote, mod) == KNOT_EOK) {
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

	rrl_destroy(ctx->time_table);
	rrl_destroy(ctx->udp_table);
	free(ctx);
}

int rrl_load(knotd_mod_t *mod)
{
	rrl_ctx_t *ctx = calloc(1, sizeof(rrl_ctx_t));
	if (ctx == NULL) {
		return KNOT_ENOMEM;
	}
	ctx->start_time = calloc(knotd_mod_threads(mod), sizeof(*ctx->start_time));
	if (ctx->start_time == NULL) {
		free(ctx);
		return KNOT_ENOMEM;
	}

	uint32_t instant_limit = knotd_conf_mod(mod, MOD_INSTANT_LIMIT).single.integer;
	uint32_t time_limit = knotd_conf_mod(mod, MOD_TIME_LIMIT).single.integer;
	uint32_t rate_limit = knotd_conf_mod(mod, MOD_RATE_LIMIT).single.integer;
	size_t size = knotd_conf_mod(mod, MOD_TBL_SIZE).single.integer;
	uint32_t log_period = knotd_conf_mod(mod, MOD_LOG_PERIOD).single.integer;
	ctx->time_table = rrl_create(size, instant_limit, time_limit, 0, log_period);
	ctx->udp_table = rrl_create(size, instant_limit, time_limit, rate_limit, log_period);
	if (ctx->time_table == NULL || ctx->udp_table == NULL) {
		ctx_free(ctx);
		return KNOT_ENOMEM;
	}

	ctx->slip = knotd_conf_mod(mod, MOD_SLIP).single.integer;
	ctx->dry_run = knotd_conf_mod(mod, MOD_DRY_RUN).single.boolean;
	ctx->whitelist = knotd_conf_mod(mod, MOD_WHITELIST);

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

	/* The explicit reference of the AVX2 variant ensures the optimized
	 * code isn't removed by linker if linking statically.
	 * Check: nm ./src/.libs/knotd | grep KRU_
	 * https://stackoverflow.com/a/28663156/587396
	 */
	knotd_mod_log(mod, LOG_DEBUG, "using %s implementation",
	              KRU.limited == KRU_AVX2.limited ? "optimized" : "generic");

	knotd_mod_ctx_set(mod, ctx);

	knotd_mod_proto_hook(mod, KNOTD_STAGE_PROTO_BEGIN, protolimit_start);
	knotd_mod_proto_hook(mod, KNOTD_STAGE_PROTO_END, protolimit_end);

	return knotd_mod_hook(mod, KNOTD_STAGE_BEGIN, ratelimit_apply);
}

void rrl_unload(knotd_mod_t *mod)
{
	rrl_ctx_t *ctx = knotd_mod_ctx(mod);

	knotd_conf_free(&ctx->whitelist);
	free(ctx->start_time);
	ctx_free(ctx);
}

KNOTD_MOD_API(rrl, KNOTD_MOD_FLAG_SCOPE_ANY | KNOTD_MOD_FLAG_OPT_CONF,
              rrl_load, rrl_unload, rrl_conf, rrl_conf_check);
