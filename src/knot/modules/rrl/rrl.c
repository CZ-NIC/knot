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

#include "knot/include/module.h"
#include "knot/modules/rrl/functions.h"
#include "knot/modules/rrl/kru.h"

#define MOD_RATE_LIMIT		"\x0A""rate-limit"
#define MOD_INSTANT_LIMIT	"\x0D""instant-limit"
#define MOD_SLIP		"\x04""slip"
#define MOD_TBL_SIZE		"\x0A""table-size"
#define MOD_WHITELIST		"\x09""whitelist"
#define MOD_LOG_PERIOD		"\x0A""log-period"
#define MOD_DRY_RUN		"\x07""dry-run"

const yp_item_t rrl_conf[] = {
	{ MOD_INSTANT_LIMIT, YP_TINT, YP_VINT = { 1,  (1ll << 32) / 768 - 1, 50 } },
	{ MOD_RATE_LIMIT,    YP_TINT, YP_VINT = { 1, ((1ll << 32) / 768 - 1) * 1000 } },
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
	knotd_conf_t instant_limit = knotd_conf_check_item(args, MOD_INSTANT_LIMIT);
	if (rate_limit.count == 0) {
		args->err_str = "no rate limit specified";
		return KNOT_EINVAL;
	}
	if (rate_limit.single.integer > 1000ll * instant_limit.single.integer) {
		args->err_str = "rate limit per millisecond is higher than instant limit";
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

typedef struct {
	rrl_table_t *rrl;
	int slip;
	bool dry_run;
	knotd_conf_t whitelist;
} rrl_ctx_t;

static knotd_state_t ratelimit_apply(knotd_state_t state, knot_pkt_t *pkt,
                                     knotd_qdata_t *qdata, knotd_mod_t *mod)
{
	assert(pkt && qdata && mod);

	rrl_ctx_t *ctx = knotd_mod_ctx(mod);

	// Rate limit is applied to pure UDP only.
	if (qdata->params->proto != KNOTD_QUERY_PROTO_UDP) {
		return state;
	}

	// Rate limit is not applied to responses with a valid cookie.
	if (qdata->params->flags & KNOTD_QUERY_FLAG_COOKIE) {
		return state;
	}

	// Exempt clients.
	if (knotd_conf_addr_range_match(&ctx->whitelist, knotd_qdata_remote_addr(qdata))) {
		return state;
	}

	if (rrl_query(ctx->rrl, knotd_qdata_remote_addr(qdata), mod) == KNOT_EOK) {
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

	rrl_destroy(ctx->rrl);
	free(ctx);
}

int rrl_load(knotd_mod_t *mod)
{
	rrl_ctx_t *ctx = calloc(1, sizeof(rrl_ctx_t));
	if (ctx == NULL) {
		return KNOT_ENOMEM;
	}

	uint32_t instant_limit = knotd_conf_mod(mod, MOD_INSTANT_LIMIT).single.integer;
	uint32_t rate_limit = knotd_conf_mod(mod, MOD_RATE_LIMIT).single.integer;
	size_t size = knotd_conf_mod(mod, MOD_TBL_SIZE).single.integer;
	uint32_t log_period = knotd_conf_mod(mod, MOD_LOG_PERIOD).single.integer;
	ctx->rrl = rrl_create(size, instant_limit, rate_limit, true, log_period);
	if (ctx->rrl == NULL) {
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

	return knotd_mod_hook(mod, KNOTD_STAGE_BEGIN, ratelimit_apply);
}

void rrl_unload(knotd_mod_t *mod)
{
	rrl_ctx_t *ctx = knotd_mod_ctx(mod);

	knotd_conf_free(&ctx->whitelist);
	ctx_free(ctx);
}

KNOTD_MOD_API(rrl, KNOTD_MOD_FLAG_SCOPE_ANY,
              rrl_load, rrl_unload, rrl_conf, rrl_conf_check);
