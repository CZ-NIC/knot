/*  Copyright (C) 2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#define MOD_UDP_ALLOW_RATE	"\x0e""udp-allow-rate"
#define MOD_UDP_TRUNC_RATE	"\x11""udp-truncate-rate"

const yp_item_t noudp_conf[] = {
	{ MOD_UDP_ALLOW_RATE, YP_TINT, YP_VINT = { 0, UINT32_MAX, 0 } },
	{ MOD_UDP_TRUNC_RATE, YP_TINT, YP_VINT = { 1, UINT32_MAX, 0 } },
	{ NULL }
};

int noudp_conf_check(knotd_conf_check_args_t *args)
{
	knotd_conf_t allow = knotd_conf_check_item(args, MOD_UDP_ALLOW_RATE);
	knotd_conf_t trunc = knotd_conf_check_item(args, MOD_UDP_TRUNC_RATE);
	if (allow.count == 1 && trunc.count == 1) {
		args->err_str = "udp-allow-rate and udp-truncate-rate cannot be specified together";
		return KNOT_EINVAL;
	}
	return KNOT_EOK;
}

typedef struct {
	uint32_t rate;
	uint32_t *counters;
	bool trunc_mode;
} noudp_ctx_t;

static knotd_state_t noudp_begin(knotd_state_t state, knot_pkt_t *pkt,
                                 knotd_qdata_t *qdata, knotd_mod_t *mod)
{
	if (qdata->params->proto != KNOTD_QUERY_PROTO_UDP) {
		return state;
	}

	bool truncate = true;

	noudp_ctx_t *ctx = knotd_mod_ctx(mod);
	if (ctx->rate > 0) {
		bool apply = false;
		if (++ctx->counters[qdata->params->thread_id] >= ctx->rate) {
			ctx->counters[qdata->params->thread_id] = 0;
			apply = true;
		}
		truncate = (apply == ctx->trunc_mode);
	}

	if (truncate) {
		knot_wire_set_tc(pkt->wire);
		return KNOTD_STATE_DONE;
	} else {
		return state;
	}
}

int noudp_load(knotd_mod_t *mod)
{
	noudp_ctx_t *ctx = calloc(1, sizeof(noudp_ctx_t));
	if (ctx == NULL) {
		return KNOT_ENOMEM;
	}

	knotd_conf_t allow = knotd_conf_mod(mod, MOD_UDP_ALLOW_RATE);
	knotd_conf_t trunc = knotd_conf_mod(mod, MOD_UDP_TRUNC_RATE);

	if (allow.count == 1) {
		ctx->rate = allow.single.integer;
	} else if (trunc.count == 1) {
		ctx->rate = trunc.single.integer;
		ctx->trunc_mode = true;
	}

	if (ctx->rate > 0) {
		ctx->counters = calloc(knotd_mod_threads(mod), sizeof(uint32_t));
		if (ctx->counters == NULL) {
			free(ctx);
			return KNOT_ENOMEM;
		}
	}

	knotd_mod_ctx_set(mod, ctx);

	return knotd_mod_hook(mod, KNOTD_STAGE_BEGIN, noudp_begin);
}

void noudp_unload(knotd_mod_t *mod)
{
	noudp_ctx_t *ctx = knotd_mod_ctx(mod);
	free(ctx->counters);
	free(ctx);
}

KNOTD_MOD_API(noudp, KNOTD_MOD_FLAG_SCOPE_ANY | KNOTD_MOD_FLAG_OPT_CONF,
              noudp_load, noudp_unload, noudp_conf, noudp_conf_check);
