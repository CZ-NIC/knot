/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

const yp_item_t noudp_conf[] = {
	{ MOD_UDP_ALLOW_RATE, YP_TINT, YP_VINT = { 0, UINT32_MAX, 0, YP_SNONE }, YP_FMULTI },
	{ NULL }
};

typedef struct {
	uint32_t udp_allow_rate;
} noudp_ctx_t;

static bool is_udp(knotd_qdata_t *qdata)
{
	return qdata->params->flags & KNOTD_QUERY_FLAG_LIMIT_SIZE;
}

static knotd_state_t noudp_begin(knotd_state_t state, knot_pkt_t *pkt,
                                 knotd_qdata_t *qdata, knotd_mod_t *mod)
{
	noudp_ctx_t *a = knotd_mod_ctx(mod);
	if (is_udp(qdata)) {
		knot_wire_set_tc(pkt->wire);
		return KNOTD_STATE_DONE;
	}

	return state;
}

int noudp_load(knotd_mod_t *mod)
{
	noudp_ctx_t *ctx = calloc(1, sizeof(noudp_ctx_t));
    if (ctx == NULL) {
		return KNOT_ENOMEM;
	}

	knotd_conf_t conf = knotd_conf_mod(mod, MOD_UDP_ALLOW_RATE);
    ctx->udp_allow_rate = conf.single.integer;

	knotd_mod_ctx_set(mod, ctx);

	return knotd_mod_hook(mod, KNOTD_STAGE_BEGIN, noudp_begin);
}

void noudp_unload(knotd_mod_t *mod)
{
	noudp_ctx_t *ctx = knotd_mod_ctx(mod);
	free(ctx);
}


KNOTD_MOD_API(noudp, KNOTD_MOD_FLAG_SCOPE_ANY | KNOTD_MOD_FLAG_OPT_CONF,
              noudp_load, noudp_unload, noudp_conf, NULL);
