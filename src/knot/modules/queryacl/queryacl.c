/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include "contrib/sockaddr.h"

#define MOD_ADDRESS	"\x07""address"
#define MOD_INTERFACE	"\x09""interface"

const yp_item_t queryacl_conf[] = {
	{ MOD_ADDRESS,   YP_TNET, YP_VNONE, YP_FMULTI },
	{ MOD_INTERFACE, YP_TNET, YP_VNONE, YP_FMULTI },
	{ NULL }
};

typedef struct {
	knotd_conf_t allow_addr;
	knotd_conf_t allow_iface;
} queryacl_ctx_t;

static knotd_state_t queryacl_process(knotd_state_t state, knot_pkt_t *pkt,
                                      knotd_qdata_t *qdata, knotd_mod_t *mod)
{
	assert(pkt && qdata && mod);

	queryacl_ctx_t *ctx = knotd_mod_ctx(mod);

	// Continue only for regular queries.
	if (qdata->type != KNOTD_QUERY_TYPE_NORMAL) {
		return state;
	}

	// Get interface address.
	struct sockaddr_storage iface;
	socklen_t iface_len = sizeof(iface);
	if (getsockname(qdata->params->socket, (struct sockaddr *)&iface, &iface_len) != 0) {
		knotd_mod_log(mod, LOG_ERR, "failed to get interface address");
		return KNOTD_STATE_FAIL;
	}

	if (ctx->allow_addr.count > 0) {
		if (!knotd_conf_addr_range_match(&ctx->allow_addr, qdata->params->remote)) {
			qdata->rcode = KNOT_RCODE_NOTAUTH;
			return KNOTD_STATE_FAIL;
		}
	}

	if (ctx->allow_iface.count > 0) {
		if (!knotd_conf_addr_range_match(&ctx->allow_iface, &iface)) {
			qdata->rcode = KNOT_RCODE_NOTAUTH;
			return KNOTD_STATE_FAIL;
		}
	}

	return state;
}

int queryacl_load(knotd_mod_t *mod)
{
	// Create module context.
	queryacl_ctx_t *ctx = calloc(1, sizeof(queryacl_ctx_t));
	if (ctx == NULL) {
		return KNOT_ENOMEM;
	}

	ctx->allow_addr = knotd_conf_mod(mod, MOD_ADDRESS);
	ctx->allow_iface = knotd_conf_mod(mod, MOD_INTERFACE);

	knotd_mod_ctx_set(mod, ctx);

	return knotd_mod_hook(mod, KNOTD_STAGE_BEGIN, queryacl_process);
}

void queryacl_unload(knotd_mod_t *mod)
{
	queryacl_ctx_t *ctx = knotd_mod_ctx(mod);
	if (ctx != NULL) {
		knotd_conf_free(&ctx->allow_addr);
		knotd_conf_free(&ctx->allow_iface);
	}
	free(ctx);
}

KNOTD_MOD_API(queryacl, KNOTD_MOD_FLAG_SCOPE_ANY,
              queryacl_load, queryacl_unload, queryacl_conf, NULL);
