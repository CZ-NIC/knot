/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
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

	if (ctx->allow_addr.count > 0) {
		const struct sockaddr_storage *addr = knotd_qdata_remote_addr(qdata);
		if (!knotd_conf_addr_range_match(&ctx->allow_addr, addr)) {
			qdata->rcode = KNOT_RCODE_NOTAUTH;
			return KNOTD_STATE_FAIL;
		}
	}

	if (ctx->allow_iface.count > 0) {
		const struct sockaddr_storage *addr = knotd_qdata_local_addr(qdata);
		if (!knotd_conf_addr_range_match(&ctx->allow_iface, addr)) {
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
