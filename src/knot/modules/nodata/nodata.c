/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include "knot/include/module.h"
#include "contrib/wire_ctx.h"

#define MOD_TTL		"\x03""ttl"

const yp_item_t nodata_conf[] = {
	{ MOD_TTL, YP_TINT, YP_VINT = { 1, INT32_MAX, 30, YP_STIME } },
	{ NULL }
};

typedef struct {
	uint8_t data[48];
	uint8_t data_len;
	uint32_t ttl;
} nodata_ctx_t;

static knotd_state_t treat_refused(knotd_state_t state, knot_pkt_t *pkt,
                                   knotd_qdata_t *qdata, knotd_mod_t *mod)
{
	assert(pkt && qdata && mod);

	nodata_ctx_t *ctx = knotd_mod_ctx(mod);

	if (qdata->rcode != KNOT_RCODE_REFUSED) {
		return state;
	}

	if (knot_pkt_qtype(pkt) == KNOT_RRTYPE_SOA) {
		(void)knot_pkt_begin(pkt, KNOT_ANSWER);
		knotd_mod_stats_incr(mod, qdata->params->thread_id, 0, 0, 1);
	} else {
		(void)knot_pkt_begin(pkt, KNOT_AUTHORITY);
		knotd_mod_stats_incr(mod, qdata->params->thread_id, 1, 0, 1);
	}

	knot_rrset_t soa;
	knot_rrset_init(&soa, (knot_dname_t *)knot_pkt_qname(pkt),
	                KNOT_RRTYPE_SOA, KNOT_CLASS_IN, ctx->ttl);
	knot_rrset_add_rdata(&soa, ctx->data, ctx->data_len, NULL);

	if (knot_pkt_put(pkt, KNOT_COMPR_HINT_QNAME, &soa, KNOT_PF_NULL) != KNOT_EOK) {
		return KNOTD_STATE_FAIL;
	}

	knot_rdataset_clear(&soa.rrs, NULL);

	qdata->rcode = KNOT_RCODE_NOERROR;
	qdata->rcode_ede = KNOT_EDNS_EDE_NONE;

	return KNOTD_STATE_DONE;
}

int nodata_load(knotd_mod_t *mod)
{
	nodata_ctx_t *ctx = calloc(1, sizeof(nodata_ctx_t));
	if (ctx == NULL) {
		return KNOT_ENOMEM;
	}

	knotd_conf_t val = knotd_conf_mod(mod, MOD_TTL);
	ctx->ttl = val.single.integer;

	uint8_t invalid[9] = "\x07""invalid";
	wire_ctx_t wire = wire_ctx_init(ctx->data, sizeof(ctx->data));
	wire_ctx_write(&wire, invalid, sizeof(invalid));
	wire_ctx_write(&wire, invalid, sizeof(invalid));
	wire_ctx_write_u32(&wire, 1);
	wire_ctx_write_u32(&wire, ctx->ttl);
	wire_ctx_write_u32(&wire, ctx->ttl);
	wire_ctx_write_u32(&wire, ctx->ttl);
	wire_ctx_write_u32(&wire, ctx->ttl);
	assert(wire.error == KNOT_EOK);
	ctx->data_len = wire_ctx_offset(&wire);

	int ret = knotd_mod_stats_add(mod, "answer", 1, NULL);
	if (ret != KNOT_EOK) {
		free(ctx);
		return ret;
	}
	ret = knotd_mod_stats_add(mod, "authority", 1, NULL);
	if (ret != KNOT_EOK) {
		free(ctx);
		return ret;
	}

	knotd_mod_ctx_set(mod, ctx);

	return knotd_mod_hook(mod, KNOTD_STAGE_ERROR, treat_refused);
}

void nodata_unload(knotd_mod_t *mod)
{
	nodata_ctx_t *ctx = knotd_mod_ctx(mod);
	free(ctx);
}

KNOTD_MOD_API(nodata, KNOTD_MOD_FLAG_SCOPE_GLOBAL | KNOTD_MOD_FLAG_OPT_CONF,
              nodata_load, nodata_unload, nodata_conf, NULL);
