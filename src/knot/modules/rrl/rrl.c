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
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "contrib/sockaddr.h"
#include "knot/include/module.h"
#include "knot/nameserver/process_query.h" // Dependency on qdata->extra!
#include "knot/modules/rrl/functions.h"

#define MOD_RATE_LIMIT		"\x0A""rate-limit"
#define MOD_SLIP		"\x04""slip"
#define MOD_TBL_SIZE		"\x0A""table-size"
#define MOD_WHITELIST		"\x09""whitelist"

const yp_item_t rrl_conf[] = {
	{ MOD_RATE_LIMIT, YP_TINT, YP_VINT = { 1, INT32_MAX } },
	{ MOD_SLIP,       YP_TINT, YP_VINT = { 0, RRL_SLIP_MAX, 1 } },
	{ MOD_TBL_SIZE,   YP_TINT, YP_VINT = { 1, INT32_MAX, 393241 } },
	{ MOD_WHITELIST,  YP_TNET, YP_VNONE, YP_FMULTI },
	{ NULL }
};

int rrl_conf_check(knotd_conf_check_args_t *args)
{
	knotd_conf_t limit = knotd_conf_check_item(args, MOD_RATE_LIMIT);
	if (limit.count == 0) {
		args->err_str = "no rate limit specified";
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

typedef struct {
	rrl_table_t *rrl;
	int slip;
	knotd_conf_t whitelist;
} rrl_ctx_t;

static const knot_dname_t *name_from_rrsig(const knot_rrset_t *rr)
{
	if (rr == NULL) {
		return NULL;
	}
	if (rr->type != KNOT_RRTYPE_RRSIG) {
		return NULL;
	}

	// This is a signature.
	return knot_rrsig_signer_name(&rr->rrs, 0);
}

static const knot_dname_t *name_from_authrr(const knot_rrset_t *rr)
{
	if (rr == NULL) {
		return NULL;
	}
	if (rr->type != KNOT_RRTYPE_NS && rr->type != KNOT_RRTYPE_SOA) {
		return NULL;
	}

	// This is a valid authority RR.
	return rr->owner;
}

static bool addr_range_match(const knotd_conf_t *range, const struct sockaddr_storage *addr)
{
	assert(range && addr);

	for (size_t i = 0; i < range->count; i++) {
		knotd_conf_val_t *val = &range->multi[i];
		if (val->addr_max.ss_family == AF_UNSPEC) {
			if (sockaddr_net_match((struct sockaddr *)addr,
			                       (struct sockaddr *)&val->addr,
			                       val->addr_mask)) {
				return true;
			}
		} else {
			if (sockaddr_range_match((struct sockaddr *)addr,
			                         (struct sockaddr *)&val->addr,
			                         (struct sockaddr *)&val->addr_max)) {
				return true;
			}
		}
	}

	return false;
}

static knotd_state_t ratelimit_apply(knotd_state_t state, knot_pkt_t *pkt,
                                     knotd_qdata_t *qdata, knotd_mod_t *mod)
{
	assert(pkt && qdata && mod);

	rrl_ctx_t *ctx = knotd_mod_ctx(mod);

	// Rate limit is not applied to TCP connections.
	if (!(qdata->params->flags & KNOTD_QUERY_FLAG_LIMIT_SIZE)) {
		return state;
	}

	// Rate limit is not applied to responses with a valid cookie.
	if (qdata->params->flags & KNOTD_QUERY_FLAG_COOKIE) {
		return state;
	}

	// Exempt clients.
	if (addr_range_match(&ctx->whitelist, qdata->params->remote)) {
		return state;
	}

	rrl_req_t req = {
		.w = pkt->wire,
		.query = qdata->query
	};

	if (!EMPTY_LIST(qdata->extra->wildcards)) {
		req.flags = RRL_REQ_WILDCARD;
	}

	// Take the zone name if known.
	const knot_dname_t *zone_name = knotd_qdata_zone_name(qdata);

	// Take the signer name as zone name if there is an RRSIG.
	if (zone_name == NULL) {
		const knot_pktsection_t *ans = knot_pkt_section(pkt, KNOT_ANSWER);
		for (int i = 0; i < ans->count; i++) {
			zone_name = name_from_rrsig(knot_pkt_rr(ans, i));
			if (zone_name != NULL) {
				break;
			}
		}
	}

	// Take the NS or SOA owner name if there is no RRSIG.
	if (zone_name == NULL) {
		const knot_pktsection_t *auth = knot_pkt_section(pkt, KNOT_AUTHORITY);
		for (int i = 0; i < auth->count; i++) {
			zone_name = name_from_authrr(knot_pkt_rr(auth, i));
			if (zone_name != NULL) {
				break;
			}
		}
	}

	if (rrl_query(ctx->rrl, qdata->params->remote, &req, zone_name, mod) == KNOT_EOK) {
		// Rate limiting not applied.
		return state;
	}

	if (ctx->slip > 0 && rrl_slip_roll(ctx->slip)) {
		// Slip the answer.
		knotd_mod_stats_incr(mod, 0, 0, 1);
		qdata->err_truncated = true;
		return KNOTD_STATE_FAIL;
	} else {
		// Drop the answer.
		knotd_mod_stats_incr(mod, 1, 0, 1);
		return KNOTD_STATE_NOOP;
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
	// Create RRL context.
	rrl_ctx_t *ctx = calloc(1, sizeof(rrl_ctx_t));
	if (ctx == NULL) {
		return KNOT_ENOMEM;
	}

	// Create table.
	knotd_conf_t rate = knotd_conf_mod(mod, MOD_RATE_LIMIT);
	knotd_conf_t size = knotd_conf_mod(mod, MOD_TBL_SIZE);
	ctx->rrl = rrl_create(size.single.integer, rate.single.integer);
	if (ctx->rrl == NULL) {
		ctx_free(ctx);
		return KNOT_ENOMEM;
	}

	// Get slip.
	knotd_conf_t conf = knotd_conf_mod(mod, MOD_SLIP);
	ctx->slip = conf.single.integer;

	// Get whitelist.
	ctx->whitelist = knotd_conf_mod(mod, MOD_WHITELIST);

	// Set up statistics counters.
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

	knotd_mod_ctx_set(mod, ctx);

	return knotd_mod_hook(mod, KNOTD_STAGE_END, ratelimit_apply);
}

void rrl_unload(knotd_mod_t *mod)
{
	rrl_ctx_t *ctx = knotd_mod_ctx(mod);

	knotd_conf_free(&ctx->whitelist);
	ctx_free(ctx);
}

KNOTD_MOD_API(rrl, KNOTD_MOD_FLAG_SCOPE_ANY,
              rrl_load, rrl_unload, rrl_conf, rrl_conf_check);
