/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <netinet/in.h>

#include "knot/include/module.h"
#include "libknot/yparser/yptrafo.h"
#include "contrib/sockaddr.c"

#define MOD_ZONE   "\x04""zone"
#define MOD_A      "\x01""a"
#define MOD_AAAA   "\x04""aaaa"
#define MOD_LABELS "\x06""labels"
#define MOD_TTL    "\x03""ttl"

typedef struct {
	const knot_dname_t *zone;
	knotd_conf_t a;
	knotd_conf_t aaaa;
	knotd_conf_t labels;
	uint32_t ttl;
} append_ctx_t;

static int check_addr_family(knotd_conf_check_args_t *args)
{
	bool no_port;
	struct sockaddr_storage ss = yp_addr(args->data, &no_port);
	if (strcmp(args->item->name, MOD_A) == 0 && ss.ss_family == AF_INET) {
		return KNOT_EOK;
	} else if (strcmp(args->item->name, MOD_AAAA) == 0 && ss.ss_family == AF_INET6) {
		return KNOT_EOK;
	}

	args->err_str = "invalid address";
	return KNOT_EINVAL;
}

const yp_item_t append_conf[] = {
	{ MOD_ZONE,   YP_TDNAME, YP_VNONE },
	{ MOD_A,      YP_TADDR,  YP_VNONE, YP_FNONE, { check_addr_family } },
	{ MOD_AAAA,   YP_TADDR,  YP_VNONE, YP_FNONE, { check_addr_family } },
	{ MOD_LABELS, YP_TDNAME, YP_VNONE, YP_FMULTI },
	{ MOD_TTL,    YP_TINT,   YP_VINT = { 1, INT32_MAX, 86400, YP_STIME } },
	{ NULL }
};

static knotd_in_state_t append_query(knotd_in_state_t state, knot_pkt_t *pkt,
                                     knotd_qdata_t *qdata, knotd_mod_t *mod)
{
	assert(pkt && qdata);

	/* Only when query has answer */
	if (state != KNOTD_IN_STATE_HIT) {
		return state;
	}

	append_ctx_t *ctx = knotd_mod_ctx(mod);
	if (ctx == NULL) {
		return KNOTD_IN_STATE_ERROR;
	}

	const knot_dname_t *zone_name = knotd_qdata_zone_name(qdata);
	if (zone_name == NULL) {
		return KNOTD_IN_STATE_ERROR;
	}

	/* Retrieve the query tuple. */
	const knot_dname_t *qname = knot_pkt_qname(qdata->query);
	const uint16_t qtype = knot_pkt_qtype(qdata->query);
	const uint16_t qclass = knot_pkt_qclass(qdata->query);

	/* We only allow A and AAAA records, which are Internet class. */
	if (qclass != KNOT_CLASS_IN) {
		return state;
	}

	/* Only handle A and AAAA queries. */
	const uint8_t *addr = NULL;
	size_t addr_len = 0;
	if (qtype == KNOT_RRTYPE_A && ctx->a.count == 1) {
		struct sockaddr_in *a = (struct sockaddr_in *)&ctx->a.single.addr;
		addr = (const uint8_t *)&a->sin_addr;
		addr_len = sizeof(a->sin_addr);
	} else if (qtype == KNOT_RRTYPE_AAAA && ctx->aaaa.count == 1) {
		struct sockaddr_in6 *aaaa = (struct sockaddr_in6 *)&ctx->aaaa.single.addr;
		addr = (const uint8_t *)&aaaa->sin6_addr;
		addr_len = sizeof(aaaa->sin6_addr);
	} else {
		return state;
	}

	/* Filter out irrelevant queries */
	int idx = 0;
	for (; idx < ctx->labels.count; ++idx) {
		knot_dname_t *label_qname = knot_dname_replace_suffix(ctx->labels.multi[idx].dname, 0, zone_name, &pkt->mm);
		if (knot_dname_is_equal(qname, label_qname)) {
			knot_dname_free(label_qname, &pkt->mm);
			break;
		}
		knot_dname_free(label_qname, &pkt->mm);
	}
	if (idx == ctx->labels.count) {
		return state;
	}

	knot_dname_t *new_qname = knot_dname_replace_suffix(qname,
			knot_dname_labels(zone_name, NULL), ctx->zone, &pkt->mm);

	/* Owner name, type, and class are taken from the question. */
	knot_rrset_t *rrset = knot_rrset_new(new_qname, qtype, qclass, ctx->ttl,
	                                     &pkt->mm);
	knot_dname_free(new_qname, &pkt->mm);
	if (rrset == NULL) {
		return KNOTD_IN_STATE_ERROR;
	}

	/* Record data is the query source address. */
	int ret = knot_rrset_add_rdata(rrset, addr, addr_len, &pkt->mm);
	if (ret != KNOT_EOK) {
		knot_rrset_free(rrset, &pkt->mm);
		return KNOTD_IN_STATE_ERROR;
	}

	/* Add the new RRset to the response packet. */
	ret = knot_pkt_put(pkt, KNOT_COMPR_HINT_NONE, rrset, KNOT_PF_FREE);
	if (ret != KNOT_EOK) {
		knot_rrset_free(rrset, &pkt->mm);
		return KNOTD_IN_STATE_ERROR;
	}

	return state;
}

int append_load(knotd_mod_t *mod)
{
	append_ctx_t *ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		return KNOT_ENOMEM;
	}

	knotd_conf_t conf_zone = knotd_conf_mod(mod, MOD_ZONE);
	ctx->zone = conf_zone.single.dname;

	ctx->a = knotd_conf_mod(mod, MOD_A);

	ctx->aaaa = knotd_conf_mod(mod, MOD_AAAA);

	ctx->labels = knotd_conf_mod(mod, MOD_LABELS);

	knotd_conf_t conf_ttl = knotd_conf_mod(mod, MOD_TTL);
	ctx->ttl = conf_ttl.single.integer;

	knotd_mod_ctx_set(mod, ctx);

	knotd_mod_in_hook(mod, KNOTD_STAGE_ANSWER, append_query);

	return KNOT_EOK;
}

int append_conf_check(knotd_conf_check_args_t *args)
{
	knotd_conf_t conf_zone = knotd_conf_check_item(args, MOD_ZONE);
	if (conf_zone.count == 0) {
		args->err_str = "no zone configured";
		return KNOT_EINVAL;
	}

	knotd_conf_t conf_a = knotd_conf_check_item(args, MOD_A);
	knotd_conf_t conf_aaaa = knotd_conf_check_item(args, MOD_AAAA);
	if (conf_a.count + conf_aaaa.count == 0) {
		args->err_str = "no address configured";
		return KNOT_EINVAL;
	}

	knotd_conf_t conf_labels = knotd_conf_check_item(args, MOD_LABELS);
	if (conf_labels.count == 0) {
		args->err_str = "no labels configured";
		return KNOT_EINVAL;
	}
	knotd_conf_free(&conf_labels);

	return KNOT_EOK;
}

void append_unload(knotd_mod_t *mod)
{
	append_ctx_t *ctx = knotd_mod_ctx(mod);
	if (ctx != NULL) {
		knotd_conf_free(&ctx->labels);
	}
	free(ctx);
}

KNOTD_MOD_API(append, KNOTD_MOD_FLAG_SCOPE_ZONE, append_load, append_unload,
              append_conf, append_conf_check);
