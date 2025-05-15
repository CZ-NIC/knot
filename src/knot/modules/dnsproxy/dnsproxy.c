/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include "contrib/net.h"
#include "knot/include/module.h"
#include "knot/conf/schema.h"
#include "knot/query/capture.h" // Forces static module!
#include "knot/query/requestor.h" // Forces static module!
#include "libknot/xdp.h"

#define MOD_REMOTE		"\x06""remote"
#define MOD_ADDRESS		"\x07""address"
#define MOD_TCP_FASTOPEN	"\x0C""tcp-fastopen"
#define MOD_TIMEOUT		"\x07""timeout"
#define MOD_FALLBACK		"\x08""fallback"
#define MOD_CATCH_NXDOMAIN	"\x0E""catch-nxdomain"

const yp_item_t dnsproxy_conf[] = {
	{ MOD_REMOTE,         YP_TREF,  YP_VREF = { C_RMT }, YP_FNONE,
	                                { knotd_conf_check_ref } },
	{ MOD_TIMEOUT,        YP_TINT,  YP_VINT = { 0, INT32_MAX, 500 } },
	{ MOD_ADDRESS,        YP_TNET,  YP_VNONE, YP_FMULTI },
	{ MOD_FALLBACK,       YP_TBOOL, YP_VBOOL = { true } },
	{ MOD_TCP_FASTOPEN,   YP_TBOOL, YP_VNONE },
	{ MOD_CATCH_NXDOMAIN, YP_TBOOL, YP_VNONE },
	{ NULL }
};

int dnsproxy_conf_check(knotd_conf_check_args_t *args)
{
	knotd_conf_t rmt = knotd_conf_check_item(args, MOD_REMOTE);
	if (rmt.count == 0) {
		args->err_str = "no remote server specified";
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

typedef struct {
	knotd_conf_t remote;
	knotd_conf_t via;
	knotd_conf_t addr;
	bool fallback;
	bool tfo;
	bool catch_nxdomain;
	int timeout;
} dnsproxy_t;

static int fwd(dnsproxy_t *proxy, knot_pkt_t *pkt, knotd_qdata_t *qdata, int addr_pos)
{
	/* Copy the query as the requestor modifies and frees it. */
	knot_pkt_t *query = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, NULL);
	int ret = knot_pkt_copy(query, qdata->query);
	if (ret != KNOT_EOK) {
		knot_pkt_free(query);
		return ret;
	}

	/* Capture layer context. */
	const knot_layer_api_t *capture = query_capture_api();
	struct capture_param capture_param = {
		.sink = pkt
	};

	/* Create a forwarding request. */
	knot_requestor_t re;
	ret = knot_requestor_init(&re, capture, &capture_param, qdata->mm);
	if (ret != KNOT_EOK) {
		knot_pkt_free(query);
		return ret;
	}

	bool udp = false;
	if (qdata->params->xdp_msg == NULL) {
		if (!net_is_stream(qdata->params->socket)) {
			udp = true;
		}
	}
#if ENABLE_XDP
	else {
		if (!(qdata->params->xdp_msg->flags & KNOT_XDP_MSG_TCP)) {
			udp = true;
		}
	}
#endif

	knot_request_flag_t flags = KNOT_REQUEST_NONE;
	if (udp) {
		flags = KNOT_REQUEST_UDP;
	} else if (proxy->tfo) {
		flags = KNOT_REQUEST_TFO;
	}

	if (query->tsig_rr != NULL) {
		knot_tsig_append(query->wire, &query->size, query->max_size, query->tsig_rr);
	}

	const struct sockaddr_storage *dst = &proxy->remote.multi[addr_pos].addr;
	const struct sockaddr_storage *src = NULL;
	if (addr_pos < proxy->via.count) { // Simplified via address selection!
		src = &proxy->via.multi[addr_pos].addr;
	}
	knot_request_t *req = knot_request_make_generic(re.mm, dst, src, query,
	                                                NULL, NULL, NULL, NULL, NULL, 0, flags);
	if (req == NULL) {
		knot_requestor_clear(&re);
		knot_pkt_free(query);
		return KNOT_ENOMEM;
	}

	/* Forward request. */
	ret = knot_requestor_exec(&re, req, proxy->timeout);

	if (pkt->tsig_rr != NULL) {
		knot_tsig_append(pkt->wire, &pkt->size, pkt->max_size, pkt->tsig_rr);
	}

	knot_request_free(req, re.mm);
	knot_requestor_clear(&re);

	return ret;
}

static knotd_state_t dnsproxy_fwd(knotd_state_t state, knot_pkt_t *pkt,
                                  knotd_qdata_t *qdata, knotd_mod_t *mod)
{
	assert(pkt && qdata && mod);

	dnsproxy_t *proxy = knotd_mod_ctx(mod);

	/* Forward only queries ending with REFUSED (no zone) or NXDOMAIN (if configured) */
	if (proxy->fallback && !(qdata->rcode == KNOT_RCODE_REFUSED ||
	     (qdata->rcode == KNOT_RCODE_NXDOMAIN && proxy->catch_nxdomain))) {
		return state;
	}

	/* Forward from specified addresses only if configured. */
	if (proxy->addr.count > 0) {
		const struct sockaddr_storage *addr = knotd_qdata_remote_addr(qdata);
		if (!knotd_conf_addr_range_match(&proxy->addr, addr)) {
			return state;
		}
	}

	int ret = KNOT_EOK;

	/* Try to forward the packet. */
	assert(proxy->remote.count > 0);
	for (int i = 0; i < proxy->remote.count; i++) {
		ret = fwd(proxy, pkt, qdata, i);
		if (ret == KNOT_EOK) {
			break;
		}
	}

	/* Check result. */
	if (ret != KNOT_EOK) {
		return state; /* Forwarding failed, ignore. */
	} else {
		qdata->rcode = knot_pkt_ext_rcode(pkt);
	}

	return (proxy->fallback ? KNOTD_STATE_DONE : KNOTD_STATE_FINAL);
}

int dnsproxy_load(knotd_mod_t *mod)
{
	dnsproxy_t *proxy = calloc(1, sizeof(*proxy));
	if (proxy == NULL) {
		return KNOT_ENOMEM;
	}

	knotd_conf_t remote_id = knotd_conf_mod(mod, MOD_REMOTE);

	proxy->remote = knotd_conf(mod, C_RMT, C_ADDR, &remote_id);

	proxy->via = knotd_conf(mod, C_RMT, C_VIA, &remote_id);

	proxy->addr = knotd_conf_mod(mod, MOD_ADDRESS);

	knotd_conf_t conf = knotd_conf_mod(mod, MOD_TIMEOUT);
	proxy->timeout = conf.single.integer;

	conf = knotd_conf_mod(mod, MOD_FALLBACK);
	proxy->fallback = conf.single.boolean;

	conf = knotd_conf_mod(mod, MOD_TCP_FASTOPEN);
	proxy->tfo = conf.single.boolean;

	conf = knotd_conf_mod(mod, MOD_CATCH_NXDOMAIN);
	proxy->catch_nxdomain = conf.single.boolean;

	knotd_mod_ctx_set(mod, proxy);

	if (proxy->fallback) {
		return knotd_mod_hook(mod, KNOTD_STAGE_END, dnsproxy_fwd);
	} else {
		return knotd_mod_hook(mod, KNOTD_STAGE_BEGIN, dnsproxy_fwd);
	}
}

void dnsproxy_unload(knotd_mod_t *mod)
{
	dnsproxy_t *ctx = knotd_mod_ctx(mod);
	if (ctx != NULL) {
		knotd_conf_free(&ctx->remote);
		knotd_conf_free(&ctx->via);
		knotd_conf_free(&ctx->addr);
	}
	free(ctx);
}

KNOTD_MOD_API(dnsproxy, KNOTD_MOD_FLAG_SCOPE_ANY,
              dnsproxy_load, dnsproxy_unload, dnsproxy_conf, dnsproxy_conf_check);
