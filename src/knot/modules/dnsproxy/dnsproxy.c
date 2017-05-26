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

#include "contrib/net.h"
#include "knot/include/module.h"
#include "knot/conf/scheme.h"
#include "knot/query/capture.h" // Forces static module!
#include "knot/query/requestor.h" // Forces static module!

/* Module configuration scheme. */
#define MOD_REMOTE		"\x06""remote"
#define MOD_TIMEOUT		"\x07""timeout"
#define MOD_FALLBACK		"\x08""fallback"
#define MOD_CATCH_NXDOMAIN	"\x0E""catch-nxdomain"

const yp_item_t dnsproxy_conf[] = {
	{ MOD_REMOTE,         YP_TREF,  YP_VREF = { C_RMT }, YP_FNONE,
	                                { knotd_conf_check_ref } },
	{ MOD_TIMEOUT,        YP_TINT,  YP_VINT = { 0, INT32_MAX, 500 } },
	{ MOD_FALLBACK,       YP_TBOOL, YP_VBOOL = { true } },
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
	struct sockaddr_storage remote;
	struct sockaddr_storage via;
	bool fallback;
	bool catch_nxdomain;
	int timeout;
} dnsproxy_t;

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

	/* Forward also original TSIG. */
	if (qdata->query->tsig_rr != NULL && !proxy->fallback) {
		knot_tsig_append(qdata->query->wire, &qdata->query->size,
		                 qdata->query->max_size, qdata->query->tsig_rr);
	}

	/* Capture layer context. */
	const knot_layer_api_t *capture = query_capture_api();
	struct capture_param capture_param = {
		.sink = pkt
	};

	/* Create a forwarding request. */
	struct knot_requestor re;
	int ret = knot_requestor_init(&re, capture, &capture_param, qdata->mm);
	if (ret != KNOT_EOK) {
		return state; /* Ignore, not enough memory. */
	}

	bool is_tcp = net_is_stream(qdata->params->socket);
	const struct sockaddr *dst = (const struct sockaddr *)&proxy->remote;
	const struct sockaddr *src = (const struct sockaddr *)&proxy->via;
	struct knot_request *req = knot_request_make(re.mm, dst, src, qdata->query, NULL,
	                                             is_tcp ? 0 : KNOT_RQ_UDP);
	if (req == NULL) {
		knot_requestor_clear(&re);
		return state; /* Ignore, not enough memory. */
	}

	/* Forward request. */
	ret = knot_requestor_exec(&re, req, proxy->timeout);

	knot_request_free(req, re.mm);
	knot_requestor_clear(&re);

	/* Check result. */
	if (ret != KNOT_EOK) {
		qdata->rcode = KNOT_RCODE_SERVFAIL;
		return KNOTD_STATE_FAIL; /* Forwarding failed, SERVFAIL. */
	} else {
		qdata->rcode = knot_pkt_ext_rcode(pkt);
	}

	/* Respond also with TSIG. */
	if (pkt->tsig_rr != NULL && !proxy->fallback) {
		knot_tsig_append(pkt->wire, &pkt->size, pkt->max_size, pkt->tsig_rr);
	}

	return KNOTD_STATE_DONE;
}

int dnsproxy_load(knotd_mod_t *mod)
{
	dnsproxy_t *proxy = calloc(1, sizeof(*proxy));
	if (proxy == NULL) {
		return KNOT_ENOMEM;
	}

	knotd_conf_t remote = knotd_conf_mod(mod, MOD_REMOTE);
	knotd_conf_t conf = knotd_conf(mod, C_RMT, C_ADDR, &remote);
	if (conf.count > 0) {
		proxy->remote = conf.multi[0].addr;
		knotd_conf_free(&conf);
	}
	conf = knotd_conf(mod, C_RMT, C_VIA, &remote);
	if (conf.count > 0) {
		proxy->via = conf.multi[0].addr;
		knotd_conf_free(&conf);
	}

	conf = knotd_conf_mod(mod, MOD_TIMEOUT);
	proxy->timeout = conf.single.integer;

	conf = knotd_conf_mod(mod, MOD_FALLBACK);
	proxy->fallback = conf.single.boolean;

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
	free(knotd_mod_ctx(mod));
}

KNOTD_MOD_API(dnsproxy, KNOTD_MOD_FLAG_SCOPE_ANY,
              dnsproxy_load, dnsproxy_unload, dnsproxy_conf, dnsproxy_conf_check);
