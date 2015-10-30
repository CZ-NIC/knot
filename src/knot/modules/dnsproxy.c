/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "libknot/processing/requestor.h"
#include "knot/common/log.h"
#include "knot/modules/dnsproxy.h"
#include "knot/nameserver/capture.h"
#include "knot/nameserver/process_query.h"

/* Module configuration scheme. */
#define MOD_REMOTE		"\x06""remote"
#define MOD_CATCH_NXDOMAIN	"\x0E""catch-nxdomain"

const yp_item_t scheme_mod_dnsproxy[] = {
	{ C_ID,               YP_TSTR,  YP_VNONE },
	{ MOD_REMOTE,         YP_TREF,  YP_VREF = { C_RMT }, YP_FNONE, { check_ref } },
	{ MOD_CATCH_NXDOMAIN, YP_TBOOL, YP_VNONE },
	{ C_COMMENT,          YP_TSTR,  YP_VNONE },
	{ NULL }
};

int check_mod_dnsproxy(conf_check_t *args)
{
	conf_val_t rmt = conf_rawid_get_txn(args->conf, args->txn, C_MOD_DNSPROXY,
	                                    MOD_REMOTE, args->id, args->id_len);
	if (rmt.code != KNOT_EOK) {
		args->err_str = "no remote server specified";
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

struct dnsproxy {
	conf_remote_t remote;
	bool catch_nxdomain;
};

static int dnsproxy_fwd(int state, knot_pkt_t *pkt, struct query_data *qdata, void *ctx)
{
	if (pkt == NULL || qdata == NULL || ctx == NULL) {
		return KNOT_STATE_FAIL;
	}

	/* Forward only queries ending with REFUSED (no zone) or NXDOMAIN (if configured) */
	struct dnsproxy *proxy = ctx;
	if (!(qdata->rcode == KNOT_RCODE_REFUSED ||
	     (qdata->rcode == KNOT_RCODE_NXDOMAIN && proxy->catch_nxdomain))) {
		return state;
	}

	/* Create a forwarding request. */
	struct knot_requestor re;
	knot_requestor_init(&re, qdata->mm);
	struct capture_param param;
	param.sink = pkt;
	int ret = knot_requestor_overlay(&re, LAYER_CAPTURE, &param);
	if (ret != KNOT_EOK) {
		return KNOT_STATE_FAIL;
	}

	bool is_tcp = net_is_stream(qdata->param->socket);
	struct knot_request *req;
	const struct sockaddr *dst = (const struct sockaddr *)&proxy->remote.addr;
	const struct sockaddr *src = (const struct sockaddr *)&proxy->remote.via;
	req = knot_request_make(re.mm, dst, src, qdata->query, is_tcp ? 0 : KNOT_RQ_UDP);
	if (req == NULL) {
		return state; /* Ignore, not enough memory. */
	}

	/* Forward request. */
	ret = knot_requestor_enqueue(&re, req);
	if (ret == KNOT_EOK) {
		conf_val_t val = conf_get(conf(), C_SRV, C_TCP_REPLY_TIMEOUT);
		struct timeval tv = { conf_int(&val), 0 };
		ret = knot_requestor_exec(&re, &tv);
	} else {
		knot_request_free(re.mm, req);
	}

	knot_requestor_clear(&re);

	/* Check result. */
	if (ret != KNOT_EOK) {
		qdata->rcode = KNOT_RCODE_SERVFAIL;
		return KNOT_STATE_FAIL; /* Forwarding failed, SERVFAIL. */
	}

	return KNOT_STATE_DONE;
}

int dnsproxy_load(struct query_plan *plan, struct query_module *self,
                  const knot_dname_t *zone)
{
	if (plan == NULL || self == NULL) {
		return KNOT_EINVAL;
	}

	struct dnsproxy *proxy = mm_alloc(self->mm, sizeof(struct dnsproxy));
	if (proxy == NULL) {
		return KNOT_ENOMEM;
	}
	memset(proxy, 0, sizeof(struct dnsproxy));

	conf_val_t val = conf_mod_get(self->config, MOD_REMOTE, self->id);
	proxy->remote = conf_remote(self->config, &val, 0);

	val = conf_mod_get(self->config, MOD_CATCH_NXDOMAIN, self->id);
	proxy->catch_nxdomain = conf_bool(&val);

	self->ctx = proxy;

	return query_plan_step(plan, QPLAN_END, dnsproxy_fwd, self->ctx);
}

int dnsproxy_unload(struct query_module *self)
{
	if (self == NULL) {
		return KNOT_EINVAL;
	}

	mm_free(self->mm, self->ctx);
	return KNOT_EOK;
}
