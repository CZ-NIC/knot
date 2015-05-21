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
#define MOD_REMOTE	"\x06""remote"

const yp_item_t scheme_mod_dnsproxy[] = {
	{ C_ID,       YP_TSTR,  YP_VNONE },
	{ MOD_REMOTE, YP_TADDR, YP_VADDR = { 53 } },
	{ C_COMMENT,  YP_TSTR,  YP_VNONE },
	{ NULL }
};

/* Defines. */
#define MODULE_ERR(msg, ...) log_error("module 'dnsproxy', " msg, ##__VA_ARGS__)

struct dnsproxy {
	struct sockaddr_storage remote;
};

static int dnsproxy_fwd(int state, knot_pkt_t *pkt, struct query_data *qdata, void *ctx)
{
	if (pkt == NULL || qdata == NULL || ctx == NULL) {
		return KNOT_STATE_FAIL;
	}

	/* If not already satisfied. */
	if (state == KNOT_STATE_DONE) {
		return state;
	}

	struct dnsproxy *proxy = ctx;

	/* Create a forwarding request. */
	struct knot_requestor re;
	knot_requestor_init(&re, qdata->mm);
	struct capture_param param;
	param.sink = pkt;
	int ret = knot_requestor_overlay(&re, LAYER_CAPTURE, &param);
	if (ret != KNOT_EOK) {
		return KNOT_STATE_FAIL;
	}

	bool is_tcp = net_is_connected(qdata->param->socket);
	struct knot_request *req;
	req = knot_request_make(re.mm, (const struct sockaddr *)&proxy->remote,
	                        NULL, qdata->query, is_tcp ? 0 : KNOT_RQ_UDP);
	if (req == NULL) {
		return state; /* Ignore, not enough memory. */
	}

	/* Forward request. */
	ret = knot_requestor_enqueue(&re, req);
	if (ret == KNOT_EOK) {
		conf_val_t val = conf_get(conf(), C_SRV, C_TCP_HSHAKE_TIMEOUT);
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

int dnsproxy_load(struct query_plan *plan, struct query_module *self)
{
	if (plan == NULL || self == NULL) {
		return KNOT_EINVAL;
	}

	struct dnsproxy *proxy = mm_alloc(self->mm, sizeof(struct dnsproxy));
	if (proxy == NULL) {
		MODULE_ERR("not enough memory");
		return KNOT_ENOMEM;
	}
	memset(proxy, 0, sizeof(struct dnsproxy));

	conf_val_t val = conf_mod_get(self->config, MOD_REMOTE, self->id);
	if (val.code != KNOT_EOK) {
		if (val.code == KNOT_EINVAL) {
			MODULE_ERR("no remote proxy address for '%s'",
			           self->id->data);
		}
		mm_free(self->mm, proxy);
		return val.code;
	}
	proxy->remote = conf_addr(&val, NULL);

	self->ctx = proxy;

	return query_plan_step(plan, QPLAN_BEGIN, dnsproxy_fwd, self->ctx);
}

int dnsproxy_unload(struct query_module *self)
{
	if (self == NULL) {
		return KNOT_EINVAL;
	}

	mm_free(self->mm, self->ctx);
	return KNOT_EOK;
}
