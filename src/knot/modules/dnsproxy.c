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
#include "knot/modules/dnsproxy.h"
#include "knot/nameserver/capture.h"
#include "knot/nameserver/process_query.h"

#define MODULE_ERR(msg...) log_error("module 'dnsproxy', " msg)

struct dnsproxy {
	conf_iface_t remote;
};

static int dnsproxy_fwd(int state, knot_pkt_t *pkt, struct query_data *qdata, void *ctx)
{
	if (pkt == NULL || qdata == NULL || ctx == NULL) {
		return KNOT_NS_PROC_FAIL;
	}

	/* If not already satisfied. */
	if (state == KNOT_NS_PROC_DONE) {
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
		return KNOT_NS_PROC_FAIL;
	}

	bool is_tcp = net_is_connected(qdata->param->socket);
	struct knot_request *req = knot_request_make(re.mm, (struct sockaddr *)&proxy->remote.addr,
	                                             NULL, qdata->query, is_tcp ? 0 : KNOT_RQ_UDP);
	if (req == NULL) {
		return state; /* Ignore, not enough memory. */
	}

	/* Forward request. */
	ret = knot_requestor_enqueue(&re, req);
	if (ret == KNOT_EOK) {
		struct timeval tv = { conf()->max_conn_hs, 0 };
		ret = knot_requestor_exec(&re, &tv);
	} else {
		knot_request_free(re.mm, req);
	}

	knot_requestor_clear(&re);

	/* Check result. */
	if (ret != KNOT_EOK) {
		qdata->rcode = KNOT_RCODE_SERVFAIL;
		return KNOT_NS_PROC_FAIL; /* Forwarding failed, SERVFAIL. */
	}

	return KNOT_NS_PROC_DONE;
}

int dnsproxy_load(struct query_plan *plan, struct query_module *self)
{
	struct dnsproxy *proxy = mm_alloc(self->mm, sizeof(struct dnsproxy));
	if (proxy == NULL) {
		MODULE_ERR("not enough memory");
		return KNOT_ENOMEM;
	}
	memset(proxy, 0, sizeof(struct dnsproxy));

	/* Determine IPv4/IPv6 */
	int family = AF_INET;
	if (strchr(self->param, ':')) {
		family = AF_INET6;
	}

	int ret = sockaddr_set(&proxy->remote.addr, family, self->param, 53);
	if (ret != KNOT_EOK) {
		MODULE_ERR("invalid proxy address: '%s'", self->param);
		mm_free(self->mm, proxy);
		return KNOT_EINVAL;
	}

	return query_plan_step(plan, QPLAN_BEGIN, dnsproxy_fwd, proxy);
}

int dnsproxy_unload(struct query_module *self)
{
	mm_free(self->mm, self->ctx);
	return KNOT_EOK;
}

