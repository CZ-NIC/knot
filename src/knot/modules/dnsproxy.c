/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "knot/query/requestor.h"
#include "knot/common/log.h"
#include "knot/modules/dnsproxy.h"
#include "knot/query/capture.h"
#include "knot/nameserver/process_query.h"
#include "contrib/mempattern.h"
#include "contrib/net.h"

/* Module configuration scheme. */
#define MOD_REMOTE		"\x06""remote"
#define MOD_TIMEOUT		"\x07""timeout"
#define MOD_CATCH_NXDOMAIN	"\x0E""catch-nxdomain"

const yp_item_t scheme_mod_dnsproxy[] = {
	{ C_ID,               YP_TSTR,  YP_VNONE },
	{ MOD_REMOTE,         YP_TREF,  YP_VREF = { C_RMT }, YP_FNONE, { check_ref } },
	{ MOD_TIMEOUT,        YP_TINT,  YP_VINT = { 0, INT32_MAX, 500 } },
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
	int timeout;
};

struct dnsproxy_data {
	struct knot_requestor re;
	struct knot_request *req;
};

static int dnsproxy_fwd(int state, knot_pkt_t *pkt, struct query_data *qdata, void *ctx)
{
	knot_layer_t *layer = qdata->param->layer;
	struct dnsproxy *proxy = ctx;
	struct dnsproxy_data *proxy_data = layer->defer_data;
	int ret;

	if (layer->defer_fd.fd == 0) {
		if (pkt == NULL || qdata == NULL || ctx == NULL) {
			return KNOT_STATE_FAIL;
		}

		/* Forward only queries ending with REFUSED (no zone) or NXDOMAIN (if configured) */
		if (!(qdata->rcode == KNOT_RCODE_REFUSED ||
		     (qdata->rcode == KNOT_RCODE_NXDOMAIN && proxy->catch_nxdomain))) {
			return state;
		}

		proxy_data = malloc(sizeof(*proxy_data));
		if (proxy_data == NULL) {
			return state; /* Ignore, not enough memory. */
		}

		/* Capture layer context. */
		const knot_layer_api_t *capture = query_capture_api();

		/* Create a forwarding request. */
		int ret = knot_requestor_init(&proxy_data->re, capture,
		                              pkt, qdata->mm);
		if (ret != KNOT_EOK) {
			free(proxy_data);
			return state; /* Ignore, not enough memory. */
		}

		bool is_tcp = net_is_stream(qdata->param->socket);
		proxy_data->req = knot_request_make(proxy_data->re.mm,
			(const struct sockaddr *)&proxy->remote.addr,
			(const struct sockaddr *)&proxy->remote.via,
			qdata->query, is_tcp ? 0 : KNOT_RQ_UDP);
		if (proxy_data->req == NULL) {
			knot_requestor_clear(&proxy_data->re);
			free(proxy_data);
			return state; /* Ignore, not enough memory. */
		}

		layer->defer_data = proxy_data;
	}

	if (layer->defer_fd.fd == -1) {
		ret = KNOT_EOK;
	} else if (layer->defer_timeout == -1) {
		ret = KNOT_ETIMEOUT;
	} else if (layer->defer_fd.revents & POLLERR) {
		ret = KNOT_ECONN;
	} else {
		/* Forward request. */
		ret = knot_requestor_exec_nonblocking(
			&proxy_data->re, proxy_data->req);

		/* If the request is incomplete, defer. */
		if (proxy_data->re.layer.defer_fd.fd) {
			layer->defer_fd.fd = proxy_data->re.layer.defer_fd.fd;
			layer->defer_fd.events = proxy_data->re.layer.defer_fd.events;
			layer->defer_timeout = conf()->cache.srv_tcp_reply_timeout;
			return KNOT_STATE_PRODUCE;
		}
	}

	knot_request_free(proxy_data->req, proxy_data->re.mm);
	knot_requestor_clear(&proxy_data->re);
	free(proxy_data);
	layer->defer_fd.fd = 0;

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

	val = conf_mod_get(self->config, MOD_TIMEOUT, self->id);
	proxy->timeout = conf_int(&val);

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
