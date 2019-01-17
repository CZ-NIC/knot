/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <assert.h>

#include "knot/common/log.h"
#include "knot/conf/conf.h"
#include "knot/query/query.h"
#include "knot/query/requestor.h"
#include "knot/zone/zone.h"
#include "libknot/errcode.h"

struct ds_push_data {
	const knot_dname_t *zone;
	knot_dname_t *parent_soa;
	knot_rrset_t del_old_ds;
	knot_rrset_t new_ds;
	const struct sockaddr *remote;
	struct query_edns_data edns;
};

#define DS_PUSH_RETRY (3600)

#define DS_PUSH_LOG(priority, zone, remote, fmt, ...) \
	ns_log(priority, zone, LOG_OPERATION_DS_PUSH, LOG_DIRECTION_OUT, remote, \
	       fmt, ## __VA_ARGS__)

static const knot_rdata_t remove_cds = { 5, { 0, 0, 0, 0, 0 } };

static int ds_push_begin(knot_layer_t *layer, void *params)
{
	layer->data = params;

	return KNOT_STATE_PRODUCE;
}

static int parent_soa_produce(struct ds_push_data *data, knot_pkt_t *pkt)
{
	int ret = knot_pkt_put_question(pkt, data->zone, KNOT_CLASS_IN, KNOT_RRTYPE_SOA);
	if (ret != KNOT_EOK) {
		return KNOT_STATE_FAIL;
	}
	query_put_edns(pkt, &data->edns);

	return KNOT_STATE_CONSUME;
}

static int ds_push_produce(knot_layer_t *layer, knot_pkt_t *pkt)
{
	struct ds_push_data *data = layer->data;

	query_init_pkt(pkt);
	if (data->parent_soa == NULL) {
		return parent_soa_produce(data, pkt);
	}

	knot_wire_set_opcode(pkt->wire, KNOT_OPCODE_UPDATE);
	int ret = knot_pkt_put_question(pkt, data->parent_soa, KNOT_CLASS_IN, KNOT_RRTYPE_SOA);
	if (ret != KNOT_EOK) {
		return KNOT_STATE_FAIL;
	}

	knot_pkt_begin(pkt, KNOT_AUTHORITY);

	assert(data->del_old_ds.type == KNOT_RRTYPE_DS);
	ret = knot_pkt_put(pkt, KNOT_COMPR_HINT_NONE, &data->del_old_ds, 0);
	if (ret != KNOT_EOK) {
		return KNOT_STATE_FAIL;
	}

	assert(data->new_ds.type == KNOT_RRTYPE_DS);
	assert(!knot_rrset_empty(&data->new_ds));
	if (knot_rdata_cmp(data->new_ds.rrs.rdata, &remove_cds) != 0) {
		// otherwise only remove DS - it was a special "remove CDS"
		ret = knot_pkt_put(pkt, KNOT_COMPR_HINT_NONE, &data->new_ds, 0);
		if (ret != KNOT_EOK) {
			return KNOT_STATE_FAIL;
		}
	}

	query_put_edns(pkt, &data->edns);

	return KNOT_STATE_CONSUME;
}

static int ds_push_consume(knot_layer_t *layer, knot_pkt_t *pkt)
{
	struct ds_push_data *data = layer->data;

	if (data->parent_soa != NULL) {
		// DS push has been already sent, just finish the action
		free(data->parent_soa);
		return KNOT_STATE_DONE;
	}

	const knot_pktsection_t *authority = knot_pkt_section(pkt, KNOT_AUTHORITY);
	const knot_rrset_t *rr = authority->count > 0 ? knot_pkt_rr(authority, 0) : NULL;
	if (!rr || rr->type != KNOT_RRTYPE_SOA || rr->rrs.count != 1) {
		DS_PUSH_LOG(LOG_WARNING, data->zone, data->remote,
		            "malformed message");
		return KNOT_STATE_FAIL;
	}

	data->parent_soa = knot_dname_copy(rr->owner, NULL);

	return KNOT_STATE_RESET;
}

static int ds_push_reset(knot_layer_t *layer)
{
	(void)layer;
	return KNOT_STATE_PRODUCE;
}

static const knot_layer_api_t DS_PUSH_API = {
	.begin = ds_push_begin,
	.produce = ds_push_produce,
	.reset = ds_push_reset,
	.consume = ds_push_consume,
};

static int send_ds_push(conf_t *conf, zone_t *zone,
                        const conf_remote_t *parent, int timeout)
{
	const knot_rrset_t zone_cds = node_rrset(zone->contents->apex, KNOT_RRTYPE_CDS);
	if (knot_rrset_empty(&zone_cds)) {
		return KNOT_EOK; // no CDS, do nothing
	}

	struct ds_push_data data = { 0 };
	knot_rrset_init(&data.del_old_ds, zone->name, KNOT_RRTYPE_DS, KNOT_CLASS_ANY, 0);
	data.new_ds = zone_cds;
	data.new_ds.type = KNOT_RRTYPE_DS;

	data.remote = (struct sockaddr *)&parent->addr;

	data.zone = zone->name;

	query_edns_data_init(&data.edns, conf, zone->name, parent->addr.ss_family);

	knot_requestor_t requestor;
	knot_requestor_init(&requestor, &DS_PUSH_API, &data, NULL);

	knot_pkt_t *pkt = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, NULL);
	if (!pkt) {
		knot_requestor_clear(&requestor);
		return KNOT_ENOMEM;
	}

	const struct sockaddr *dst = (struct sockaddr *)&parent->addr;
	const struct sockaddr *src = (struct sockaddr *)&parent->via;
	knot_request_t *req = knot_request_make(NULL, dst, src, pkt, &parent->key, 0);
	if (!req) {
		knot_request_free(req, NULL);
		knot_requestor_clear(&requestor);
		return KNOT_ENOMEM;
	}

	int ret = knot_requestor_exec(&requestor, req, timeout);

	if (ret == KNOT_EOK && knot_pkt_ext_rcode(req->resp) == 0) {
		DS_PUSH_LOG(LOG_INFO, zone->name, dst, "success");
	} else if (knot_pkt_ext_rcode(req->resp) == 0) {
		DS_PUSH_LOG(LOG_WARNING, zone->name, dst,
		            "failed (%s)", knot_strerror(ret));
	} else {
		DS_PUSH_LOG(LOG_WARNING, zone->name, dst,
		            "server responded with error '%s'",
		            knot_pkt_ext_rcode_name(req->resp));
	}

	knot_request_free(req, NULL);
	knot_requestor_clear(&requestor);

	return ret;
}

int event_ds_push(conf_t *conf, zone_t *zone)
{
	assert(zone);

	if (zone_contents_is_empty(zone->contents)) {
		return KNOT_EOK;
	}

	int ret, timeout = conf->cache.srv_tcp_reply_timeout * 1000;

	conf_val_t policy_id = conf_zone_get(conf, C_DNSSEC_POLICY, zone->name);
	conf_id_fix_default(&policy_id);
	conf_val_t ds_push = conf_id_get(conf, C_POLICY, C_DS_PUSH, &policy_id);
	while (ds_push.code == KNOT_EOK) {
		conf_val_t addr = conf_id_get(conf, C_RMT, C_ADDR, &ds_push);
		size_t addr_count = conf_val_count(&addr);

		for (int i = 0; i < addr_count; i++) {
			conf_remote_t parent = conf_remote(conf, &ds_push, i);
			ret = send_ds_push(conf, zone, &parent, timeout);
			if (ret == KNOT_EOK) {
				break;
			}
		}

		if (ret != KNOT_EOK) {
			zone_events_schedule_at(zone, ZONE_EVENT_DS_PUSH, time(NULL) + DS_PUSH_RETRY);
		}

		conf_val_next(&ds_push);
	}

	return KNOT_EOK;
}
