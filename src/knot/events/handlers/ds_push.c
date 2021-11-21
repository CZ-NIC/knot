/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
	const knot_dname_t *parent_query;
	knot_dname_t *parent_soa;
	knot_rrset_t del_old_ds;
	knot_rrset_t new_ds;
	const struct sockaddr *remote;
	struct query_edns_data edns;
};

#define DS_PUSH_RETRY	600

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
	assert(data->parent_query[0] != '\0');
	data->parent_query = knot_wire_next_label(data->parent_query, NULL);

	int ret = knot_pkt_put_question(pkt, data->parent_query, KNOT_CLASS_IN, KNOT_RRTYPE_SOA);
	if (ret != KNOT_EOK) {
		return KNOT_STATE_FAIL;
	}

	ret = query_put_edns(pkt, &data->edns);
	if (ret != KNOT_EOK) {
		return KNOT_STATE_FAIL;
	}

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
		// Otherwise only remove DS - it was a special "remove CDS".
		ret = knot_pkt_put(pkt, KNOT_COMPR_HINT_NONE, &data->new_ds, 0);
		if (ret != KNOT_EOK) {
			return KNOT_STATE_FAIL;
		}
	}

	query_put_edns(pkt, &data->edns);

	return KNOT_STATE_CONSUME;
}

static const knot_rrset_t *sect_soa(const knot_pkt_t *pkt, knot_section_t sect)
{
	const knot_pktsection_t *s = knot_pkt_section(pkt, sect);
	const knot_rrset_t *rr = s->count > 0 ? knot_pkt_rr(s, 0) : NULL;
	if (rr == NULL || rr->type != KNOT_RRTYPE_SOA || rr->rrs.count != 1) {
		return NULL;
	}
	return rr;
}

static int ds_push_consume(knot_layer_t *layer, knot_pkt_t *pkt)
{
	struct ds_push_data *data = layer->data;

	if (data->parent_soa != NULL) {
		// DS push has already been sent, just finish the action.
		return KNOT_STATE_DONE;
	}

	const knot_rrset_t *parent_soa = sect_soa(pkt, KNOT_ANSWER);
	if (parent_soa != NULL) {
		// parent SOA obtained, continue with DS push
		data->parent_soa = knot_dname_copy(parent_soa->owner, NULL);
		return KNOT_STATE_RESET;
	}

	if (data->parent_query[0] == '\0') {
		// query for parent SOA systematically fails
		DS_PUSH_LOG(LOG_WARNING, data->zone, data->remote,
		            "unable to query parent SOA");
		return KNOT_STATE_FAIL;
	}

	return KNOT_STATE_RESET; // cut off one more label and re-query
}

static int ds_push_reset(knot_layer_t *layer)
{
	(void)layer;
	return KNOT_STATE_PRODUCE;
}

static int ds_push_finish(knot_layer_t *layer)
{
	struct ds_push_data *data = layer->data;
	free(data->parent_soa);
	data->parent_soa = NULL;
	return layer->state;
}

static const knot_layer_api_t DS_PUSH_API = {
	.begin = ds_push_begin,
	.produce = ds_push_produce,
	.reset = ds_push_reset,
	.consume = ds_push_consume,
	.finish = ds_push_finish,
};

static int send_ds_push(conf_t *conf, zone_t *zone,
                        const conf_remote_t *parent, int timeout)
{
	knot_rrset_t zone_cds = node_rrset(zone->contents->apex, KNOT_RRTYPE_CDS);
	if (knot_rrset_empty(&zone_cds)) {
		return KNOT_EOK; // No CDS, do nothing.
	}
	zone_cds.type = KNOT_RRTYPE_DS;

	struct ds_push_data data = {
		.zone = zone->name,
		.parent_query = zone->name,
		.new_ds = zone_cds,
		.remote = (struct sockaddr *)&parent->addr,
	};

	knot_rrset_init(&data.del_old_ds, zone->name, KNOT_RRTYPE_DS, KNOT_CLASS_ANY, 0);
	int ret = knot_rrset_add_rdata(&data.del_old_ds, NULL, 0, NULL);
	if (ret != KNOT_EOK) {
		return ret;
	}
	query_edns_data_init(&data.edns, conf, zone->name, parent->addr.ss_family);

	knot_requestor_t requestor;
	knot_requestor_init(&requestor, &DS_PUSH_API, &data, NULL);

	knot_pkt_t *pkt = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, NULL);
	if (pkt == NULL) {
		knot_rdataset_clear(&data.del_old_ds.rrs, NULL);
		knot_requestor_clear(&requestor);
		return KNOT_ENOMEM;
	}

	const struct sockaddr_storage *dst = &parent->addr;
	const struct sockaddr_storage *src = &parent->via;
	knot_request_t *req = knot_request_make(NULL, dst, src, pkt, &parent->key, 0);
	if (req == NULL) {
		knot_rdataset_clear(&data.del_old_ds.rrs, NULL);
		knot_request_free(req, NULL);
		knot_requestor_clear(&requestor);
		return KNOT_ENOMEM;
	}

	ret = knot_requestor_exec(&requestor, req, timeout);

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

	knot_rdataset_clear(&data.del_old_ds.rrs, NULL);
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

	int timeout = conf->cache.srv_tcp_remote_io_timeout;

	conf_val_t policy_id = conf_zone_get(conf, C_DNSSEC_POLICY, zone->name);
	conf_id_fix_default(&policy_id);
	conf_val_t ds_push = conf_id_get(conf, C_POLICY, C_DS_PUSH, &policy_id);
	while (ds_push.code == KNOT_EOK) {
		conf_val_t addr = conf_id_get(conf, C_RMT, C_ADDR, &ds_push);
		size_t addr_count = conf_val_count(&addr);

		int ret = KNOT_EOK;
		for (int i = 0; i < addr_count; i++) {
			conf_remote_t parent = conf_remote(conf, &ds_push, i);
			ret = send_ds_push(conf, zone, &parent, timeout);
			if (ret == KNOT_EOK) {
				zone->timers.next_ds_push = 0;
				break;
			}
		}

		if (ret != KNOT_EOK) {
			time_t next_push = time(NULL) + DS_PUSH_RETRY;
			zone_events_schedule_at(zone, ZONE_EVENT_DS_PUSH, next_push);
			zone->timers.next_ds_push = next_push;
		}

		conf_val_next(&ds_push);
	}

	return KNOT_EOK;
}
