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

#include <assert.h>

#include "knot/common/log.h"
#include "knot/conf/conf.h"
#include "knot/dnssec/context.h"
#include "knot/dnssec/key-events.h"
#include "knot/dnssec/zone-keys.h"
#include "knot/query/layer.h"
#include "knot/query/query.h"
#include "knot/query/requestor.h"
#include "knot/zone/zone.h"

static bool match_key_ds(zone_key_t *key, knot_rdata_t *ds)
{
	assert(key);
	assert(ds);

	dnssec_binary_t ds_rdata = {
		.size = ds->len,
		.data = ds->data,
	};

	dnssec_binary_t cds_rdata = { 0 };

	int ret = zone_key_calculate_ds(key, &cds_rdata);
	if (ret != KNOT_EOK) {
		return false;
	}

	return (dnssec_binary_cmp(&cds_rdata, &ds_rdata) == 0);
}

struct ds_query_data {
	const knot_dname_t *zone_name;
	const struct sockaddr *remote;

	zone_key_t *key;

	bool ds_ok;
	bool result_logged;
};

static int ds_query_begin(knot_layer_t *layer, void *params)
{
	layer->data = params;

	return KNOT_STATE_PRODUCE;
}

static int ds_query_produce(knot_layer_t *layer, knot_pkt_t *pkt)
{
	struct ds_query_data *data = layer->data;

	query_init_pkt(pkt);

	int r = knot_pkt_put_question(pkt, data->zone_name, KNOT_CLASS_IN, KNOT_RRTYPE_DS);
	if (r != KNOT_EOK) {
		return KNOT_STATE_FAIL;
	}

	knot_wire_set_rd(pkt->wire);

	return KNOT_STATE_CONSUME;
}

static int ds_query_consume(knot_layer_t *layer, knot_pkt_t *pkt)
{
	struct ds_query_data *data = layer->data;
	data->result_logged = true;

	if (knot_pkt_ext_rcode(pkt) != KNOT_RCODE_NOERROR) {
		ns_log(LOG_WARNING, data->zone_name, LOG_OPERATION_PARENT,
		       LOG_DIRECTION_OUT, data->remote, "failed (%s)", knot_pkt_ext_rcode_name(pkt));
		return KNOT_STATE_FAIL;
	}

	const knot_pktsection_t *answer = knot_pkt_section(pkt, KNOT_ANSWER);

	bool match = false;

	for (size_t j = 0; j < answer->count; j++) {
		const knot_rrset_t *rr = knot_pkt_rr(answer, j);
		if (!rr || rr->type != KNOT_RRTYPE_DS || rr->rrs.rr_count != 1) {
			ns_log(LOG_WARNING, data->zone_name, LOG_OPERATION_PARENT,
			       LOG_DIRECTION_OUT, data->remote, "malformed message");
			return KNOT_STATE_FAIL;
		}

		if (match_key_ds(data->key, knot_rdataset_at(&rr->rrs, 0))) {
			match = true;
			break;
		}
	}

	ns_log(LOG_INFO, data->zone_name, LOG_OPERATION_PARENT,
	       LOG_DIRECTION_OUT, data->remote, "KSK submission attempt: %s",
	       (match ? "positive" : "negative"));

	if (match) data->ds_ok = true;
	return KNOT_STATE_DONE;
}

static const knot_layer_api_t ds_query_api = {
	.begin = ds_query_begin,
	.produce = ds_query_produce,
	.consume = ds_query_consume,
	.reset = NULL,
	.finish = NULL,
};

static int try_ds(const knot_dname_t *zone_name, const conf_remote_t *parent, zone_key_t *key, size_t timeout)
{
	// TODO: Abstract interface to issue DNS queries. This is almost copy-pasted.

	assert(zone_name);
	assert(parent);

	struct ds_query_data data = {
		.zone_name = zone_name,
		.remote = (struct sockaddr *)&parent->addr,
		.key = key,
		.ds_ok = false,
		.result_logged = false,
	};

	struct knot_requestor requestor;
	knot_requestor_init(&requestor, &ds_query_api, &data, NULL);

	knot_pkt_t *pkt = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, NULL);
	if (!pkt) {
		knot_requestor_clear(&requestor);
		return KNOT_ENOMEM;
	}

	const struct sockaddr *dst = (struct sockaddr *)&parent->addr;
	const struct sockaddr *src = (struct sockaddr *)&parent->via;
	struct knot_request *req = knot_request_make(NULL, dst, src, pkt, &parent->key, 0);
	if (!req) {
		knot_request_free(req, NULL);
		knot_requestor_clear(&requestor);
		return KNOT_ENOMEM;
	}

	int ret = knot_requestor_exec(&requestor, req, timeout);
	knot_request_free(req, NULL);
	knot_requestor_clear(&requestor);

	// alternative: we could put answer back through ctx instead of errcode
	if (ret == KNOT_EOK && !data.ds_ok) {
		ret = KNOT_ENORECORD;
	}

	if (ret != KNOT_EOK && !data.result_logged) {
		ns_log(LOG_WARNING, zone_name, LOG_OPERATION_PARENT,
		       LOG_DIRECTION_OUT, data.remote, "failed (%s)", knot_strerror(ret));
	}

	return ret;
}

static bool parents_have_ds(kdnssec_ctx_t *kctx, const knot_dname_t *zone_name, zone_key_t *key, size_t timeout)
{
	bool success = true;
	dynarray_foreach(parent, knot_kasp_parent_t, i, kctx->policy->parents) {
		if ((success = !success)) return false;
		for (size_t j = 0; j < i->addrs; j++) {
			int ret = try_ds(zone_name, &i->addr[j], key, timeout);
			if (ret == KNOT_EOK) {
				success = true;
				break;
			}
		}
	}
	return success;
}

int knot_parent_ds_query(kdnssec_ctx_t *kctx, zone_keyset_t *keyset, size_t timeout)
{
	for (size_t i = 0; i < keyset->count; i++) {
		zone_key_t *key = &keyset->keys[i];
		if (dnssec_key_get_flags(key->key) == DNSKEY_FLAGS_KSK &&
		    key->cds_priority > 1) {
			if (parents_have_ds(kctx, kctx->zone->dname, key, timeout)) {
				return knot_dnssec_ksk_sbm_confirm(kctx);
			} else {
				return KNOT_ENOENT;
			}
		}
	}
	return KNOT_ENOENT;
}

int event_parent_ds_q(conf_t *conf, zone_t *zone)
{
	kdnssec_ctx_t ctx = { 0 };

	int ret = kdnssec_ctx_init(conf, &ctx, zone->name, NULL);
	if (ret != KNOT_EOK) {
		return ret;
	}

	zone_keyset_t keyset = { 0 };
	ret = load_zone_keys(&ctx, &keyset, false);
	if (ret != KNOT_EOK) {
		kdnssec_ctx_deinit(&ctx);
		return ret;
	}

	ret = knot_parent_ds_query(&ctx, &keyset, conf->cache.srv_tcp_reply_timeout * 1000);

	zone->timers.next_parent_ds_q = 0;
	if (ret != KNOT_EOK) {
		if (ctx.policy->ksk_sbm_check_interval > 0) {
			time_t next_check = time(NULL) + ctx.policy->ksk_sbm_check_interval;
			zone->timers.next_parent_ds_q = next_check;
			zone_events_schedule_at(zone, ZONE_EVENT_PARENT_DS_Q, next_check);
		}
	} else {
		zone_events_schedule_now(zone, ZONE_EVENT_DNSSEC);
	}

	free_zone_keys(&keyset);
	kdnssec_ctx_deinit(&ctx);

	return KNOT_EOK; // allways ok, if failure it has been rescheduled
}
