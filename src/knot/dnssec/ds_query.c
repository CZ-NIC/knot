/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "contrib/macros.h"
#include "knot/common/log.h"
#include "knot/conf/conf.h"
#include "knot/dnssec/ds_query.h"
#include "knot/dnssec/key-events.h"
#include "knot/query/layer.h"
#include "knot/query/query.h"
#include "knot/query/requestor.h"

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

	uint16_t edns_max_payload;

	bool ds_ok;
	bool result_logged;

	uint32_t ttl;
};

static int ds_query_begin(knot_layer_t *layer, void *params)
{
	layer->data = params;

	return KNOT_STATE_PRODUCE;
}

static int ds_query_produce(knot_layer_t *layer, knot_pkt_t *pkt)
{
	struct ds_query_data *data = layer->data;
	struct query_edns_data edns = { .max_payload = data->edns_max_payload, .do_flag = true, };

	query_init_pkt(pkt);

	int r = knot_pkt_put_question(pkt, data->zone_name, KNOT_CLASS_IN, KNOT_RRTYPE_DS);
	if (r != KNOT_EOK) {
		return KNOT_STATE_FAIL;
	}

	r = query_put_edns(pkt, &edns);
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
		switch ((rr && rr->rrs.count > 0) ? rr->type : 0) {
		case KNOT_RRTYPE_DS:
			if (match_key_ds(data->key, rr->rrs.rdata)) {
				match = true;
				if (data->ttl == 0) { // fallback: if there is no RRSIG
					data->ttl = rr->ttl;
				}
			}
			break;
		case KNOT_RRTYPE_RRSIG:
			data->ttl = knot_rrsig_original_ttl(rr->rrs.rdata);
			break;
		default:
			break;
		}
	}

	ns_log(LOG_INFO, data->zone_name, LOG_OPERATION_PARENT,
	       LOG_DIRECTION_OUT, data->remote, "KSK submission attempt: %s",
	       (match ? "positive" : "negative"));

	if (match) {
		data->ds_ok = true;
	}
	return KNOT_STATE_DONE;
}

static const knot_layer_api_t ds_query_api = {
	.begin = ds_query_begin,
	.produce = ds_query_produce,
	.consume = ds_query_consume,
	.reset = NULL,
	.finish = NULL,
};

static int try_ds(const knot_dname_t *zone_name, const conf_remote_t *parent, zone_key_t *key,
                  size_t timeout, uint32_t *ds_ttl)
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
		.ttl = 0,
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

	data.edns_max_payload = dst->sa_family == AF_INET6 ?
	                        conf()->cache.srv_max_ipv6_udp_payload :
	                        conf()->cache.srv_max_ipv4_udp_payload;

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

	*ds_ttl = data.ttl;

	return ret;
}

static bool parents_have_ds(kdnssec_ctx_t *kctx, zone_key_t *key, size_t timeout,
                            uint32_t *max_ds_ttl)
{
	bool success = false;
	dynarray_foreach(parent, knot_kasp_parent_t, i, kctx->policy->parents) {
		success = false;
		for (size_t j = 0; j < i->addrs; j++) {
			uint32_t ds_ttl = 0;
			int ret = try_ds(kctx->zone->dname, &i->addr[j], key, timeout, &ds_ttl);
			if (ret == KNOT_EOK) {
				*max_ds_ttl = MAX(*max_ds_ttl, ds_ttl);
				success = true;
				break;
			}
		}
		// Each parent must succeed.
		if (!success) {
			return false;
		}
	}
	return success;
}

int knot_parent_ds_query(kdnssec_ctx_t *kctx, zone_keyset_t *keyset, size_t timeout)
{
	uint32_t max_ds_ttl = 0;

	for (size_t i = 0; i < keyset->count; i++) {
		zone_key_t *key = &keyset->keys[i];
		if (key->is_ksk && key->cds_priority > 1) {
			if (parents_have_ds(kctx, key, timeout, &max_ds_ttl)) {
				return knot_dnssec_ksk_sbm_confirm(kctx, max_ds_ttl);
			} else {
				return KNOT_ENOENT;
			}
		}
	}
	return KNOT_ENOENT;
}
