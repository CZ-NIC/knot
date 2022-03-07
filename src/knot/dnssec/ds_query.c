/*  Copyright (C) 2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "contrib/macros.h"
#include "knot/common/log.h"
#include "knot/conf/conf.h"
#include "knot/dnssec/ds_query.h"
#include "knot/dnssec/key-events.h"
#include "knot/query/layer.h"
#include "knot/query/query.h"
#include "knot/query/requestor.h"

static bool match_key_ds(knot_kasp_key_t *key, knot_rdata_t *ds)
{
	assert(key);
	assert(ds);

	dnssec_binary_t ds_rdata = {
		.size = ds->len,
		.data = ds->data,
	};

	dnssec_binary_t cds_rdata = { 0 };

	int ret = dnssec_key_create_ds(key->key, knot_ds_digest_type(ds), &cds_rdata);
	if (ret != KNOT_EOK) {
		return false;
	}

	ret = (dnssec_binary_cmp(&cds_rdata, &ds_rdata) == 0);
	dnssec_binary_free(&cds_rdata);
	return ret;
}

static bool match_key_ds_rrset(knot_kasp_key_t *key, const knot_rrset_t *rr)
{
	if (key == NULL) {
		return false;
	}
	knot_rdata_t *rd = rr->rrs.rdata;
	for (int i = 0; i < rr->rrs.count; i++) {
		if (match_key_ds(key, rd)) {
			return true;
		}
		rd = knot_rdataset_next(rd);
	}
	return false;
}

struct ds_query_data {
	conf_t *conf;

	const knot_dname_t *zone_name;
	const struct sockaddr *remote;

	knot_kasp_key_t *key;
	knot_kasp_key_t *not_key;

	query_edns_data_t edns;

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

	query_init_pkt(pkt);

	int r = knot_pkt_put_question(pkt, data->zone_name, KNOT_CLASS_IN, KNOT_RRTYPE_DS);
	if (r != KNOT_EOK) {
		return KNOT_STATE_FAIL;
	}

	r = query_put_edns(pkt, &data->edns);
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

	uint16_t rcode = knot_pkt_ext_rcode(pkt);
	if (rcode != KNOT_RCODE_NOERROR) {
		ns_log((rcode == KNOT_RCODE_NXDOMAIN ? LOG_NOTICE : LOG_WARNING),
		       data->zone_name, LOG_OPERATION_DS_CHECK,
		       LOG_DIRECTION_OUT, data->remote,
		       layer->flags & KNOT_REQUESTOR_REUSED,
		       "failed (%s)", knot_pkt_ext_rcode_name(pkt));
		return KNOT_STATE_FAIL;
	}

	const knot_pktsection_t *answer = knot_pkt_section(pkt, KNOT_ANSWER);

	bool match = false, match_not = false;

	for (size_t j = 0; j < answer->count; j++) {
		const knot_rrset_t *rr = knot_pkt_rr(answer, j);
		switch ((rr && rr->rrs.count > 0) ? rr->type : 0) {
		case KNOT_RRTYPE_DS:
			if (match_key_ds_rrset(data->key, rr)) {
				match = true;
				if (data->ttl == 0) { // fallback: if there is no RRSIG
					data->ttl = rr->ttl;
				}
			}
			if (match_key_ds_rrset(data->not_key, rr)) {
				match_not = true;
			}
			break;
		case KNOT_RRTYPE_RRSIG:
			data->ttl = knot_rrsig_original_ttl(rr->rrs.rdata);
			break;
		default:
			break;
		}
	}

	if (match_not) {
		match = false;
	}

	ns_log(LOG_INFO, data->zone_name, LOG_OPERATION_DS_CHECK,
	       LOG_DIRECTION_OUT, data->remote, layer->flags & KNOT_REQUESTOR_REUSED,
	       "KSK submission check: %s", (match ? "positive" : "negative"));

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

static int try_ds(conf_t *conf, const knot_dname_t *zone_name, const conf_remote_t *parent,
                  knot_kasp_key_t *key, knot_kasp_key_t *not_key, size_t timeout, uint32_t *ds_ttl)
{
	// TODO: Abstract interface to issue DNS queries. This is almost copy-pasted.

	assert(zone_name);
	assert(parent);

	struct ds_query_data data = {
		.zone_name = zone_name,
		.remote = (struct sockaddr *)&parent->addr,
		.key = key,
		.not_key = not_key,
		.edns = query_edns_data_init(conf, parent->addr.ss_family,
		                             QUERY_EDNS_OPT_DO),
		.ds_ok = false,
		.result_logged = false,
		.ttl = 0,
	};

	knot_requestor_t requestor;
	knot_requestor_init(&requestor, &ds_query_api, &data, NULL);

	knot_pkt_t *pkt = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, NULL);
	if (!pkt) {
		knot_requestor_clear(&requestor);
		return KNOT_ENOMEM;
	}

	const struct sockaddr_storage *dst = &parent->addr;
	const struct sockaddr_storage *src = &parent->via;
	knot_request_t *req = knot_request_make(NULL, dst, src, pkt, &parent->key, 0);
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
		ns_log(LOG_WARNING, zone_name, LOG_OPERATION_DS_CHECK,
		       LOG_DIRECTION_OUT, data.remote,
		       requestor.layer.flags & KNOT_REQUESTOR_REUSED,
		       "failed (%s)", knot_strerror(ret));
	}

	*ds_ttl = data.ttl;

	return ret;
}

static knot_kasp_key_t *get_not_key(kdnssec_ctx_t *kctx, knot_kasp_key_t *key)
{
	knot_kasp_key_t *not_key = knot_dnssec_key2retire(kctx, key);

	if (not_key == NULL || dnssec_key_get_algorithm(not_key->key) == dnssec_key_get_algorithm(key->key)) {
		return NULL;
	}

	return not_key;
}

static bool parents_have_ds(conf_t *conf, kdnssec_ctx_t *kctx, knot_kasp_key_t *key,
                            size_t timeout, uint32_t *max_ds_ttl)
{
	bool success = false;
	knot_dynarray_foreach(parent, knot_kasp_parent_t, i, kctx->policy->parents) {
		success = false;
		for (size_t j = 0; j < i->addrs; j++) {
			uint32_t ds_ttl = 0;
			int ret = try_ds(conf, kctx->zone->dname, &i->addr[j], key,
			                 get_not_key(kctx, key), timeout, &ds_ttl);
			if (ret == KNOT_EOK) {
				*max_ds_ttl = MAX(*max_ds_ttl, ds_ttl);
				success = true;
				break;
			} else if (ret == KNOT_ENORECORD) {
				// parent was queried successfully, answer was negative
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

int knot_parent_ds_query(conf_t *conf, kdnssec_ctx_t *kctx, size_t timeout)
{
	uint32_t max_ds_ttl = 0;

	for (size_t i = 0; i < kctx->zone->num_keys; i++) {
		knot_kasp_key_t *key = &kctx->zone->keys[i];
		if (!key->is_pub_only &&
		    knot_time_cmp(key->timing.ready, kctx->now) <= 0 &&
		    knot_time_cmp(key->timing.active, kctx->now) > 0) {
			assert(key->is_ksk);
			if (parents_have_ds(conf, kctx, key, timeout, &max_ds_ttl)) {
				return knot_dnssec_ksk_sbm_confirm(kctx, max_ds_ttl + kctx->policy->ksk_sbm_delay);
			} else {
				return KNOT_ENOENT;
			}
		}
	}
	return KNOT_NO_READY_KEY;
}
