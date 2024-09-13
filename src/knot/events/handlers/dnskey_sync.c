/*  Copyright (C) 2024 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include "knot/server/server.h"
#include "knot/zone/zone.h"
#include "libdnssec/keytag.h"
#include "libknot/errcode.h"

#define DNSKEY_SYNC_LOG(priority, zone, remote, flags, fmt, ...) \
	ns_log(priority, zone, LOG_OPERATION_DNSKEY_SYNC, LOG_DIRECTION_OUT, &(remote)->addr, \
	       flags2proto(flags), ((flags) & KNOT_REQUESTOR_REUSED), (remote)->key.name, \
	       fmt, ## __VA_ARGS__)

static const unsigned remote_rrs[] = { KNOT_RRTYPE_DNSKEY, KNOT_RRTYPE_CDNSKEY, KNOT_RRTYPE_CDS };
#define REMOTE_NTYPES (sizeof(remote_rrs) / sizeof(remote_rrs[0]))

struct dnskey_sync_data {
	zone_t *zone;
	knot_rrset_t *rem_rr[REMOTE_NTYPES];
	knot_rrset_t *add_rr[REMOTE_NTYPES];
	const conf_remote_t *remote;
	query_edns_data_t edns;
	bool uptodate;
	bool ddns_sent;
};

static void log_upd(struct dnskey_sync_data *data)
{
	char buf[512], type_buf[16] = { 0 };
	wire_ctx_t w = wire_ctx_init((uint8_t *)buf, sizeof(buf));
	for (int i = 0; i < REMOTE_NTYPES; i++) {
		knot_rrtype_to_string(remote_rrs[i], type_buf, sizeof(type_buf));
		wire_ctx_printf(&w, ", %ss +%hu/-%hu", type_buf, data->add_rr[i]->rrs.count,
		                                                 data->rem_rr[i]->rrs.count);
		if (remote_rrs[i] == KNOT_RRTYPE_DNSKEY) {
			bool bracket = false, rem_part = false;
			knot_rdata_t *dnskey = data->add_rr[i]->rrs.rdata;
			for (int j = 0; !rem_part || j < data->rem_rr[i]->rrs.count; j++) {
				if (!rem_part && j >= data->add_rr[i]->rrs.count) {
					dnskey = data->rem_rr[i]->rrs.rdata;
					rem_part = true;
					j = -1;
					continue;
				}
				uint16_t keytag;
				const dnssec_binary_t bin = {
					.size = dnskey->len, .data = dnskey->data
				};
				if (dnssec_keytag(&bin, &keytag) != 0) {
					continue;
				}
				wire_ctx_printf(&w, " %s%c%d", bracket ? "" : "(",
				                rem_part ? '-' : '+', keytag);
				bracket = true;

				dnskey = knot_rdataset_next(dnskey);
			}
			if (bracket) {
				wire_ctx_printf(&w, ")");
			}
		}
	}
	if (w.error == KNOT_EOK) {
		// intentionally not DNSKEY_SYNC_LOG to save space on log line
		log_zone_info(data->zone->name, "DNSKEY sync%s", buf);
	}
}

static int next_query(struct dnskey_sync_data *data, int *idx)
{
	for (int i = 0; i < REMOTE_NTYPES; i++) {
		if (data->rem_rr[i] == NULL) {
			*idx = i;
			return remote_rrs[i];
		}
	}
	*idx = -1;
	return KNOT_RRTYPE_ANY;
}

static int dnskey_sync_begin(knot_layer_t *layer, void *params)
{
	layer->data = params;

	return KNOT_STATE_PRODUCE;
}

static int query_put_ddns(struct dnskey_sync_data *data, knot_pkt_t *pkt)
{
	int ret = KNOT_EOK;
	knot_wire_set_opcode(pkt->wire, KNOT_OPCODE_UPDATE);
	knot_pkt_begin(pkt, KNOT_AUTHORITY);

	for (int i = 0; i < REMOTE_NTYPES && ret == KNOT_EOK; i++) {
		ret = knot_pkt_put(pkt, KNOT_COMPR_HINT_NONE, data->rem_rr[i], 0);
		if (ret == KNOT_EOK) {
			ret = knot_pkt_put(pkt, KNOT_COMPR_HINT_NONE, data->add_rr[i], 0);
		}
	}

	return ret;
}

static int dnskey_sync_produce(knot_layer_t *layer, knot_pkt_t *pkt)
{
	struct dnskey_sync_data *data = layer->data;

	query_init_pkt(pkt);

	int unused, next = next_query(data, &unused);
	int ret = knot_pkt_put_question(pkt, data->zone->name, KNOT_CLASS_IN,
	                                next == KNOT_RRTYPE_ANY ? KNOT_RRTYPE_SOA : next);

	if (next == KNOT_RRTYPE_ANY && ret == KNOT_EOK) {
		ret = query_put_ddns(data, pkt);
	}

	if (ret != KNOT_EOK) {
		DNSKEY_SYNC_LOG(LOG_WARNING, data->zone->name, data->remote, layer->flags,
		                "failed to prepare update (%s)", knot_strerror(ret));
		return KNOT_STATE_FAIL;
	}

	if (next == KNOT_RRTYPE_ANY && ret == KNOT_EOK) {
		data->ddns_sent = true;
		log_upd(data);
	}

	return KNOT_STATE_CONSUME;
}

static int compute_rem_add(struct dnskey_sync_data *data, int idx)
{
	assert(data->rem_rr[idx] != NULL);

	knot_rrset_t zone_rr = node_rrset(data->zone->contents->apex, remote_rrs[idx]);
	if (!knot_rrset_empty(&zone_rr)) {
		data->add_rr[idx] = knot_rrset_copy(&zone_rr, NULL);
	} else {
		data->add_rr[idx] = knot_rrset_new(data->zone->name, remote_rrs[idx], KNOT_CLASS_IN, 0, NULL);
	}
	if (data->add_rr[idx] == NULL) {
		return KNOT_ENOMEM;
	}

	knot_rdataset_t tmp = { 0 };
	int ret = knot_rdataset_intersect(&data->add_rr[idx]->rrs, &data->rem_rr[idx]->rrs, &tmp, NULL);
	if (ret == KNOT_EOK) {
		ret = knot_rdataset_subtract(&data->rem_rr[idx]->rrs, &tmp, NULL);
	}
	if (ret == KNOT_EOK) {
		ret = knot_rdataset_subtract(&data->add_rr[idx]->rrs, &tmp, NULL);
	}
	knot_rdataset_clear(&tmp, NULL);

	return ret;
}

static int queries_evaluate(struct dnskey_sync_data *data, int layer_flags)
{
	int ret = KNOT_EOK, nonempty = 0;
	for (int i = 0; i < REMOTE_NTYPES && ret == KNOT_EOK; i++) {
		if (data->rem_rr[i] == NULL) {
			return KNOT_STATE_PRODUCE; // produce query for remote_rrs[i] type
		}
		if (data->add_rr[i] == NULL) {
			ret = compute_rem_add(data, i);
		}
		if (!knot_rrset_empty(data->rem_rr[i]) || !knot_rrset_empty(data->add_rr[i])) {
			nonempty = 1;
		}
	}

	if (ret == KNOT_EOK) {
		if (nonempty) {
			return KNOT_STATE_PRODUCE; // produce final DDNS
		} else {
			DNSKEY_SYNC_LOG(LOG_INFO, data->zone->name, data->remote, layer_flags,
			                "remote is up-to-date");
			data->uptodate = true;
			return KNOT_STATE_DONE;
		}
	} else {
		DNSKEY_SYNC_LOG(LOG_WARNING, data->zone->name, data->remote, layer_flags,
		                "failed (%s)", knot_strerror(ret));
		return KNOT_STATE_FAIL;
	}
}

static int dnskey_sync_consume(knot_layer_t *layer, knot_pkt_t *pkt)
{
	struct dnskey_sync_data *data = layer->data;
	int idx, next = next_query(data, &idx);

	if (next == KNOT_RRTYPE_ANY) { // consuming result of the final DDNS
		int rc = knot_pkt_ext_rcode(pkt);
		if (rc == KNOT_RCODE_NOERROR) {
			DNSKEY_SYNC_LOG(LOG_INFO, data->zone->name, data->remote, layer->flags,
			                "finished");
			return KNOT_STATE_DONE;
		} else {
			const knot_lookup_t *rcode = knot_lookup_by_id(knot_rcode_names, rc);
			DNSKEY_SYNC_LOG(LOG_ERR, data->zone->name, data->remote, layer->flags,
			                "remote responded with rcode %s",
			                (rcode != NULL) ? rcode->name : "Unknown");
			return KNOT_STATE_FAIL;
		}
	}
	assert(idx >= 0);

	data->rem_rr[idx] = knot_rrset_new(data->zone->name, next, KNOT_CLASS_NONE, 0, NULL);
	if (data->rem_rr[idx] == NULL || knot_pkt_qtype(pkt) != next) {
		char rrtext[64] = { 0 };
		knot_rrtype_to_string(next, rrtext, sizeof(rrtext));
		DNSKEY_SYNC_LOG(LOG_ERR, data->zone->name, data->remote, layer->flags,
		                "failed to obtain %s record", rrtext);
		return KNOT_STATE_FAIL;
	}

	const knot_pktsection_t *s = knot_pkt_section(pkt, KNOT_ANSWER);
	for (int j = 0; j < s->count; j++) {
		const knot_rrset_t *rr = knot_pkt_rr(s, j);
		if (rr->type == next && knot_dname_is_case_equal(rr->owner, data->zone->name)) {
			(void)knot_rdataset_merge(&data->rem_rr[idx]->rrs, &rr->rrs, NULL);
		}
	}

	int state = queries_evaluate(data, layer->flags);
	return (state == KNOT_STATE_PRODUCE ? KNOT_STATE_RESET : state);
}

static int dnskey_sync_reset(knot_layer_t *layer)
{
	(void)layer;
	return KNOT_STATE_PRODUCE;
}

static int dnskey_sync_finish(knot_layer_t *layer)
{
	struct dnskey_sync_data *data = layer->data;
	for (int i = 0; i < REMOTE_NTYPES; i++) {
		knot_rrset_free(data->rem_rr[i], NULL);
		knot_rrset_free(data->add_rr[i], NULL);
		data->rem_rr[i] = NULL;
		data->add_rr[i] = NULL;
	}
	return layer->state;
}

static const knot_layer_api_t DNSKEY_SYNC_API = {
	.begin = dnskey_sync_begin,
	.produce = dnskey_sync_produce,
	.reset = dnskey_sync_reset,
	.consume = dnskey_sync_consume,
	.finish = dnskey_sync_finish,
};

static int send_dnskey_sync(conf_t *conf, zone_t *zone, bool *uptodate,
                            const conf_remote_t *remote, int timeout)
{
	struct dnskey_sync_data data = {
		.zone = zone,
		.remote = remote,
		.edns = query_edns_data_init(conf, remote, 0)
	};

	knot_requestor_t requestor;
	knot_requestor_init(&requestor, &DNSKEY_SYNC_API, &data, NULL);

	knot_pkt_t *pkt = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, NULL);
	if (pkt == NULL) {
		knot_requestor_clear(&requestor);
		*uptodate = false;
		return KNOT_ENOMEM;
	}

	knot_request_t *req = knot_request_make(NULL, remote, pkt,
	                                        zone->server->quic_creds, &data.edns, 0);
	if (req == NULL) {
		knot_requestor_clear(&requestor);
		*uptodate = false;
		return KNOT_ENOMEM;
	}

	int ret = knot_requestor_exec(&requestor, req, timeout);

	if (!data.uptodate || ret != KNOT_EOK) {
		*uptodate = false;
	}

	if (data.ddns_sent && ret == KNOT_ETIMEOUT) {
		DNSKEY_SYNC_LOG(LOG_WARNING, zone->name, remote, requestor.layer.flags,
		                "timed out, may be caused by parallel mutual DNSKEY sync, "
		                "may settle down after check-interval");
		ret = KNOT_EOK;
	}

	if (ret != KNOT_EOK) {
		DNSKEY_SYNC_LOG(LOG_ERR, zone->name, remote, requestor.layer.flags,
		                "failed (%s)", knot_strerror(ret));
	}

	knot_request_free(req, NULL);
	knot_requestor_clear(&requestor);

	return ret;
}

int event_dnskey_sync(conf_t *conf, zone_t *zone)
{
	assert(zone);

	if (zone_contents_is_empty(zone->contents)) {
		return KNOT_EOK;
	}

	int timeout = conf->cache.srv_tcp_remote_io_timeout;

	conf_val_t policy_id = conf_zone_get(conf, C_DNSSEC_POLICY, zone->name);
	conf_id_fix_default(&policy_id);
	conf_val_t dnskey_sync = conf_id_get(conf, C_POLICY, C_DNSKEY_SYNC, &policy_id);
	if (dnskey_sync.code != KNOT_EOK) {
		return KNOT_EOK;
	}
	conf_val_t rmt = conf_id_get(conf, C_DNSKEY_SYNC, C_RMT, &dnskey_sync);

	bool uptodate = true;
	conf_mix_iter_t iter;
	conf_mix_iter_init(conf, &rmt, &iter);
	while (iter.id->code == KNOT_EOK) {
		conf_val_t addr = conf_id_get(conf, C_RMT, C_ADDR, iter.id);
		size_t addr_count = conf_val_count(&addr);

		for (int i = 0; i < addr_count; i++) {
			conf_remote_t parent = conf_remote(conf, iter.id, i);
			int ret = send_dnskey_sync(conf, zone, &uptodate, &parent, timeout);
			if (ret == KNOT_EOK) {
				break;
			}
		}

		conf_mix_iter_next(&iter);
	}

	if (!uptodate) {
		conf_val_t interval = conf_id_get(conf, C_DNSKEY_SYNC, C_CHK_INTERVAL,
		                                  &dnskey_sync);
		time_t next_sync = time(NULL) + conf_int(&interval);
		zone_events_schedule_at(zone, ZONE_EVENT_DNSKEY_SYNC, next_sync);
	}

	return KNOT_EOK;
}
