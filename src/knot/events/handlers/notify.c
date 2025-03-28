/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <assert.h>
#include <urcu.h>

#include "contrib/openbsd/siphash.h"
#include "knot/common/log.h"
#include "knot/conf/conf.h"
#include "knot/query/query.h"
#include "knot/query/requestor.h"
#include "knot/server/server.h"
#include "knot/zone/zone.h"
#include "libknot/errcode.h"

static notifailed_rmt_hash notifailed_hash(conf_val_t *rmt_id)
{
	SIPHASH_KEY zero_key = { 0, 0 };
	SIPHASH_CTX ctx;
	SipHash24_Init(&ctx, &zero_key);
	SipHash24_Update(&ctx, rmt_id->data, rmt_id->len);
	return SipHash24_End(&ctx);
}

/*!
 * \brief NOTIFY message processing data.
 */
struct notify_data {
	const knot_dname_t *zone;
	const knot_rrset_t *soa;
	const conf_remote_t *remote;
	query_edns_data_t edns;
};

static int notify_begin(knot_layer_t *layer, void *params)
{
	layer->data = params;

	return KNOT_STATE_PRODUCE;
}

static int notify_produce(knot_layer_t *layer, knot_pkt_t *pkt)
{
	struct notify_data *data = layer->data;

	// mandatory: NOTIFY opcode, AA flag, SOA qtype
	query_init_pkt(pkt);
	knot_wire_set_opcode(pkt->wire, KNOT_OPCODE_NOTIFY);
	knot_wire_set_aa(pkt->wire);
	knot_pkt_put_question(pkt, data->zone, KNOT_CLASS_IN, KNOT_RRTYPE_SOA);

	// unsecure hint: new SOA
	if (data->soa) {
		knot_pkt_begin(pkt, KNOT_ANSWER);
		knot_pkt_put(pkt, KNOT_COMPR_HINT_QNAME, data->soa, 0);
	}

	return KNOT_STATE_CONSUME;
}

static int notify_consume(knot_layer_t *layer, knot_pkt_t *pkt)
{
	return KNOT_STATE_DONE;
}

static const knot_layer_api_t NOTIFY_API = {
	.begin = notify_begin,
	.produce = notify_produce,
	.consume = notify_consume,
};

#define NOTIFY_OUT_LOG(priority, zone, remote, flags, fmt, ...) \
	ns_log(priority, zone, LOG_OPERATION_NOTIFY, LOG_DIRECTION_OUT, &(remote)->addr, \
	       flags2proto(flags), ((flags) & KNOT_REQUESTOR_REUSED), (remote)->key.name, \
	       fmt, ## __VA_ARGS__)

static int send_notify(conf_t *conf, zone_t *zone, const knot_rrset_t *soa,
                       const conf_remote_t *slave, int timeout, bool retry)
{
	struct notify_data data = {
		.zone = zone->name,
		.soa = soa,
		.remote = slave,
		.edns = query_edns_data_init(conf, slave, 0)
	};

	knot_requestor_t requestor;
	knot_requestor_init(&requestor, &NOTIFY_API, &data, NULL);

	knot_pkt_t *pkt = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, NULL);
	if (pkt == NULL) {
		knot_requestor_clear(&requestor);
		return KNOT_ENOMEM;
	}

	knot_request_flag_t flags = conf->cache.srv_tcp_fastopen ? KNOT_REQUEST_TFO : 0;
	knot_request_t *req = knot_request_make(NULL, slave, pkt,
	                                        zone->server->quic_creds, &data.edns, flags);
	if (req == NULL) {
		knot_requestor_clear(&requestor);
		return KNOT_ENOMEM;
	}

	int ret = knot_requestor_exec(&requestor, req, timeout);

	const char *log_retry = retry ? "retry, " : "";

	if (ret == KNOT_EOK && knot_pkt_ext_rcode(req->resp) == 0) {
		NOTIFY_OUT_LOG(LOG_INFO, zone->name, slave,
		               requestor.layer.flags,
		               "%sserial %u", log_retry, knot_soa_serial(soa->rrs.rdata));
		zone->timers.last_notified_serial = (knot_soa_serial(soa->rrs.rdata) | LAST_NOTIFIED_SERIAL_VALID);
	} else if (knot_pkt_ext_rcode(req->resp) == 0) {
		NOTIFY_OUT_LOG(LOG_WARNING, zone->name, slave,
		               requestor.layer.flags,
		               "%sfailed (%s)", log_retry, knot_strerror(ret));
	} else {
		NOTIFY_OUT_LOG(LOG_WARNING, zone->name, slave,
		               requestor.layer.flags,
		               "%sserver responded with error '%s'",
		               log_retry, knot_pkt_ext_rcode_name(req->resp));
	}

	knot_request_free(req, NULL);
	knot_requestor_clear(&requestor);

	return ret;
}

int event_notify(conf_t *conf, zone_t *zone)
{
	assert(zone);

	bool failed = false;

	if (zone_contents_is_empty(zone->contents)) {
		return KNOT_EOK;
	}

	// NOTIFY content
	int timeout = conf->cache.srv_tcp_remote_io_timeout;
	rcu_read_lock();
	knot_rrset_t soa = node_rrset(zone->contents->apex, KNOT_RRTYPE_SOA);
	knot_rrset_t *soa_cpy = knot_rrset_copy(&soa, NULL);
	rcu_read_unlock();
	if (soa_cpy == NULL) {
		return KNOT_ENOMEM;
	}

	// in case of re-try, NOTIFY only failed remotes
	pthread_mutex_lock(&zone->preferred_lock);
	bool retry = (zone->notifailed.size > 0);

	// send NOTIFY to each remote, use working address
	conf_val_t notify = conf_zone_get(conf, C_NOTIFY, zone->name);
	conf_mix_iter_t iter;
	conf_mix_iter_init(conf, &notify, &iter);
	while (iter.id->code == KNOT_EOK) {
		notifailed_rmt_hash rmt_hash = notifailed_hash(iter.id);
		if (retry && notifailed_rmt_dynarray_bsearch(&zone->notifailed, &rmt_hash) == NULL) {
			conf_mix_iter_next(&iter);
			continue;
		}
		pthread_mutex_unlock(&zone->preferred_lock);

		conf_val_t addr = conf_id_get(conf, C_RMT, C_ADDR, iter.id);
		size_t addr_count = conf_val_count(&addr);

		int ret = KNOT_EOK;

		for (int i = 0; i < addr_count; i++) {
			conf_remote_t slave = conf_remote(conf, iter.id, i);
			ret = send_notify(conf, zone, soa_cpy, &slave, timeout, retry);
			if (ret == KNOT_EOK) {
				break;
			}
		}

		pthread_mutex_lock(&zone->preferred_lock);
		if (ret != KNOT_EOK) {
			failed = true;
			if (!retry) {
				notifailed_rmt_dynarray_add(&zone->notifailed, &rmt_hash);
			}
		} else {
			notifailed_rmt_dynarray_remove(&zone->notifailed, &rmt_hash);
			notifailed_rmt_dynarray_sort(&zone->notifailed);
		}

		conf_mix_iter_next(&iter);
	}

	if (failed) {
		notifailed_rmt_dynarray_sort_dedup(&zone->notifailed);

		uint32_t retry_in = knot_soa_retry(soa_cpy->rrs.rdata);
		conf_val_t val = conf_zone_get(conf, C_RETRY_MIN_INTERVAL, zone->name);
		retry_in = MAX(retry_in, conf_int(&val));
		val = conf_zone_get(conf, C_RETRY_MAX_INTERVAL, zone->name);
		retry_in = MIN(retry_in, conf_int(&val));

		zone_events_schedule_at(zone, ZONE_EVENT_NOTIFY, time(NULL) + retry_in);
	}
	pthread_mutex_unlock(&zone->preferred_lock);
	knot_rrset_free(soa_cpy, NULL);

	return failed ? KNOT_ERROR : KNOT_EOK;
}
