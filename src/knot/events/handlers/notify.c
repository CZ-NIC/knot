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
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <assert.h>

#include "knot/common/log.h"
#include "knot/conf/conf.h"
#include "knot/query/query.h"
#include "knot/query/requestor.h"
#include "knot/zone/zone.h"
#include "libknot/errcode.h"

/*!
 * \brief NOTIFY message processing data.
 */
struct notify_data {
	const knot_dname_t *zone;
	const knot_rrset_t *soa;
	const struct sockaddr *remote;
	struct query_edns_data edns;
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

	query_put_edns(pkt, &data->edns);

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

#define NOTIFY_LOG(priority, zone, remote, fmt, ...) \
	ns_log(priority, zone, LOG_OPERATION_NOTIFY, LOG_DIRECTION_OUT, remote, \
	       fmt, ## __VA_ARGS__)

static int send_notify(conf_t *conf, zone_t *zone, const knot_rrset_t *soa,
                       const conf_remote_t *slave, int timeout)
{
	struct notify_data data = {
		.zone = zone->name,
		.soa = soa,
		.remote = (struct sockaddr *)&slave->addr,
	};

	query_edns_data_init(&data.edns, conf, zone->name, slave->addr.ss_family);

	struct knot_requestor requestor = { 0 };
	knot_requestor_init(&requestor, &NOTIFY_API, &data, NULL);

	knot_pkt_t *pkt = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, NULL);
	if (!pkt) {
		knot_requestor_clear(&requestor);
		return KNOT_ENOMEM;
	}

	const struct sockaddr *dst = (struct sockaddr *)&slave->addr;
	const struct sockaddr *src = (struct sockaddr *)&slave->via;
	struct knot_request *req = knot_request_make(NULL, dst, src, pkt, &slave->key, 0);
	if (!req) {
		knot_request_free(req, NULL);
		knot_requestor_clear(&requestor);
		return KNOT_ENOMEM;
	}

	int ret = knot_requestor_exec(&requestor, req, timeout);

	if (ret == KNOT_EOK) {
		NOTIFY_LOG(LOG_INFO, zone->name, dst,
			   "serial %u", knot_soa_serial(soa->rrs.rdata));
	} else if (knot_pkt_ext_rcode(req->resp) == 0) {
		NOTIFY_LOG(LOG_WARNING, zone->name, dst,
		           "failed (%s)", knot_strerror(ret));
	} else {
		NOTIFY_LOG(LOG_WARNING, zone->name, dst,
		           "server responded with error '%s'",
		           knot_pkt_ext_rcode_name(req->resp));
	}

	knot_request_free(req, NULL);
	knot_requestor_clear(&requestor);

	return ret;
}

int event_notify(conf_t *conf, zone_t *zone)
{
	assert(zone);

	if (zone_contents_is_empty(zone->contents)) {
		return KNOT_EOK;
	}

	// NOTIFY content
	int timeout = conf->cache.srv_tcp_reply_timeout * 1000;
	knot_rrset_t soa = node_rrset(zone->contents->apex, KNOT_RRTYPE_SOA);

	// send NOTIFY to each remote, use working address
	conf_val_t notify = conf_zone_get(conf, C_NOTIFY, zone->name);
	while (notify.code == KNOT_EOK) {
		conf_val_t addr = conf_id_get(conf, C_RMT, C_ADDR, &notify);
		size_t addr_count = conf_val_count(&addr);

		for (int i = 0; i < addr_count; i++) {
			conf_remote_t slave = conf_remote(conf, &notify, i);
			int ret = send_notify(conf, zone, &soa, &slave, timeout);
			if (ret == KNOT_EOK) {
				break;
			}
		}

		conf_val_next(&notify);
	}

	return KNOT_EOK;
}
