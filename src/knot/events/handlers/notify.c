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
	const struct sockaddr_storage *remote;
	uint16_t response_rcode;
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
	struct notify_data *data = layer->data;

	data->response_rcode = knot_pkt_get_ext_rcode(pkt);
	if (data->response_rcode != KNOT_RCODE_NOERROR) {
		return KNOT_STATE_FAIL;
	}

	return KNOT_STATE_DONE;
}

static const knot_layer_api_t NOTIFY_API = {
	.begin = notify_begin,
	.produce = notify_produce,
	.consume = notify_consume,
};

static int send_notify(zone_t *zone, const knot_rrset_t *soa,
                       const conf_remote_t *slave, int timeout, uint16_t *rcode)
{
	struct notify_data data = {
		.zone = zone->name,
		.soa = soa,
		.remote = &slave->addr,
	};

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
	knot_request_free(req, NULL);
	knot_requestor_clear(&requestor);

	*rcode = data.response_rcode;

	return ret;
}

#define NOTIFY_LOG(priority, zone, remote, fmt, ...) \
	ns_log(priority, zone, LOG_OPERATION_NOTIFY, LOG_DIRECTION_OUT, remote, \
	       fmt, ## __VA_ARGS__)

static void log_notify_result(int ret, uint16_t rcode, const knot_dname_t *zone,
                              const struct sockaddr_storage *_remote, uint32_t serial)
{
	const struct sockaddr *remote = (struct sockaddr *)_remote;

	if (ret == KNOT_EOK) {
		NOTIFY_LOG(LOG_INFO, zone, remote, "serial %u", serial);
	} else if (rcode == 0) {
		NOTIFY_LOG(LOG_WARNING, zone, remote, "failed (%s)", knot_strerror(ret));
	} else {
		const knot_lookup_t *lut = knot_lookup_by_id(knot_rcode_names, rcode);
		if (lut) {
			NOTIFY_LOG(LOG_WARNING, zone, remote, "server responded with %s", lut->name);
		} else {
			NOTIFY_LOG(LOG_WARNING, zone, remote, "server responded with RCODE %u", rcode);
		}
	}
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
	uint32_t serial = zone_contents_serial(zone->contents);

	// send NOTIFY to each remote, use working address
	conf_val_t notify = conf_zone_get(conf, C_NOTIFY, zone->name);
	while (notify.code == KNOT_EOK) {
		conf_val_t addr = conf_id_get(conf, C_RMT, C_ADDR, &notify);
		size_t addr_count = conf_val_count(&addr);

		for (int i = 0; i < addr_count; i++) {
			uint16_t rcode = 0;
			conf_remote_t slave = conf_remote(conf, &notify, i);
			int ret = send_notify(zone, &soa, &slave, timeout, &rcode);
			log_notify_result(ret, rcode, zone->name, &slave.addr, serial);
			if (ret == KNOT_EOK) {
				break;
			}
		}

		conf_val_next(&notify);
	}

	return KNOT_EOK;
}
