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

#include <unistd.h>

#include "knot/dnssec/zone-events.h"
#include "knot/nameserver/internet.h"
#include "knot/nameserver/update.h"
#include "knot/query/requestor.h"
#include "libknot/libknot.h"

static int update_enqueue(zone_t *zone, knotd_qdata_t *qdata)
{
	assert(zone);
	assert(qdata);

	/* Create serialized request. */
	knot_request_t *req = calloc(1, sizeof(*req));
	if (req == NULL) {
		return KNOT_ENOMEM;
	}

	/* Store socket and remote address. */
	req->fd = dup(qdata->params->socket);
	memcpy(&req->remote, knotd_qdata_remote_addr(qdata), sizeof(req->remote));

	/* Store update request. */
	req->query = knot_pkt_new(NULL, qdata->query->max_size, NULL);
	int ret = knot_pkt_copy(req->query, qdata->query);
	if (ret != KNOT_EOK) {
		knot_pkt_free(req->query);
		free(req);
		return ret;
	}

	/* Store and update possible TSIG context (see NS_NEED_AUTH). */
	if (qdata->sign.tsig_key.name != NULL) {
		req->sign = qdata->sign;
		req->sign.tsig_digest = (uint8_t *)knot_tsig_rdata_mac(req->query->tsig_rr);
		req->sign.tsig_key.name = req->query->tsig_rr->owner;
		ret = dnssec_binary_dup(&qdata->sign.tsig_key.secret, &req->sign.tsig_key.secret);
		if (ret != KNOT_EOK) {
			knot_pkt_free(req->query);
			free(req);
			return ret;
		}
		assert(req->sign.tsig_digestlen == knot_tsig_rdata_mac_length(req->query->tsig_rr));
		assert(req->sign.tsig_key.algorithm == knot_tsig_rdata_alg(req->query->tsig_rr));
	}

	pthread_mutex_lock(&zone->ddns_lock);

	/* Enqueue created request. */
	ptrlist_add(&zone->ddns_queue, req, NULL);
	++zone->ddns_queue_size;

	pthread_mutex_unlock(&zone->ddns_lock);

	/* Schedule UPDATE event. */
	zone_events_schedule_now(zone, ZONE_EVENT_UPDATE);

	return KNOT_EOK;
}

int update_process_query(knot_pkt_t *pkt, knotd_qdata_t *qdata)
{
	/* DDNS over XDP not supported. */
	if (qdata->params->xdp_msg != NULL) {
		qdata->rcode = KNOT_RCODE_SERVFAIL;
		return KNOT_STATE_FAIL;
	}

	/* RFC1996 require SOA question. */
	NS_NEED_QTYPE(qdata, KNOT_RRTYPE_SOA, KNOT_RCODE_FORMERR);

	/* Check valid zone. */
	NS_NEED_ZONE(qdata, KNOT_RCODE_NOTAUTH);

	/* Need valid transaction security. */
	NS_NEED_AUTH(qdata, ACL_ACTION_UPDATE);
	/* Check expiration. */
	NS_NEED_ZONE_CONTENTS(qdata);
	/* Check frozen zone. */
	NS_NEED_NOT_FROZEN(qdata);

	/* Store update into DDNS queue. */
	int ret = update_enqueue((zone_t *)qdata->extra->zone, qdata);
	if (ret != KNOT_EOK) {
		return KNOT_STATE_FAIL;
	}

	/* No immediate response. */
	return KNOT_STATE_NOOP;
}
