/*  Copyright (C) 2025 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include "contrib/sockaddr.h"
#include "libknot/libknot.h"
#include "libknot/quic/quic_conn.h"
#include "libknot/quic/tls.h"

static int update_enqueue(zone_t *zone, knotd_qdata_t *qdata)
{
	assert(zone);
	assert(qdata);

	pthread_mutex_lock(&zone->ddns_lock);
	if (zone->events.ufrozen && zone->ddns_queue_size >= 8) {
		pthread_mutex_unlock(&zone->ddns_lock);
		qdata->rcode = KNOT_RCODE_REFUSED;
		qdata->rcode_ede = KNOT_EDNS_EDE_NOT_READY;
		return KNOT_ELIMIT;
	}
	pthread_mutex_unlock(&zone->ddns_lock);

	/* Create serialized request. */
	knot_request_t *req = calloc(1, sizeof(*req));
	if (req == NULL) {
		return KNOT_ENOMEM;
	}

	/* Store socket and remote address. */
	req->fd = dup(qdata->params->socket);
	const struct sockaddr_storage *remote = knotd_qdata_remote_addr(qdata);
	memcpy(&req->remote, remote, sockaddr_len(remote));

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

#ifdef ENABLE_QUIC
	if (qdata->params->quic_conn != NULL) {
		req->flags |= KNOT_REQUEST_QUIC;
		req->quic_conn = qdata->params->quic_conn;
		knot_quic_conn_block(req->quic_conn, true);
		assert(qdata->params->quic_stream >= 0);
		req->quic_stream = qdata->params->quic_stream;
	} else
#endif // ENABLE_QUIC
	if (qdata->params->tls_conn != NULL) {
		req->flags |= KNOT_REQUEST_TLS;
		req->tls_req_ctx.conn = qdata->params->tls_conn;
		req->tls_req_ctx.conn->fd_clones_count++;
		knot_tls_conn_block(req->tls_req_ctx.conn, true);
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

knot_layer_state_t update_process_query(knot_pkt_t *pkt, knotd_qdata_t *qdata)
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

	/* Store update into DDNS queue. */
	int ret = update_enqueue((zone_t *)qdata->extra->zone, qdata);
	if (ret != KNOT_EOK) {
		return KNOT_STATE_FAIL;
	}

	/* No immediate response. */
	return KNOT_STATE_NOOP;
}
