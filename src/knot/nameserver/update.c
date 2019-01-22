/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <sys/socket.h>

#include "libdnssec/random.h"
#include "knot/common/log.h"
#include "knot/dnssec/zone-events.h"
#include "knot/events/handlers.h"
#include "knot/query/capture.h"
#include "knot/query/requestor.h"
#include "knot/nameserver/update.h"
#include "knot/nameserver/internet.h"
#include "knot/nameserver/process_query.h"
#include "knot/nameserver/log.h"
#include "knot/updates/ddns.h"
#include "knot/updates/apply.h"
#include "knot/events/events.h"
#include "libknot/libknot.h"
#include "contrib/net.h"
#include "contrib/string.h"
#include "contrib/time.h"

#define UPDATE_LOG(priority, qdata, fmt...) \
	ns_log(priority, knot_pkt_qname(qdata->query), LOG_OPERATION_UPDATE, \
	       LOG_DIRECTION_IN, (struct sockaddr *)qdata->params->remote, fmt)

static void init_qdata_from_request(knotd_qdata_t *qdata,
                                    const zone_t *zone,
                                    knot_request_t *req,
                                    knotd_qdata_params_t *params,
                                    knotd_qdata_extra_t *extra)
{
	memset(qdata, 0, sizeof(*qdata));
	qdata->params = params;
	qdata->query = req->query;
	qdata->sign = req->sign;
	qdata->extra = extra;
	memset(extra, 0, sizeof(*extra));
	qdata->extra->zone = zone;
}

static int check_prereqs(knot_request_t *request,
                         const zone_t *zone, zone_update_t *update,
                         knotd_qdata_t *qdata)
{
	uint16_t rcode = KNOT_RCODE_NOERROR;
	int ret = ddns_process_prereqs(request->query, update, &rcode);
	if (ret != KNOT_EOK) {
		UPDATE_LOG(LOG_WARNING, qdata, "prerequisites not met (%s)",
		           knot_strerror(ret));
		assert(rcode != KNOT_RCODE_NOERROR);
		knot_wire_set_rcode(request->resp->wire, rcode);
		return ret;
	}

	return KNOT_EOK;
}

static int process_single_update(knot_request_t *request,
                                 const zone_t *zone, zone_update_t *update,
                                 knotd_qdata_t *qdata)
{
	uint16_t rcode = KNOT_RCODE_NOERROR;
	int ret = ddns_process_update(zone, request->query, update, &rcode);
	if (ret != KNOT_EOK) {
		UPDATE_LOG(LOG_WARNING, qdata, "failed to apply (%s)",
		           knot_strerror(ret));
		assert(rcode != KNOT_RCODE_NOERROR);
		knot_wire_set_rcode(request->resp->wire, rcode);
		return ret;
	}

	return KNOT_EOK;
}

static void set_rcodes(list_t *requests, const uint16_t rcode)
{
	ptrnode_t *node = NULL;
	WALK_LIST(node, *requests) {
		knot_request_t *req = node->d;
		if (knot_wire_get_rcode(req->resp->wire) == KNOT_RCODE_NOERROR) {
			knot_wire_set_rcode(req->resp->wire, rcode);
		}
	}
}

static void store_original_qname(knotd_qdata_t *qdata, const knot_pkt_t *pkt)
{
	memcpy(qdata->extra->orig_qname, knot_pkt_qname(pkt), pkt->qname_size);
}

static int process_bulk(zone_t *zone, list_t *requests, zone_update_t *up)
{
	// Walk all the requests and process.
	ptrnode_t *node = NULL;
	WALK_LIST(node, *requests) {
		knot_request_t *req = node->d;
		// Init qdata structure for logging (unique per-request).
		knotd_qdata_params_t params = {
			.remote = &req->remote
		};
		knotd_qdata_t qdata;
		knotd_qdata_extra_t extra;
		init_qdata_from_request(&qdata, zone, req, &params, &extra);

		store_original_qname(&qdata, req->query);
		process_query_qname_case_lower(req->query);

		int ret = check_prereqs(req, zone, up, &qdata);
		if (ret != KNOT_EOK) {
			// Skip updates with failed prereqs.
			continue;
		}

		ret = process_single_update(req, zone, up, &qdata);
		if (ret != KNOT_EOK) {
			return ret;
		}

		process_query_qname_case_restore(req->query, &qdata);
	}

	return KNOT_EOK;
}

static int process_normal(conf_t *conf, zone_t *zone, list_t *requests)
{
	assert(requests);

	// Init zone update structure
	zone_update_t up;
	int ret = zone_update_init(&up, zone, UPDATE_INCREMENTAL | UPDATE_SIGN);
	if (ret != KNOT_EOK) {
		set_rcodes(requests, KNOT_RCODE_SERVFAIL);
		return ret;
	}

	// Process all updates.
	ret = process_bulk(zone, requests, &up);
	if (ret != KNOT_EOK) {
		zone_update_clear(&up);
		set_rcodes(requests, KNOT_RCODE_SERVFAIL);
		return ret;
	}

	// Sign update.
	conf_val_t val = conf_zone_get(conf, C_DNSSEC_SIGNING, zone->name);
	bool dnssec_enable = (up.flags & UPDATE_SIGN) && conf_bool(&val);
	if (dnssec_enable) {
		zone_sign_reschedule_t resch = { 0 };
		ret = knot_dnssec_sign_update(&up, &resch);
		if (ret != KNOT_EOK) {
			zone_update_clear(&up);
			set_rcodes(requests, KNOT_RCODE_SERVFAIL);
			return ret;
		}
		event_dnssec_reschedule(conf, zone, &resch, false); // false since we handle NOTIFY after processing ddns queue
	}

	// Apply changes.
	ret = zone_update_commit(conf, &up);
	zone_update_clear(&up);
	if (ret != KNOT_EOK) {
		if (ret == KNOT_EZONESIZE) {
			set_rcodes(requests, KNOT_RCODE_REFUSED);
		} else {
			set_rcodes(requests, KNOT_RCODE_SERVFAIL);
		}
		return ret;
	}

	return KNOT_EOK;
}

static void process_requests(conf_t *conf, zone_t *zone, list_t *requests)
{
	assert(zone);
	assert(requests);

	/* Keep original state. */
	struct timespec t_start = time_now();
	const uint32_t old_serial = zone_contents_serial(zone->contents);

	/* Process authenticated packet. */
	int ret = process_normal(conf, zone, requests);
	if (ret != KNOT_EOK) {
		log_zone_error(zone->name, "DDNS, processing failed (%s)",
		               knot_strerror(ret));
		return;
	}

	/* Evaluate response. */
	const uint32_t new_serial = zone_contents_serial(zone->contents);
	if (new_serial == old_serial) {
		log_zone_info(zone->name, "DDNS, finished, no changes to the zone were made");
		return;
	}

	struct timespec t_end = time_now();
	log_zone_info(zone->name, "DDNS, finished, serial %u -> %u, "
	              "%.02f seconds", old_serial, new_serial,
	              time_diff_ms(&t_start, &t_end) / 1000.0);

	zone_events_schedule_at(zone, ZONE_EVENT_NOTIFY, time(NULL) + 1);
}

static int remote_forward(conf_t *conf, knot_request_t *request, conf_remote_t *remote)
{
	/* Copy request and assign new ID. */
	knot_pkt_t *query = knot_pkt_new(NULL, request->query->max_size, NULL);
	int ret = knot_pkt_copy(query, request->query);
	if (ret != KNOT_EOK) {
		knot_pkt_free(query);
		return ret;
	}
	knot_wire_set_id(query->wire, dnssec_random_uint16_t());
	knot_tsig_append(query->wire, &query->size, query->max_size, query->tsig_rr);

	/* Prepare packet capture layer. */
	const knot_layer_api_t *capture = query_capture_api();
	struct capture_param capture_param = {
		.sink = request->resp
	};

	/* Create requestor instance. */
	knot_requestor_t re;
	ret = knot_requestor_init(&re, capture, &capture_param, NULL);
	if (ret != KNOT_EOK) {
		knot_pkt_free(query);
		return ret;
	}

	/* Create a request. */
	const struct sockaddr *dst = (const struct sockaddr *)&remote->addr;
	const struct sockaddr *src = (const struct sockaddr *)&remote->via;
	knot_request_t *req = knot_request_make(re.mm, dst, src, query, NULL, 0);
	if (req == NULL) {
		knot_requestor_clear(&re);
		knot_pkt_free(query);
		return KNOT_ENOMEM;
	}

	/* Execute the request. */
	int timeout = 1000 * conf->cache.srv_tcp_reply_timeout;
	ret = knot_requestor_exec(&re, req, timeout);

	knot_request_free(req, re.mm);
	knot_requestor_clear(&re);

	return ret;
}

static void forward_request(conf_t *conf, zone_t *zone, knot_request_t *request)
{
	/* Read the ddns master or the first master. */
	conf_val_t remote = conf_zone_get(conf, C_DDNS_MASTER, zone->name);
	if (remote.code != KNOT_EOK) {
		remote = conf_zone_get(conf, C_MASTER, zone->name);
	}

	/* Get the number of remote addresses. */
	conf_val_t addr = conf_id_get(conf, C_RMT, C_ADDR, &remote);
	size_t addr_count = conf_val_count(&addr);
	assert(addr_count > 0);

	/* Try all remote addresses to forward the request to. */
	int ret = KNOT_EOK;
	for (size_t i = 0; i < addr_count; i++) {
		conf_remote_t master = conf_remote(conf, &remote, i);

		ret = remote_forward(conf, request, &master);
		if (ret == KNOT_EOK) {
			break;
		}
	}

	/* Restore message ID and TSIG. */
	knot_wire_set_id(request->resp->wire, knot_wire_get_id(request->query->wire));
	knot_tsig_append(request->resp->wire, &request->resp->size,
	                 request->resp->max_size, request->resp->tsig_rr);

	/* Set RCODE if forwarding failed. */
	if (ret != KNOT_EOK) {
		knot_wire_set_rcode(request->resp->wire, KNOT_RCODE_SERVFAIL);
		log_zone_error(zone->name, "DDNS, failed to forward updates to the master (%s)",
		               knot_strerror(ret));
	} else {
		log_zone_info(zone->name, "DDNS, updates forwarded to the master");
	}
}

static void forward_requests(conf_t *conf, zone_t *zone, list_t *requests)
{
	assert(zone);
	assert(requests);

	ptrnode_t *node = NULL;
	WALK_LIST(node, *requests) {
		knot_request_t *req = node->d;
		forward_request(conf, zone, req);
	}
}

static void send_update_response(conf_t *conf, const zone_t *zone, knot_request_t *req)
{
	if (req->resp) {
		if (!zone_is_slave(conf, zone)) {
			// Sign the response with TSIG where applicable
			knotd_qdata_t qdata;
			knotd_qdata_extra_t extra;
			init_qdata_from_request(&qdata, zone, req, NULL, &extra);

			(void)process_query_sign_response(req->resp, &qdata);
		}

		if (net_is_stream(req->fd)) {
			int timeout = 1000 * conf->cache.srv_tcp_reply_timeout;
			net_dns_tcp_send(req->fd, req->resp->wire, req->resp->size,
			                 timeout);
		} else {
			net_dgram_send(req->fd, req->resp->wire, req->resp->size,
			               (struct sockaddr *)&req->remote);
		}
	}
}

static void free_request(knot_request_t *req)
{
	close(req->fd);
	knot_pkt_free(req->query);
	knot_pkt_free(req->resp);
	dnssec_binary_free(&req->sign.tsig_key.secret);
	free(req);
}

static void send_update_responses(conf_t *conf, const zone_t *zone, list_t *updates)
{
	ptrnode_t *node = NULL, *nxt = NULL;
	WALK_LIST_DELSAFE(node, nxt, *updates) {
		knot_request_t *req = node->d;
		send_update_response(conf, zone, req);
		free_request(req);
	}
	ptrlist_free(updates, NULL);
}

static int init_update_responses(list_t *updates)
{
	ptrnode_t *node = NULL, *nxt = NULL;
	WALK_LIST_DELSAFE(node, nxt, *updates) {
		knot_request_t *req = node->d;
		req->resp = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, NULL);
		if (req->resp == NULL) {
			return KNOT_ENOMEM;
		}

		assert(req->query);
		knot_pkt_init_response(req->resp, req->query);
	}

	return KNOT_EOK;
}

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
	memcpy(&req->remote, qdata->params->remote, sizeof(req->remote));

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

static size_t update_dequeue(zone_t *zone, list_t *updates)
{
	assert(zone);
	assert(updates);

	pthread_mutex_lock(&zone->ddns_lock);

	if (EMPTY_LIST(zone->ddns_queue)) {
		/* Lost race during reload. */
		pthread_mutex_unlock(&zone->ddns_lock);
		return 0;
	}

	*updates = zone->ddns_queue;
	size_t update_count = zone->ddns_queue_size;
	init_list(&zone->ddns_queue);
	zone->ddns_queue_size = 0;

	pthread_mutex_unlock(&zone->ddns_lock);

	return update_count;
}

int update_process_query(knot_pkt_t *pkt, knotd_qdata_t *qdata)
{
	/* RFC1996 require SOA question. */
	NS_NEED_QTYPE(qdata, KNOT_RRTYPE_SOA, KNOT_RCODE_FORMERR);

	/* Check valid zone. */
	NS_NEED_ZONE(qdata, KNOT_RCODE_NOTAUTH);

	/* Need valid transaction security. */
	NS_NEED_AUTH(qdata, ACL_ACTION_UPDATE);
	/* Check expiration. */
	NS_NEED_ZONE_CONTENTS(qdata, KNOT_RCODE_SERVFAIL);
	/* Check frozen zone. */
	NS_NEED_NOT_FROZEN(qdata, KNOT_RCODE_REFUSED);

	/* Restore original QNAME for DDNS ACL checks. */
	process_query_qname_case_restore(qdata->query, qdata);
	/* Store update into DDNS queue. */
	int ret = update_enqueue((zone_t *)qdata->extra->zone, qdata);
	if (ret != KNOT_EOK) {
		return KNOT_STATE_FAIL;
	}

	/* No immediate response. */
	return KNOT_STATE_NOOP;
}

void updates_execute(conf_t *conf, zone_t *zone)
{
	if (zone == NULL) {
		return;
	}

	/* Get list of pending updates. */
	list_t updates;
	size_t update_count = update_dequeue(zone, &updates);
	if (update_count == 0) {
		return;
	}

	/* Init updates respones. */
	int ret = init_update_responses(&updates);
	if (ret != KNOT_EOK) {
		/* Send what responses we can. */
		set_rcodes(&updates, KNOT_RCODE_SERVFAIL);
		send_update_responses(conf, zone, &updates);
		return;
	}

	/* Process update list - forward if zone has master, or execute.
	   RCODEs are set. */
	if (zone_is_slave(conf, zone)) {
		log_zone_info(zone->name,
		              "DDNS, forwarding %zu updates", update_count);
		forward_requests(conf, zone, &updates);
	} else {
		log_zone_info(zone->name,
		              "DDNS, processing %zu updates", update_count);
		process_requests(conf, zone, &updates);
	}

	/* Send responses. */
	send_update_responses(conf, zone, &updates);
}
