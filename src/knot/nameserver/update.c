/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <sys/socket.h>

#include "dnssec/random.h"
#include "knot/common/log.h"
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
#include "contrib/print.h"

/* UPDATE-specific logging (internal, expects 'qdata' variable set). */
#define UPDATE_LOG(severity, msg, ...) \
	NS_PROC_LOG(severity, qdata->zone->name, qdata->param->remote, \
	            "DDNS", msg, ##__VA_ARGS__)

static void init_qdata_from_request(struct query_data *qdata,
                                    const zone_t *zone,
                                    struct knot_request *req,
                                    struct process_query_param *param)
{
	memset(qdata, 0, sizeof(*qdata));
	qdata->param = param;
	qdata->query = req->query;
	qdata->zone = zone;
	qdata->sign = req->sign;
}

static int check_prereqs(struct knot_request *request,
                         const zone_t *zone, zone_update_t *update,
                         struct query_data *qdata)
{
	uint16_t rcode = KNOT_RCODE_NOERROR;
	int ret = ddns_process_prereqs(request->query, update, &rcode);
	if (ret != KNOT_EOK) {
		UPDATE_LOG(LOG_WARNING, "prerequisites not met (%s)",
		           knot_strerror(ret));
		assert(rcode != KNOT_RCODE_NOERROR);
		knot_wire_set_rcode(request->resp->wire, rcode);
		return ret;
	}

	return KNOT_EOK;
}

static int process_single_update(struct knot_request *request,
                                 const zone_t *zone, zone_update_t *update,
                                 struct query_data *qdata)
{
	uint16_t rcode = KNOT_RCODE_NOERROR;
	int ret = ddns_process_update(zone, request->query, update, &rcode);
	if (ret != KNOT_EOK) {
		UPDATE_LOG(LOG_WARNING, "failed to apply (%s)",
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
		struct knot_request *req = node->d;
		if (knot_wire_get_rcode(req->resp->wire) == KNOT_RCODE_NOERROR) {
			knot_wire_set_rcode(req->resp->wire, rcode);
		}
	}
}

static void store_original_qname(struct query_data *qdata, const knot_pkt_t *pkt)
{
	memcpy(qdata->orig_qname, knot_pkt_qname(pkt), pkt->qname_size);
}

static int process_bulk(zone_t *zone, list_t *requests, zone_update_t *up)
{
	// Walk all the requests and process.
	ptrnode_t *node = NULL;
	WALK_LIST(node, *requests) {
		struct knot_request *req = node->d;
		// Init qdata structure for logging (unique per-request).
		struct process_query_param param = {
			.remote = &req->remote
		};
		struct query_data qdata;
		init_qdata_from_request(&qdata, zone, req, &param);

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

		process_query_qname_case_restore(&qdata, req->query);
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

	// Apply changes.
	ret = zone_update_commit(conf, &up);
	if (ret != KNOT_EOK) {
		if (ret == KNOT_ETTL) {
			set_rcodes(requests, KNOT_RCODE_REFUSED);
		} else {
			set_rcodes(requests, KNOT_RCODE_SERVFAIL);
		}
		return ret;
	}

	zone_update_clear(&up);

	/* Sync zonefile immediately if configured. */
	conf_val_t val = conf_zone_get(conf, C_ZONEFILE_SYNC, zone->name);
	if (conf_int(&val) == 0) {
		zone_events_schedule(zone, ZONE_EVENT_FLUSH, ZONE_EVENT_NOW);
	}

	return KNOT_EOK;
}

static void process_requests(conf_t *conf, zone_t *zone, list_t *requests)
{
	assert(zone);
	assert(requests);

	/* Keep original state. */
	struct timeval t_start, t_end;
	gettimeofday(&t_start, NULL);
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

	gettimeofday(&t_end, NULL);
	log_zone_info(zone->name, "DDNS, update finished, serial %u -> %u, "
	              "%.02f seconds", old_serial, new_serial,
	              time_diff(&t_start, &t_end) / 1000.0);

	zone_events_schedule(zone, ZONE_EVENT_NOTIFY, ZONE_EVENT_NOW);
}

static int remote_forward(conf_t *conf, struct knot_request *request, conf_remote_t *remote)
{
	/* Copy request and assign new ID. */
	knot_pkt_t *query = knot_pkt_new(NULL, request->query->max_size, NULL);
	int ret = knot_pkt_copy(query, request->query);
	if (ret != KNOT_EOK) {
		knot_pkt_free(&query);
		return ret;
	}
	knot_wire_set_id(query->wire, dnssec_random_uint16_t());
	knot_tsig_append(query->wire, &query->size, query->max_size, query->tsig_rr);

	/* Create requestor instance. */
	struct knot_requestor re;
	ret = knot_requestor_init(&re, NULL);
	if (ret != KNOT_EOK) {
		knot_pkt_free(&query);
		return ret;
	}

	/* Prepare packet capture layer. */
	struct capture_param param = {
		.sink = request->resp
	};

	ret = knot_requestor_overlay(&re, query_capture_api(), &param);
	if (ret != KNOT_EOK) {
		knot_requestor_clear(&re);
		knot_pkt_free(&query);
		return ret;
	}

	/* Create a request. */
	const struct sockaddr *dst = (const struct sockaddr *)&remote->addr;
	const struct sockaddr *src = (const struct sockaddr *)&remote->via;
	struct knot_request *req = knot_request_make(re.mm, dst, src, query, 0);
	if (req == NULL) {
		knot_requestor_clear(&re);
		knot_pkt_free(&query);
		return KNOT_ENOMEM;
	}

	/* Execute the request. */
	conf_val_t *val = &conf->cache.srv_tcp_reply_timeout;
	int timeout = conf_int(val) * 1000;
	ret = knot_requestor_exec(&re, req, timeout);

	knot_request_free(req, re.mm);
	knot_requestor_clear(&re);

	return ret;
}

static void forward_request(conf_t *conf, zone_t *zone, struct knot_request *request)
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
		struct knot_request *req = node->d;
		forward_request(conf, zone, req);
	}
}

static bool update_tsig_check(conf_t *conf, struct query_data *qdata, struct knot_request *req)
{
	// Check that ACL is still valid.
	if (!process_query_acl_check(conf, qdata->zone->name, ACL_ACTION_UPDATE, qdata)) {
		UPDATE_LOG(LOG_WARNING, "ACL check failed");
		knot_wire_set_rcode(req->resp->wire, qdata->rcode);
		return false;
	} else {
		// Check TSIG validity.
		int ret = process_query_verify(qdata);
		if (ret != KNOT_EOK) {
			UPDATE_LOG(LOG_WARNING, "failed (%s)",
			           knot_strerror(ret));
			knot_wire_set_rcode(req->resp->wire, qdata->rcode);
			return false;
		}
	}

	// Store signing context for response.
	req->sign = qdata->sign;

	return true;
}

static void send_update_response(conf_t *conf, const zone_t *zone, struct knot_request *req)
{
	if (req->resp) {
		if (!zone_is_slave(conf, zone)) {
			// Sign the response with TSIG where applicable
			struct query_data qdata;
			init_qdata_from_request(&qdata, zone, req, NULL);

			(void)process_query_sign_response(req->resp, &qdata);
		}

		if (net_is_stream(req->fd)) {
			conf_val_t *val = &conf->cache.srv_tcp_reply_timeout;
			int timeout = conf_int(val) * 1000;
			net_dns_tcp_send(req->fd, req->resp->wire, req->resp->size,
			                 timeout);
		} else {
			net_dgram_send(req->fd, req->resp->wire, req->resp->size,
			               &req->remote);
		}
	}
}

static void free_request(struct knot_request *req)
{
	close(req->fd);
	knot_pkt_free(&req->query);
	knot_pkt_free(&req->resp);
	free(req);
}

static void send_update_responses(conf_t *conf, const zone_t *zone, list_t *updates)
{
	ptrnode_t *node = NULL, *nxt = NULL;
	WALK_LIST_DELSAFE(node, nxt, *updates) {
		struct knot_request *req = node->d;
		send_update_response(conf, zone, req);
		free_request(req);
	}
	ptrlist_free(updates, NULL);
}

static int init_update_responses(conf_t *conf, const zone_t *zone, list_t *updates,
                                 size_t *update_count)
{
	ptrnode_t *node = NULL, *nxt = NULL;
	WALK_LIST_DELSAFE(node, nxt, *updates) {
		struct knot_request *req = node->d;
		req->resp = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, NULL);
		if (req->resp == NULL) {
			return KNOT_ENOMEM;
		}

		assert(req->query);
		knot_pkt_init_response(req->resp, req->query);
		if (zone_is_slave(conf, zone)) {
			// Don't check TSIG for forwards.
			continue;
		}

		struct process_query_param param = {
			.remote = &req->remote
		};

		struct query_data qdata;
		init_qdata_from_request(&qdata, zone, req, &param);

		if (!update_tsig_check(conf, &qdata, req)) {
			// ACL/TSIG check failed, send response.
			send_update_response(conf, zone, req);
			// Remove this request from processing list.
			free_request(req);
			ptrlist_rem(node, NULL);
			*update_count -= 1;
		}
	}

	return KNOT_EOK;
}

int update_process_query(knot_pkt_t *pkt, struct query_data *qdata)
{
	/* RFC1996 require SOA question. */
	NS_NEED_QTYPE(qdata, KNOT_RRTYPE_SOA, KNOT_RCODE_FORMERR);

	/* Check valid zone. */
	NS_NEED_ZONE(qdata, KNOT_RCODE_NOTAUTH);

	/* Need valid transaction security. */
	zone_t *zone = (zone_t *)qdata->zone;
	NS_NEED_AUTH(qdata, zone->name, ACL_ACTION_UPDATE);
	/* Check expiration. */
	NS_NEED_ZONE_CONTENTS(qdata, KNOT_RCODE_SERVFAIL);

	/* Restore original QNAME for DDNS ACL checks. */
	process_query_qname_case_restore(qdata, qdata->query);
	/* Store update into DDNS queue. */
	int ret = zone_update_enqueue(zone, qdata->query, qdata->param);
	if (ret != KNOT_EOK) {
		return KNOT_STATE_FAIL;
	}

	/* No immediate response. */
	pkt->size = 0;
	return KNOT_STATE_DONE;
}

void updates_execute(conf_t *conf, zone_t *zone)
{
	/* Get list of pending updates. */
	list_t updates;
	size_t update_count = zone_update_dequeue(zone, &updates);
	if (update_count == 0) {
		return;
	}

	/* Init updates respones. */
	int ret = init_update_responses(conf, zone, &updates, &update_count);
	if (ret != KNOT_EOK) {
		/* Send what responses we can. */
		set_rcodes(&updates, KNOT_RCODE_SERVFAIL);
		send_update_responses(conf, zone, &updates);
		return;
	}

	if (update_count == 0) {
		/* All updates failed their ACL checks. */
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
