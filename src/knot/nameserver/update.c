/*  Copyright (C) 2013 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "knot/nameserver/update.h"
#include "knot/nameserver/internet.h"
#include "knot/nameserver/process_query.h"
#include "knot/updates/apply.h"
#include "knot/dnssec/zone-sign.h"
#include "common/debug.h"
#include "knot/dnssec/zone-events.h"
#include "knot/updates/ddns.h"
#include "common/descriptor.h"
#include "libknot/tsig-op.h"
#include "knot/zone/zone.h"
#include "knot/zone/events.h"
#include "knot/server/tcp-handler.h"
#include "knot/server/udp-handler.h"
#include "knot/nameserver/requestor.h"
#include "knot/nameserver/capture.h"
#include "libknot/dnssec/random.h"

/* UPDATE-specific logging (internal, expects 'qdata' variable set). */
#define UPDATE_LOG(severity, msg...) \
	QUERY_LOG(severity, qdata, "UPDATE", msg)

int update_query_process(knot_pkt_t *pkt, struct query_data *qdata)
{
	/* RFC1996 require SOA question. */
	NS_NEED_QTYPE(qdata, KNOT_RRTYPE_SOA, KNOT_RCODE_FORMERR);

	/* Check valid zone. */
	NS_NEED_ZONE(qdata, KNOT_RCODE_NOTAUTH);

	/* Need valid transaction security. */
	zone_t *zone = (zone_t *)qdata->zone;
	NS_NEED_AUTH(&zone->conf->acl.update_in, qdata);
	/* Check expiration. */
	NS_NEED_ZONE_CONTENTS(qdata, KNOT_RCODE_SERVFAIL);

	/* Store update into DDNS queue. */
	int ret = zone_update_enqueue(zone, qdata->query, qdata->param);
	if (ret != KNOT_EOK) {
		return NS_PROC_FAIL;
	}

	/* No immediate response. */
	pkt->size = 0;
	return NS_PROC_DONE;
}

static bool apex_rr_changed(const zone_contents_t *old_contents,
                            const zone_contents_t *new_contents,
                            uint16_t type)
{
	knot_rrset_t old_rr = node_rrset(old_contents->apex, type);
	knot_rrset_t new_rr = node_rrset(new_contents->apex, type);

	return !knot_rrset_equal(&old_rr, &new_rr, KNOT_RRSET_COMPARE_WHOLE);
}

static bool zones_dnskey_changed(const zone_contents_t *old_contents,
                                 const zone_contents_t *new_contents)
{
	return apex_rr_changed(old_contents, new_contents, KNOT_RRTYPE_DNSKEY);
}

static bool zones_nsec3param_changed(const zone_contents_t *old_contents,
                                     const zone_contents_t *new_contents)
{
	return apex_rr_changed(old_contents, new_contents,
	                       KNOT_RRTYPE_NSEC3PARAM);
}

static int sign_update(zone_t *zone, const zone_contents_t *old_contents,
                       zone_contents_t *new_contents, changeset_t *ddns_ch,
                       list_t *sec_chs)
{
	assert(zone != NULL);
	assert(old_contents != NULL);
	assert(new_contents != NULL);
	assert(ddns_ch != NULL);

	changeset_t *sec_ch = changeset_new(zone->name);
	if (sec_ch == NULL) {
		return KNOT_ENOMEM;
	}
	add_head(sec_chs, &sec_ch->n);

	/*
	 * Check if the UPDATE changed DNSKEYs or NSEC3PARAM.
	 * If so, we have to sign the whole zone.
	 */
	int ret = KNOT_EOK;
	uint32_t refresh_at = 0;
	if (zones_dnskey_changed(old_contents, new_contents) ||
	    zones_nsec3param_changed(old_contents, new_contents)) {
		ret = knot_dnssec_zone_sign(new_contents, zone->conf,
		                            sec_ch, KNOT_SOA_SERIAL_KEEP,
		                            &refresh_at);
	} else {
		// Sign the created changeset
		ret = knot_dnssec_sign_changeset(new_contents, zone->conf,
		                                 ddns_ch, sec_ch,
		                                 &refresh_at);
	}
	if (ret != KNOT_EOK) {
		changesets_free(sec_chs);
		return ret;
	}

	// Apply DNSSEC changeset
	ret = apply_changesets_directly(new_contents, sec_chs);
	if (ret != KNOT_EOK) {
		changesets_free(sec_chs);
		return ret;
	}

	// Merge changesets
	ret = changeset_merge(ddns_ch, sec_ch);
	if (ret != KNOT_EOK) {
		update_cleanup(sec_chs);
		changesets_free(sec_chs);
		return ret;
	}

	// Plan next zone resign.
	const time_t resign_time = zone_events_get_time(zone, ZONE_EVENT_DNSSEC);
	if (time(NULL) + refresh_at < resign_time) {
		zone_events_schedule(zone, ZONE_EVENT_DNSSEC, refresh_at);
	}

	return KNOT_EOK;
}

static int process_single_update(struct request_data *request, const zone_t *zone,
                                 changeset_t *ch)
{
	uint16_t rcode = KNOT_RCODE_NOERROR;
	int ret = ddns_process_prereqs(request->query, zone->contents, &rcode);
	if (ret != KNOT_EOK) {
		assert(rcode != KNOT_RCODE_NOERROR);
		knot_wire_set_rcode(request->resp->wire, rcode);
		return ret;
	}

	ret = ddns_process_update(zone, request->query, ch, &rcode);
	if (ret != KNOT_EOK) {
		assert(rcode != KNOT_RCODE_NOERROR);
		knot_wire_set_rcode(request->resp->wire, rcode);
	}

	return ret;
}

static void set_rcodes(list_t *queries, const uint16_t rcode)
{
	struct request_data *query;
	WALK_LIST(query, *queries) {
		if (knot_wire_get_rcode(query->resp->wire) == KNOT_RCODE_NOERROR) {
			knot_wire_set_rcode(query->resp->wire, rcode);
		}
	}
}

static int process_normal(zone_t *zone, list_t *queries)
{
#warning TODO proper logging
	assert(queries);

	// Create DDNS change
	changeset_t ddns_ch;
	int ret = changeset_init(&ddns_ch, zone->name);
	if (ret != KNOT_EOK) {
		set_rcodes(queries, KNOT_RCODE_SERVFAIL);
		return ret;
	}

	struct request_data *query;
	WALK_LIST(query, *queries) {
		ret = process_single_update(query, zone, &ddns_ch);
		if (ret != KNOT_EOK) {
			changeset_clear(&ddns_ch);
			set_rcodes(queries, KNOT_RCODE_SERVFAIL);
			return ret;
		}
	}

	zone_contents_t *new_contents = NULL;
	const bool change_made = !changeset_empty(&ddns_ch);
	list_t apply;
	init_list(&apply);
	if (change_made) {
		add_head(&apply, &ddns_ch.n);
		ret = apply_changesets(zone, &apply, &new_contents);
		if (ret != KNOT_EOK) {
			if (ret == KNOT_ETTL) {
				set_rcodes(queries, KNOT_RCODE_REFUSED);
			} else {
				set_rcodes(queries, KNOT_RCODE_SERVFAIL);
			}
			changeset_clear(&ddns_ch);
			return ret;
		}
	} else {
		changeset_clear(&ddns_ch);
		return KNOT_EOK;
	}
	assert(new_contents);

	list_t sec_chs;
	init_list(&sec_chs);
	if (zone->conf->dnssec_enable) {
		ret = sign_update(zone, zone->contents, new_contents, &ddns_ch,
		                  &sec_chs);
		if (ret != KNOT_EOK) {
			update_rollback(&apply, &new_contents);
			changeset_clear(&ddns_ch);
			set_rcodes(queries, KNOT_RCODE_SERVFAIL);
			return ret;
		}
	}

	// Write changes to journal if all went well. (DNSSEC merged)
	ret = zone_change_store(zone, &apply);
	if (ret != KNOT_EOK) {
		update_rollback(&apply, &new_contents);
		changeset_clear(&ddns_ch);
		set_rcodes(queries, KNOT_RCODE_SERVFAIL);
		return ret;
	}

	// Switch zone contents.
	zone_contents_t *old_contents = zone_switch_contents(zone, new_contents);
	synchronize_rcu();
	update_free_old_zone(&old_contents);

	// Clear DDNS changes
	update_cleanup(&apply);
	changeset_clear(&ddns_ch);

	// Clear DNSSEC changes
	update_cleanup(&sec_chs);
	changesets_free(&sec_chs);

	// Sync zonefile immediately if configured.
	if (zone->conf->dbsync_timeout == 0) {
		zone_events_schedule(zone, ZONE_EVENT_FLUSH, ZONE_EVENT_NOW);
	}

	return ret;
}


static int process_queries(zone_t *zone, list_t *queries)
{
	if (zone == NULL || queries == NULL) {
		return KNOT_EINVAL;
	}

//	UPDATE_LOG(LOG_INFO, "Started.");

	/* Keep original state. */
	struct timeval t_start, t_end;
	gettimeofday(&t_start, NULL);
	const uint32_t old_serial = zone_contents_serial(zone->contents);

	/* Process authenticated packet. */
	int ret = process_normal(zone, queries);
	if (ret != KNOT_EOK) {
//		UPDATE_LOG(LOG_ERR, "%s", knot_strerror(ret));
		return ret;
	}

	/* Evaluate response. */
	const uint32_t new_serial = zone_contents_serial(zone->contents);
	if (new_serial == old_serial) {
//		UPDATE_LOG(LOG_NOTICE, "No change to zone made.");
		return KNOT_EOK;
	}

	gettimeofday(&t_end, NULL);
//	UPDATE_LOG(LOG_INFO, "Serial %u -> %u", old_serial, new_serial);
	printf("Update finished in %.02fs.\n",
	           time_diff(&t_start, &t_end) / 1000.0);
	
	zone_events_schedule(zone, ZONE_EVENT_NOTIFY, ZONE_EVENT_NOW);

	return KNOT_EOK;
}

static int forward_query(zone_t *zone, struct request_data *update)
{
	/* Create requestor instance. */
	struct requestor re;
	requestor_init(&re, NS_PROC_CAPTURE, NULL);

	/* Fetch primary master. */
	const conf_iface_t *master = zone_master(zone);

	/* Copy request and assign new ID. */
	knot_pkt_t *query = knot_pkt_new(NULL, update->query->max_size, NULL);
	int ret = knot_pkt_copy(query, update->query);
	if (ret != KNOT_EOK) {
		knot_wire_set_rcode(update->resp->wire, KNOT_RCODE_SERVFAIL);
		return ret;
	}
	knot_wire_set_id(query->wire, knot_random_uint16_t());
	knot_tsig_append(query->wire, &query->size, query->max_size, query->tsig_rr);

	/* Create a request. */
	struct request *req = requestor_make(&re, master, query);
	if (req == NULL) {
		knot_pkt_free(&query);
		knot_wire_set_rcode(update->resp->wire, KNOT_RCODE_SERVFAIL);
		return KNOT_ENOMEM;
	}

	/* Enqueue and execute request. */
	struct process_capture_param param;
	param.sink = update->resp;
	ret = requestor_enqueue(&re, req, &param);
	if (ret == KNOT_EOK) {
		struct timeval tv = { conf()->max_conn_reply, 0 };
		ret = requestor_exec(&re, &tv);
	}

	requestor_clear(&re);

	/* Restore message ID and TSIG. */
	knot_wire_set_id(update->resp->wire, knot_wire_get_id(update->query->wire));
	knot_tsig_append(update->resp->wire, &update->resp->size,
	                 update->resp->max_size, update->resp->tsig_rr);

	/* Set RCODE if forwarding failed. */
	if (ret != KNOT_EOK) {
		knot_wire_set_rcode(update->resp->wire, KNOT_RCODE_SERVFAIL);
//		UPDATE_LOG(LOG_INFO, "Failed to forward UPDATE to master: %s",
//		           knot_strerror(ret));
		printf("Failed to forward\n");
	} else {
//		UPDATE_LOG(LOG_INFO, "Forwarded UPDATE to master.");
		printf("Forwarded\n");
	}

	return ret;
}

static void forward_queries(zone_t *zone, list_t *queries)
{
	struct request_data *query;
	WALK_LIST(query, *queries) {
		forward_query(zone, query);
	}
}

#undef UPDATE_LOG

static int init_update_respones(list_t *updates)
{
	struct request_data *r = NULL;
	WALK_LIST(r, *updates) {
		r->resp = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, NULL);
		if (r->resp == NULL) {
			return KNOT_ENOMEM;
		}

		assert(r->query);
		knot_pkt_init_response(r->resp, r->query);
	}

	return KNOT_EOK;
}

static void send_update_responses(list_t *updates)
{
	struct request_data *r, *nxt;
	WALK_LIST_DELSAFE(r, nxt, *updates) {
		if (net_is_connected(r->fd)) {
			tcp_send_msg(r->fd, r->resp->wire, r->resp->size);
		} else {
			udp_send_msg(r->fd, r->resp->wire, r->resp->size,
			             (struct sockaddr *)&r->remote);
		}
		close(r->fd);
		knot_pkt_free(&r->query);
		knot_pkt_free(&r->resp);
		free(r);
	}
}

int updates_execute(zone_t *zone)
{
	/* Get list of pending updates. */
	list_t updates;
	zone_update_dequeue(zone, &updates);
	if (EMPTY_LIST(updates)) {
		return KNOT_EOK;
	}

	/* Init updates respones. */
	int ret = init_update_respones(&updates);
	if (ret != KNOT_EOK) {
#warning UPDATES lost, no responses!
		return ret;
	}

	/* Process update list - forward if zone has master, or execute. */
	if (zone_master(zone)) {
		forward_queries(zone, &updates);
	} else {
		ret = process_queries(zone, &updates);
	}
	UNUSED(ret); /* Don't care about the Knot code, RCODEs are set. */

	/* Send responses. */
	send_update_responses(&updates);

	return KNOT_EOK;
}

