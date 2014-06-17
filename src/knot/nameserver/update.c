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

/* UPDATE-specific logging (internal, expects 'qdata' variable set). */
#define UPDATE_LOG(severity, msg...) \
	QUERY_LOG(severity, qdata, "UPDATE", msg)

static int update_forward(knot_pkt_t *pkt, struct query_data *qdata)
{
	/*! \todo ref #244 This will be reimplemented later. */
	qdata->rcode = KNOT_RCODE_NOTIMPL;
	return NS_PROC_FAIL;
}

int update_answer(knot_pkt_t *pkt, struct query_data *qdata)
{
	/* RFC1996 require SOA question. */
	NS_NEED_QTYPE(qdata, KNOT_RRTYPE_SOA, KNOT_RCODE_FORMERR);

	/* Check valid zone. */
	NS_NEED_ZONE(qdata, KNOT_RCODE_NOTAUTH);

	/* Allow pass-through of an unknown TSIG in DDNS forwarding
	   (must have zone). */
	zone_t *zone = (zone_t *)qdata->zone;
	if (zone_master(zone) != NULL) {
		return update_forward(pkt, qdata);
	}

	/* Need valid transaction security. */
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
                       zone_contents_t *new_contents, changeset_t *ddns_ch)
{
	assert(zone != NULL);
	assert(old_contents != NULL);
	assert(new_contents != NULL);
	assert(ddns_ch != NULL);

	changesets_t *sec_chs = changesets_create(1);
	if (sec_chs == NULL) {
		return KNOT_ENOMEM;
	}
	changeset_t *sec_ch = changesets_get_last(sec_chs);

	/*
	 * Check if the UPDATE changed DNSKEYs or NSEC3PARAM.
	 * If yes, signing just the changes is insufficient, we have to sign
	 * the whole zone.
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
		changesets_free(&sec_chs, NULL);
		return ret;
	}

	// Apply DNSSEC changeset
	ret = apply_changesets_directly(new_contents, sec_chs);
	if (ret != KNOT_EOK) {
		changesets_free(&sec_chs, NULL);
		return ret;
	}

	// Merge changesets
	ret = changeset_merge(ddns_ch, sec_ch);
	if (ret != KNOT_EOK) {
		changesets_free(&sec_chs, NULL);
		return ret;
	}

	// Free the DNSSEC changeset's SOA from (not used anymore)
	knot_rrset_free(&sec_ch->soa_from, NULL);
	// Shallow free DNSSEC changesets
	free(sec_chs);

	// Plan next zone resign.
	const time_t resign_time = zone_events_get_time(zone, ZONE_EVENT_DNSSEC);
	if (time(NULL) + refresh_at < resign_time) {
		zone_events_schedule(zone, ZONE_EVENT_DNSSEC, refresh_at);
	}
	return ret;
}

static int process_authenticated(uint16_t *rcode, struct query_data *qdata)
{
	assert(rcode);
	assert(qdata);

	const knot_pkt_t *query = qdata->query;
	zone_t *zone = (zone_t *)qdata->zone;

	int ret = ddns_process_prereqs(query, zone->contents, rcode);
	if (ret != KNOT_EOK) {
		assert(*rcode != KNOT_RCODE_NOERROR);
		return ret;
	}

	// Create DDNS changesets
	changesets_t *ddns_chs = changesets_create(1);
	if (ddns_chs == NULL) {
		*rcode = KNOT_RCODE_SERVFAIL;
		return KNOT_ENOMEM;
	}
	changeset_t *ddns_ch = changesets_get_last(ddns_chs);
	ret = ddns_process_update(zone, query, ddns_ch, rcode);
	if (ret != KNOT_EOK) {
		assert(*rcode != KNOT_RCODE_NOERROR);
		changesets_free(&ddns_chs, NULL);
		return ret;
	}
	assert(*rcode == KNOT_RCODE_NOERROR);

	zone_contents_t *new_contents = NULL;
	const bool change_made = !changeset_is_empty(ddns_ch);
	if (change_made) {
		ret = apply_changesets(zone, ddns_chs, &new_contents);
		if (ret != KNOT_EOK) {
			if (ret == KNOT_ETTL) {
				*rcode = KNOT_RCODE_REFUSED;
			} else {
				*rcode = KNOT_RCODE_SERVFAIL;
			}
			changesets_free(&ddns_chs, NULL);
			return ret;
		}
	} else {
		changesets_free(&ddns_chs, NULL);
		*rcode = KNOT_RCODE_NOERROR;
		return KNOT_EOK;
	}
	assert(new_contents);

	if (zone->conf->dnssec_enable) {
		ret = sign_update(zone, zone->contents, new_contents, ddns_ch);
		if (ret != KNOT_EOK) {
			update_rollback(ddns_chs, &new_contents);
			changesets_free(&ddns_chs, NULL);
			*rcode = KNOT_RCODE_SERVFAIL;
			return ret;
		}
	}

	// Write changes to journal if all went well. (DNSSEC merged)
	ret = zone_change_store(zone, ddns_chs);
	if (ret != KNOT_EOK) {
		update_rollback(ddns_chs, &new_contents);
		changesets_free(&ddns_chs, NULL);
		*rcode = KNOT_RCODE_SERVFAIL;
		return ret;
	}

	// Switch zone contents.
	zone_contents_t *old_contents = zone_switch_contents(zone, new_contents);
	synchronize_rcu();
	update_free_old_zone(&old_contents);

	update_cleanup(ddns_chs);
	changesets_free(&ddns_chs, NULL);

	/* Sync zonefile immediately if configured. */
	if (zone->conf->dbsync_timeout == 0) {
		zone_events_schedule(zone, ZONE_EVENT_FLUSH, ZONE_EVENT_NOW);
	}

	*rcode = KNOT_RCODE_NOERROR;
	return ret;
}


int update_process_query(knot_pkt_t *pkt, struct query_data *qdata)
{
	if (pkt == NULL || qdata == NULL) {
		return KNOT_EINVAL;
	}

	UPDATE_LOG(LOG_INFO, "Started.");

	/* Keep original state. */
	struct timeval t_start, t_end;
	gettimeofday(&t_start, NULL);
	zone_t *zone = (zone_t *)qdata->zone;
	const uint32_t old_serial = zone_contents_serial(zone->contents);

	/* Process authenticated packet. */
	uint16_t rcode = KNOT_RCODE_NOERROR;
	int ret = process_authenticated(&rcode, qdata);
	if (ret != KNOT_EOK) {
		assert(rcode != KNOT_RCODE_NOERROR);
		UPDATE_LOG(LOG_ERR, "%s", knot_strerror(ret));
		knot_wire_set_rcode(pkt->wire, rcode);
		return ret;
	}

	/* Evaluate response. */
	const uint32_t new_serial = zone_contents_serial(zone->contents);
	if (new_serial == old_serial) {
		assert(rcode == KNOT_RCODE_NOERROR);
		UPDATE_LOG(LOG_NOTICE, "No change to zone made.");
		return KNOT_EOK;
	}

	gettimeofday(&t_end, NULL);
	UPDATE_LOG(LOG_INFO, "Serial %u -> %u", old_serial, new_serial);
	UPDATE_LOG(LOG_INFO, "Finished in %.02fs.",
	           time_diff(&t_start, &t_end) / 1000.0);
	
	zone_events_schedule(zone, ZONE_EVENT_NOTIFY, ZONE_EVENT_NOW);

	return KNOT_EOK;
}

#undef UPDATE_LOG
