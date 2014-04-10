#include "knot/nameserver/update.h"
#include "knot/nameserver/internet.h"
#include "knot/nameserver/process_query.h"
#include "knot/dnssec/zone-sign.h"
#include "common/debug.h"
#include "knot/dnssec/zone-events.h"
#include "knot/updates/ddns.h"
#include "common/descriptor.h"
#include "knot/server/zones.h"
#include "libknot/tsig-op.h"
#include "knot/zone/zone.h"

/* Forward decls. */
static int zones_process_update_auth(struct query_data *qdata);

/* AXFR-specific logging (internal, expects 'qdata' variable set). */
#define UPDATE_LOG(severity, msg...) \
	QUERY_LOG(severity, qdata, "UPDATE", msg)

static int update_forward(knot_pkt_t *pkt, struct query_data *qdata)
{
	/*! \todo This will be reimplemented when RESPONSE and REQUEST processors
	 *        are written. */

	zone_t* zone = (zone_t *)qdata->zone;
	knot_pkt_t *query = qdata->query;

	/* Check transport type. */
	unsigned flags = XFR_FLAG_TCP;
	if (qdata->param->proc_flags & NS_QUERY_LIMIT_SIZE) {
		flags = XFR_FLAG_UDP;
	}

	/* Prepare task. */
	knot_ns_xfr_t *rq = xfr_task_create(zone, XFR_TYPE_FORWARD, flags);
	if (!rq) {
		return NS_PROC_FAIL;
	}

	const conf_iface_t *master = zone_master(zone);
	xfr_task_setaddr(rq, &master->addr, &master->via);
	/* Don't set TSIG key, as it's only forwarded. */

	/* Copy query originator data. */
	rq->fwd_src_fd = qdata->param->query_socket;
	memcpy(&rq->fwd_addr, qdata->param->query_source, sizeof(struct sockaddr_storage));
	rq->packet_nr = knot_wire_get_id(query->wire);

	/* Duplicate query to keep it in memory during forwarding. */
	rq->query = knot_pkt_new(NULL, query->max_size, NULL);
	if (rq->query == NULL) {
		xfr_task_free(rq);
		return NS_PROC_FAIL;
	} else {
		memcpy(rq->query->wire, query->wire, query->size);
		rq->query->size = query->size;
	}

	/* Copy TSIG. */
	int ret = KNOT_EOK;
	if (query->tsig_rr) {
		ret = knot_tsig_append(rq->query->wire, &rq->query->size,
		                       rq->query->max_size, query->tsig_rr);
		if (ret != KNOT_EOK) {
			xfr_task_free(rq);
			return NS_PROC_FAIL;
		}
	}

#warning "XFR."
#if 0
	/* Retain pointer to zone and issue. */
	xfrhandler_t *xfr = qdata->param->server->xfr;
	ret = xfr_enqueue(xfr, rq);
	if (ret != KNOT_EOK) {
		xfr_task_free(rq);
		return NS_PROC_FAIL;
	}
#endif

	/* No immediate response. */
	pkt->size = 0;
	return NS_PROC_DONE;
}

static int update_prereq_check(struct query_data *qdata)
{
	knot_pkt_t *query = qdata->query;

	const zone_contents_t *contents = qdata->zone->contents;
	// DDNS Prerequisities Section processing (RFC2136, Section 3.2).
	return knot_ddns_process_prereqs(query, contents, &qdata->rcode);
}

static int update_process(knot_pkt_t *resp, struct query_data *qdata)
{
	/* Check prerequisites. */
	int ret = update_prereq_check(qdata);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/*! \todo Reusing the API for compatibility reasons. */
	return zones_process_update_auth(qdata);
}

int update_answer(knot_pkt_t *pkt, struct query_data *qdata)
{
	/* RFC1996 require SOA question. */
	NS_NEED_QTYPE(qdata, KNOT_RRTYPE_SOA, KNOT_RCODE_FORMERR);

	/* Check valid zone, transaction security and contents. */
	NS_NEED_ZONE(qdata, KNOT_RCODE_NOTAUTH);

	/* Allow pass-through of an unknown TSIG in DDNS forwarding (must have zone). */
	zone_t *zone = (zone_t *)qdata->zone;
	if (zone_master(zone) != NULL) {
		return update_forward(pkt, qdata);
	}

	/* Need valid transaction security. */
	NS_NEED_AUTH(zone->update_in, qdata);
	NS_NEED_ZONE_CONTENTS(qdata, KNOT_RCODE_SERVFAIL); /* Check expiration. */

	/*
	 * Check if UPDATE not running already.
	 */
	if (pthread_mutex_trylock(&zone->ddns_lock) != 0) {
		qdata->rcode = KNOT_RCODE_SERVFAIL;
		log_zone_error("Failed to process UPDATE for "
		               "zone %s: Another UPDATE in progress.\n",
		               zone->conf->name);
		return NS_PROC_FAIL;
	}

	/* Check if the zone is not discarded. */
	if (zone->flags & ZONE_DISCARDED) {
		pthread_mutex_unlock(&zone->ddns_lock);
		return NS_PROC_FAIL;
	}

	struct timeval t_start = {0}, t_end = {0};
	gettimeofday(&t_start, NULL);
	UPDATE_LOG(LOG_INFO, "Started (serial %u).", zone_contents_serial(qdata->zone->contents));

	/* Reserve space for TSIG. */
	knot_pkt_reserve(pkt, tsig_wire_maxsize(qdata->sign.tsig_key));

	/* Retain zone for the whole processing so it doesn't disappear
	 * for example during reload.
	 * @note This is going to be fixed when this is made a zone event. */
	zone_retain(zone);

	/* Process UPDATE. */
	rcu_read_unlock();
	int ret = update_process(pkt, qdata);
	rcu_read_lock();

	/* Since we unlocked RCU read lock, it is possible that the
	 * zone was modified/removed in the background. Therefore,
	 * we must NOT touch the zone after we release it here. */
	pthread_mutex_unlock(&zone->ddns_lock);
	zone_release(zone);
	qdata->zone = NULL;

	/* Evaluate */
	switch(ret) {
	case KNOT_EOK:    /* Last response. */
		gettimeofday(&t_end, NULL);
		UPDATE_LOG(LOG_INFO, "Finished in %.02fs.",
		           time_diff(&t_start, &t_end) / 1000.0);
		return NS_PROC_DONE;
		break;
	default:          /* Generic error. */
		UPDATE_LOG(LOG_ERR, "%s", knot_strerror(ret));
		return NS_PROC_FAIL;
	}
}

static int knot_ns_process_update(const knot_pkt_t *query,
                           zone_t *zone,
                           knot_changesets_t *chgs, uint16_t *rcode)
{
	if (query == NULL || zone == NULL || chgs == NULL ||
	    EMPTY_LIST(chgs->sets) || rcode == NULL) {
		return KNOT_EINVAL;
	}

	// Create changesets from UPDATE
	dbg_ns_verb("Applying the UPDATE and creating changeset...\n");
	int ret = knot_ddns_process_update(zone, query,
	                                   knot_changesets_get_last(chgs),
	                                   rcode);
	return ret;
}

static int replan_zone_sign_after_ddns(zone_t *zone, uint32_t refresh_at)
{
	assert(zone);

	return KNOT_DNSSEC_ENOTSUP;
#if 0
	if (zone->dnssec.timer->tv.tv_sec <= refresh_at) {
		return KNOT_EOK;
	}

	zones_cancel_dnssec(zone);
	return zones_schedule_dnssec(zone, refresh_at);
#endif
}

static bool apex_rr_changed(const zone_contents_t *old_contents,
                            const zone_contents_t *new_contents,
                            uint16_t type)
{
	knot_rrset_t old_rr = knot_node_rrset(old_contents->apex, type);
	knot_rrset_t new_rr = knot_node_rrset(new_contents->apex, type);

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
	return apex_rr_changed(old_contents, new_contents, KNOT_RRTYPE_NSEC3PARAM);
}

/*! \brief Process UPDATE query.
 *
 * Functions expects that the query is already authenticated
 * and TSIG signature is verified.
 *
 * \note Set parameter 'rcode' according to answering procedure.
 * \note Function expects RCU to be locked.
 *
 * \retval KNOT_EOK if successful.
 * \retval error if not.
 */
static int zones_process_update_auth(struct query_data *qdata)
{
	assert(qdata);
	assert(qdata->zone);

	zone_t *zone = (zone_t *)qdata->zone;
	conf_zone_t *zone_config = zone->conf;
	knot_tsig_key_t *tsig_key = qdata->sign.tsig_key;
	const struct sockaddr_storage *addr = qdata->param->query_source;

	/* Create log message prefix. */
	char *keytag = NULL;
	if (tsig_key) {
		keytag = knot_dname_to_str(tsig_key->name);
	}
	char *r_str = xfr_remote_str(addr, keytag);
	char *msg  = sprintf_alloc("UPDATE of '%s' from %s",
	                           zone_config->name, r_str ? r_str : "'unknown'");
	free(r_str);
	free(keytag);

	/*!
	 * We must prepare a changesets_t structure even though there will
	 * be only one changeset - because of the API.
	 */
	knot_changesets_t *chgsets = knot_changesets_create(1);
	if (chgsets == NULL) {
		qdata->rcode = KNOT_RCODE_SERVFAIL;
		log_zone_error("%s Cannot create changesets structure.\n", msg);
		free(msg);
		return KNOT_ENOMEM;
	}
	knot_changeset_t *diff_ch = knot_changesets_get_last(chgsets);

	// Process the UPDATE packet, create changesets.
	if (knot_changesets_create_changeset(chgsets) == NULL) {
		knot_changesets_free(&chgsets);
		free(msg);
		return KNOT_ENOMEM;
	}
	qdata->rcode = KNOT_RCODE_SERVFAIL; /* SERVFAIL unless it applies correctly. */

	zone_contents_t *new_contents = NULL;
	zone_contents_t *old_contents = zone->contents;
	int ret = knot_ns_process_update(qdata->query, zone, chgsets, &qdata->rcode);

	if (ret != KNOT_EOK) {
		knot_changesets_free(&chgsets);
		free(msg);
		return ret;
	}

	const bool change_made =
		!knot_changeset_is_empty(knot_changesets_get_last(chgsets));
	if (!change_made) {
		log_zone_notice("%s: No change to zone made.\n", msg);
		qdata->rcode = KNOT_RCODE_NOERROR;
		knot_changesets_free(&chgsets);
		free(msg);
		return KNOT_EOK;
	} else {
		ret = xfrin_apply_changesets(zone, chgsets, &new_contents);
		if (ret != KNOT_EOK) {
			log_zone_notice("%s: Failed to process: %s.\n", msg, knot_strerror(ret));
			qdata->rcode = KNOT_RCODE_SERVFAIL;
			knot_changesets_free(&chgsets);
			free(msg);
			return ret;
		}
	}

	assert(new_contents);

	knot_changesets_t *sec_chs = NULL;
	knot_changeset_t *sec_ch = NULL;
	uint32_t refresh_at = 0;

	if (zone_config->dnssec_enable) {
		sec_chs = knot_changesets_create(1);
		if (sec_chs == NULL) {
			xfrin_rollback_update(chgsets, &new_contents);
			knot_changesets_free(&chgsets);
			free(msg);
			return KNOT_ENOMEM;
		}

		sec_ch = knot_changesets_get_last(sec_chs);
	}

	// Apply changeset to zone created by DDNS processing
	if (zone_config->dnssec_enable) {
		/*!
		 * Check if the UPDATE changed DNSKEYs. If yes, resign the whole
		 * zone, if not, sign only the changeset.
		 * Do the same if NSEC3PARAM changed.
		 */
		if (zones_dnskey_changed(old_contents, new_contents) ||
		    zones_nsec3param_changed(old_contents, new_contents)) {
			ret = knot_dnssec_zone_sign(new_contents, zone_config,
			                            sec_ch,
			                            KNOT_SOA_SERIAL_KEEP,
			                            &refresh_at);
		} else {
			// Sign the created changeset
			ret = knot_dnssec_sign_changeset(new_contents, zone_config,
			                      diff_ch,
			                      sec_ch,
			                      &refresh_at);
		}

		if (ret != KNOT_EOK) {
			log_zone_error("%s: Failed to sign incoming update (%s)"
			               "\n", msg, knot_strerror(ret));
			xfrin_rollback_update(chgsets, &new_contents);
			knot_changesets_free(&chgsets);
			knot_changesets_free(&sec_chs);
			free(msg);
			return ret;
		}
	}

	// Merge changesets
	ret = knot_changeset_merge(diff_ch, sec_ch);
	if (ret != KNOT_EOK) {
		log_zone_error("%s: Failed to save new entry to journal (%s)\n",
		               msg, knot_strerror(ret));
		xfrin_rollback_update(chgsets, &new_contents);
		knot_changesets_free_merged(chgsets, sec_chs);
		free(msg);
		return ret;
	}

	// Apply DNSSEC changeset
	bool new_signatures = !knot_changeset_is_empty(sec_ch);
	if (new_signatures) {
		ret = xfrin_apply_changesets_dnssec_ddns(new_contents,
		                                         sec_chs,
		                                         chgsets);
		if (ret != KNOT_EOK) {
			log_zone_error("%s: Failed to sign incoming update (%s)"
			               "\n", msg, knot_strerror(ret));
			xfrin_rollback_update(chgsets, &new_contents);
			xfrin_rollback_update(sec_chs, &new_contents);
			knot_changesets_free_merged(chgsets, sec_chs);
			free(msg);
			return ret;
		}

		// Plan zone resign if needed
//		assert(zone->dnssec.timer);
		ret = replan_zone_sign_after_ddns(zone, refresh_at);
		if (ret != KNOT_EOK) {
			log_zone_error("%s: Failed to replan zone sign (%s)\n",
			               msg, knot_strerror(ret));
			xfrin_rollback_update(chgsets, &new_contents);
			xfrin_rollback_update(sec_chs, &new_contents);
			knot_changesets_free_merged(chgsets, sec_chs);
			free(msg);
			return ret;
		}
	} else {
		// Set NSEC3 nodes if no new signatures were created (or auto DNSSEC is off)
		ret = zone_contents_adjust_nsec3_pointers(new_contents);
		if (ret != KNOT_EOK) {
			xfrin_rollback_update(chgsets, &new_contents);
			knot_changesets_free_merged(chgsets, sec_chs);
			free(msg);
			return ret;
		}
	}

#warning Journal is unprotected now, this will not be safe until DDNS is made a zone event.
	/* Write changes to journal if all went well. */
	ret = zone_change_store(zone, chgsets);

	// Switch zone contents.
	old_contents = xfrin_switch_zone(zone, new_contents);
	xfrin_zone_contents_free(&old_contents);

	// Cleanup.
	xfrin_cleanup_successful_update(chgsets);
	xfrin_cleanup_successful_update(sec_chs);

	// Free changesets, but not the data.
	knot_changesets_free_merged(chgsets, sec_chs);
	assert(ret == KNOT_EOK);
	qdata->rcode = KNOT_RCODE_NOERROR; /* Mark as successful. */
	if (new_signatures) {
		log_zone_info("%s: Successfuly signed.\n", msg);
	}

	free(msg);
	msg = NULL;

	/* Trim extra heap. */
	mem_trim();

	/* Sync zonefile immediately if configured. */
	if (zone_config->dbsync_timeout == 0) {
#warning Implement me (schedule zone file flush to now)
	}

	return ret;
}

#undef UPDATE_LOG
