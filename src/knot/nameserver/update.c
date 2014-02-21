#include <config.h>

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

/* Forward decls. */
static int zones_process_update_auth(zone_t *zone, knot_pkt_t *query,
                              knot_rcode_t *rcode, const struct sockaddr_storage *addr,
                              knot_tsig_key_t *tsig_key);

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

	/* Retain pointer to zone and issue. */
	xfrhandler_t *xfr = qdata->param->server->xfr;
	ret = xfr_enqueue(xfr, rq);
	if (ret != KNOT_EOK) {
		xfr_task_free(rq);
		return NS_PROC_FAIL;
	}

	/* No immediate response. */
	pkt->size = 0;
	return NS_PROC_DONE;
}

static int update_prereq_check(struct query_data *qdata)
{
	knot_pkt_t *query = qdata->query;
	const knot_zone_contents_t *contents = qdata->zone->contents;

	/*
	 * 2) DDNS Prerequisities Section processing (RFC2136, Section 3.2).
	 *
	 * \note Permissions section means probably policies and fine grained
	 *       access control, not transaction security.
	 */
	knot_rcode_t rcode = KNOT_RCODE_NOERROR;
	knot_ddns_prereq_t *prereqs = NULL;
	int ret = knot_ddns_process_prereqs(query, &prereqs, &rcode);
	if (ret == KNOT_EOK) {
		ret = knot_ddns_check_prereqs(contents, &prereqs, &rcode);
		knot_ddns_prereqs_free(&prereqs);
	}
	qdata->rcode = rcode;

	return ret;
}

static int update_process(knot_pkt_t *resp, struct query_data *qdata)
{
	/* Check prerequisites. */
	int ret = update_prereq_check(qdata);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/*! \todo Reusing the API for compatibility reasons. */
	knot_rcode_t rcode = qdata->rcode;
	ret = zones_process_update_auth((zone_t *)qdata->zone, qdata->query,
	                                &rcode,
	                                qdata->param->query_source,
	                                qdata->sign.tsig_key);
	qdata->rcode = rcode;
	return ret;
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

	struct timeval t_start = {0}, t_end = {0};
	gettimeofday(&t_start, NULL);
	UPDATE_LOG(LOG_INFO, "Started (serial %u).", knot_zone_serial(qdata->zone->contents));

	/* Reserve space for TSIG. */
	knot_pkt_reserve(pkt, tsig_wire_maxsize(qdata->sign.tsig_key));

	/* Process UPDATE. */
	int ret = update_process(pkt, qdata);

	pthread_mutex_unlock(&zone->ddns_lock);

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

/*
 * This function should:
 * 1) Create zone shallow copy and the changes structure.
 * 2) Call knot_ddns_process_update().
 *    - If something went bad, call xfrin_rollback_update() and return an error.
 *    - If everything went OK, continue.
 * 3) Finalize the updated zone.
 *
 * NOTE: Mostly copied from xfrin_apply_changesets(). Should be refactored in
 *       order to get rid of duplicate code.
 */
int knot_ns_process_update(const knot_pkt_t *query,
                           knot_zone_contents_t *old_contents,
                           knot_zone_contents_t **new_contents,
                           knot_changesets_t *chgs, knot_rcode_t *rcode,
                           uint32_t new_serial)
{
	if (query == NULL || old_contents == NULL || chgs == NULL ||
	    EMPTY_LIST(chgs->sets) || new_contents == NULL || rcode == NULL) {
		return KNOT_EINVAL;
	}

	dbg_ns("Applying UPDATE to zone...\n");

	// 1) Create zone shallow copy.
	dbg_ns_verb("Creating shallow copy of the zone...\n");
	knot_zone_contents_t *contents_copy = NULL;
	int ret = xfrin_prepare_zone_copy(old_contents, &contents_copy);
	if (ret != KNOT_EOK) {
		dbg_ns("Failed to prepare zone copy: %s\n",
		          knot_strerror(ret));
		*rcode = KNOT_RCODE_SERVFAIL;
		return ret;
	}

	// 2) Apply the UPDATE and create changesets.
	dbg_ns_verb("Applying the UPDATE and creating changeset...\n");
	ret = knot_ddns_process_update(contents_copy, query,
	                               knot_changesets_get_last(chgs),
	                               chgs->changes, rcode, new_serial);
	if (ret != KNOT_EOK) {
		dbg_ns("Failed to apply UPDATE to the zone copy or no update"
		       " made: %s\n", (ret < 0) ? knot_strerror(ret)
		                                : "No change made.");
		xfrin_rollback_update(old_contents, &contents_copy,
		                      chgs->changes);
		return ret;
	}

	// 3) Finalize zone
	dbg_ns_verb("Finalizing updated zone...\n");
	ret = xfrin_finalize_updated_zone(contents_copy, false,
	                                  NULL);
	if (ret != KNOT_EOK) {
		dbg_ns("Failed to finalize updated zone: %s\n",
		       knot_strerror(ret));
		xfrin_rollback_update(old_contents, &contents_copy,
		                      chgs->changes);
		*rcode = (ret == KNOT_EMALF) ? KNOT_RCODE_FORMERR
		                             : KNOT_RCODE_SERVFAIL;
		return ret;
	}

	*new_contents = contents_copy;

	return KNOT_EOK;
}

static int replan_zone_sign_after_ddns(zone_t *zone, uint32_t refresh_at)
{
	assert(zone);

	if (zone->dnssec.timer->tv.tv_sec <= refresh_at) {
		return KNOT_EOK;
	}

	zones_cancel_dnssec(zone);
	return zones_schedule_dnssec(zone, refresh_at);
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
static int zones_process_update_auth(zone_t *zone, knot_pkt_t *query,
                              knot_rcode_t *rcode, const struct sockaddr_storage *addr,
                              knot_tsig_key_t *tsig_key)
{
	assert(zone);
	assert(query);
	assert(rcode);
	assert(addr);

	int ret = KNOT_EOK;

	/* Create log message prefix. */
	char *keytag = NULL;
	if (tsig_key) {
		keytag = knot_dname_to_str(tsig_key->name);
	}
	char *r_str = xfr_remote_str(addr, keytag);
	char *msg  = sprintf_alloc("UPDATE of '%s' from %s",
	                           zone->conf->name, r_str ? r_str : "'unknown'");
	free(r_str);
	free(keytag);

	/*!
	 * We must prepare a changesets_t structure even though there will
	 * be only one changeset - because of the API.
	 */
	knot_changesets_t *chgsets = knot_changesets_create();
	if (chgsets == NULL) {
		*rcode = KNOT_RCODE_SERVFAIL;
		log_zone_error("%s Cannot create changesets structure.\n", msg);
		free(msg);
		return ret;
	}

	// Process the UPDATE packet, apply to zone, create changesets.
	if (knot_changesets_create_changeset(chgsets) == NULL) {
		return KNOT_ENOMEM;
	}
	*rcode = KNOT_RCODE_SERVFAIL; /* SERVFAIL unless it applies correctly. */

	uint32_t new_serial = zones_next_serial(zone);

	knot_zone_contents_t *new_contents = NULL;
	knot_zone_contents_t *old_contents = zone->contents;
	ret = knot_ns_process_update(query, old_contents, &new_contents,
	                             chgsets, rcode, new_serial);
	if (ret != KNOT_EOK) {
		if (ret > 0) {
			log_zone_notice("%s: No change to zone made.\n", msg);
			*rcode = KNOT_RCODE_NOERROR;
		}

		knot_changesets_free(&chgsets);
		free(msg);
		return (ret < 0) ? ret : KNOT_EOK;
	}

	knot_changesets_t *sec_chs = NULL;
	knot_changeset_t *sec_ch = NULL;
	uint32_t refresh_at = 0;

	assert(zone->conf);
	if (zone->conf->dnssec_enable) {
		sec_chs = knot_changesets_create();
		sec_ch = knot_changesets_create_changeset(sec_chs);
		if (sec_chs == NULL || sec_ch == NULL) {
			xfrin_rollback_update(zone->contents, &new_contents,
			                      chgsets->changes);
			knot_changesets_free(&chgsets);
			free(msg);
			return KNOT_ENOMEM;
		}
	}

	// Apply changeset to zone created by DDNS processing

	hattrie_t *sorted_changes = NULL;

	if (zone->conf->dnssec_enable) {
		/*!
		 * Check if the UPDATE changed DNSKEYs. If yes, resign the whole
		 * zone, if not, sign only the changeset.
		 * Do the same if NSEC3PARAM changed.
		 */
		if (zones_dnskey_changed(old_contents, new_contents) ||
		    zones_nsec3param_changed(old_contents, new_contents)) {
			ret = knot_dnssec_zone_sign(new_contents, zone->conf,
			                            sec_ch,
			                            KNOT_SOA_SERIAL_KEEP,
			                            &refresh_at, new_serial);
		} else {
			// Sign the created changeset
			ret = knot_dnssec_sign_changeset(new_contents, zone->conf,
			                      knot_changesets_get_last(chgsets),
			                      sec_ch, KNOT_SOA_SERIAL_KEEP,
			                      &refresh_at,
			                      new_serial, &sorted_changes);
		}

		if (ret != KNOT_EOK) {
			log_zone_error("%s: Failed to sign incoming update (%s)"
			               "\n", msg, knot_strerror(ret));
			xfrin_rollback_update(zone->contents, &new_contents,
					      chgsets->changes);
			knot_changesets_free(&chgsets);
			knot_changesets_free(&sec_chs);
			free(msg);
			return ret;
		}
	}

	// Merge changesets
	journal_t *transaction = NULL;
	ret = zones_merge_and_store_changesets(zone, chgsets, sec_chs,
	                                       &transaction);
	if (ret != KNOT_EOK) {
		log_zone_error("%s: Failed to save new entry to journal (%s)\n",
		               msg, knot_strerror(ret));
		xfrin_rollback_update(zone->contents, &new_contents,
		                      chgsets->changes);
		zones_free_merged_changesets(chgsets, sec_chs);
		free(msg);
		return ret;
	}

	bool new_signatures = !knot_changeset_is_empty(sec_ch);
	// Apply DNSSEC changeset
	if (new_signatures) {
		ret = xfrin_apply_changesets_dnssec_ddns(old_contents,
		                                    new_contents,
		                                    sec_chs,
		                                    chgsets,
		                                    sorted_changes);
		knot_zone_clear_sorted_changes(sorted_changes);
		hattrie_free(sorted_changes);
		if (ret != KNOT_EOK) {
			log_zone_error("%s: Failed to sign incoming update (%s)"
			               "\n", msg, knot_strerror(ret));
			zones_store_changesets_rollback(transaction);
			zones_free_merged_changesets(chgsets, sec_chs);
			return ret;
		}

		// Plan zone resign if needed
		assert(zone->dnssec.timer);
		ret = replan_zone_sign_after_ddns(zone, refresh_at);
		if (ret != KNOT_EOK) {
			log_zone_error("%s: Failed to replan zone sign (%s)\n",
			               msg, knot_strerror(ret));
			zones_store_changesets_rollback(transaction);
			zones_free_merged_changesets(chgsets, sec_chs);
			return ret;
		}
	} else {
		// Set NSEC3 nodes if no new signatures were created (or auto DNSSEC is off)
		ret = knot_zone_contents_adjust_nsec3_pointers(new_contents);
		if (ret != KNOT_EOK) {
			zones_store_changesets_rollback(transaction);
			zones_free_merged_changesets(chgsets, sec_chs);
			xfrin_rollback_update(zone->contents, &new_contents,
			                      chgsets->changes);
			free(msg);
			return ret;
		}
	}

	// Commit transaction.
	if (transaction) {
		ret = zones_store_changesets_commit(transaction);
		if (ret != KNOT_EOK) {
			log_zone_error("%s: Failed to commit new journal entry "
			               "(%s).\n", msg, knot_strerror(ret));
			xfrin_rollback_update(zone->contents, &new_contents,
			                      chgsets->changes);
			zones_free_merged_changesets(chgsets, sec_chs);
			free(msg);
			return ret;
		}
	}

	// Switch zone contents.
	zone_retain(zone);      /* Retain pointer for safe RCU unlock. */
	rcu_read_unlock();      /* Unlock for switch. */
	ret = xfrin_switch_zone(zone, new_contents, XFR_TYPE_UPDATE);
	rcu_read_lock();        /* Relock */
	zone_release(zone);     /* Release held pointer. */
	if (ret != KNOT_EOK) {
		log_zone_error("%s: Failed to replace current zone (%s)\n",
		               msg, knot_strerror(ret));
		// Cleanup old and new contents
		xfrin_rollback_update(zone->contents, &new_contents,
		                      chgsets->changes);

		/* Free changesets, but not the data. */
		zones_free_merged_changesets(chgsets, sec_chs);
		return KNOT_ERROR;
	}

	// Cleanup.
	xfrin_cleanup_successful_update(chgsets->changes);
	if (sec_chs) {
		xfrin_cleanup_successful_update(sec_chs->changes);
	}

	// Free changesets, but not the data.
	zones_free_merged_changesets(chgsets, sec_chs);
	assert(ret == KNOT_EOK);
	*rcode = KNOT_RCODE_NOERROR; /* Mark as successful. */
	if (new_signatures) {
		log_zone_info("%s: Successfuly signed.\n", msg);
	}

	free(msg);
	msg = NULL;

	/* Trim extra heap. */
	mem_trim();

	/* Sync zonefile immediately if configured. */
	if (zone->conf->dbsync_timeout == 0) {
		zones_schedule_zonefile_sync(zone, 0);
	}

	return ret;
}

#undef UPDATE_LOG
