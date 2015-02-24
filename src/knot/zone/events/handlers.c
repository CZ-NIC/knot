/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "dnssec/random.h"
#include "libknot/libknot.h"
#include "libknot/processing/requestor.h"
#include "libknot/rrtype/soa.h"

#include "knot/common/trim.h"
#include "libknot/internal/mempool.h"
#include "libknot/internal/macros.h"

#include "knot/server/udp-handler.h"
#include "knot/server/tcp-handler.h"
#include "knot/updates/changesets.h"
#include "knot/dnssec/zone-events.h"
#include "knot/zone/timers.h"
#include "knot/zone/zone-load.h"
#include "knot/zone/zonefile.h"
#include "knot/zone/events/events.h"
#include "knot/zone/events/handlers.h"
#include "knot/updates/apply.h"
#include "knot/nameserver/internet.h"
#include "knot/nameserver/update.h"
#include "knot/nameserver/notify.h"
#include "knot/nameserver/tsig_ctx.h"
#include "knot/nameserver/process_answer.h"

#define BOOTSTRAP_RETRY (30) /*!< Interval between AXFR bootstrap retries. */
#define BOOTSTRAP_MAXTIME (24*60*60) /*!< Maximum AXFR retry cap of 24 hours. */

/* ------------------------- zone query requesting -------------------------- */

/*! \brief Zone event logging. */
#define ZONE_QUERY_LOG(severity, zone, remote, operation, msg...) \
	NS_PROC_LOG(severity, &remote->addr, zone->name, operation, msg)

/*! \brief Create zone query packet. */
static knot_pkt_t *zone_query(const zone_t *zone, uint16_t pkt_type, mm_ctx_t *mm)
{
	/* Determine query type and opcode. */
	uint16_t query_type = KNOT_RRTYPE_SOA;
	uint16_t opcode = KNOT_OPCODE_QUERY;
	switch(pkt_type) {
	case KNOT_QUERY_AXFR: query_type = KNOT_RRTYPE_AXFR; break;
	case KNOT_QUERY_IXFR: query_type = KNOT_RRTYPE_IXFR; break;
	case KNOT_QUERY_NOTIFY: opcode = KNOT_OPCODE_NOTIFY; break;
	}

	knot_pkt_t *pkt = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, mm);
	if (pkt == NULL) {
		return NULL;
	}

	knot_wire_set_id(pkt->wire, dnssec_random_uint16_t());
	knot_wire_set_aa(pkt->wire);
	knot_wire_set_opcode(pkt->wire, opcode);
	knot_pkt_put_question(pkt, zone->name, KNOT_CLASS_IN, query_type);

	/* Put current SOA (optional). */
	zone_contents_t *contents = zone->contents;
	if (pkt_type == KNOT_QUERY_IXFR) {  /* RFC1995, SOA in AUTHORITY. */
		knot_pkt_begin(pkt, KNOT_AUTHORITY);
		knot_rrset_t soa_rr = node_rrset(contents->apex, KNOT_RRTYPE_SOA);
		knot_pkt_put(pkt, KNOT_COMPR_HINT_QNAME, &soa_rr, 0);
	} else if (pkt_type == KNOT_QUERY_NOTIFY) { /* RFC1996, SOA in ANSWER. */
		knot_pkt_begin(pkt, KNOT_ANSWER);
		knot_rrset_t soa_rr = node_rrset(contents->apex, KNOT_RRTYPE_SOA);
		knot_pkt_put(pkt, KNOT_COMPR_HINT_QNAME, &soa_rr, 0);
	}

	return pkt;
}

/*!
 * \brief Create a zone event query, send it, wait for the response and process it.
 *
 * \note Everything in this function is executed synchronously, returns when
 *       the query processing is either complete or an error occurs.
 */
static int zone_query_execute(zone_t *zone, uint16_t pkt_type, const conf_iface_t *remote)
{
	/* Create a memory pool for this task. */
	int ret = KNOT_EOK;
	mm_ctx_t mm;
	mm_ctx_mempool(&mm, MM_DEFAULT_BLKSIZE);

	/* Create a query message. */
	knot_pkt_t *query = zone_query(zone, pkt_type, &mm);
	if (query == NULL) {
		return KNOT_ENOMEM;
	}

	/* Answer processing parameters. */
	struct process_answer_param param = { 0 };
	param.zone = zone;
	param.query = query;
	param.remote = &remote->addr;

	/* Create requestor instance. */
	struct knot_requestor re;
	knot_requestor_init(&re, &mm);
	knot_requestor_overlay(&re, KNOT_STATE_ANSWER, &param);

	tsig_init(&param.tsig_ctx, remote->key);

	ret = tsig_sign_packet(&param.tsig_ctx, query);
	if (ret != KNOT_EOK) {
		goto fail;
	}

	/* Create a request. */
	const struct sockaddr *dst = (const struct sockaddr *)&remote->addr;
	const struct sockaddr *src = (const struct sockaddr *)&remote->via;
	struct knot_request *req = knot_request_make(re.mm, dst, src, query, 0);
	if (req == NULL) {
		ret = KNOT_ENOMEM;
		goto fail;
	}

	/* Send the queries and process responses. */
	ret = knot_requestor_enqueue(&re, req);
	if (ret == KNOT_EOK) {
		struct timeval tv = { conf()->max_conn_reply, 0 };
		ret = knot_requestor_exec(&re, &tv);
	}

fail:
	/* Cleanup. */
	tsig_cleanup(&param.tsig_ctx);
	knot_requestor_clear(&re);
	mp_delete(mm.ctx);

	return ret;
}

/* @note Module specific, expects some variables set. */
#define ZONE_XFER_LOG(severity, pkt_type, msg...) \
	if (pkt_type == KNOT_QUERY_AXFR) { \
		ZONE_QUERY_LOG(severity, zone, master, "AXFR, incoming", msg); \
	} else { \
		ZONE_QUERY_LOG(severity, zone, master, "IXFR, incoming", msg); \
	}

/*! \brief Execute zone transfer request. */
static int zone_query_transfer(zone_t *zone, const conf_iface_t *master, uint16_t pkt_type)
{
	assert(zone);
	assert(master);

	int ret = zone_query_execute(zone, pkt_type, master);
	if (ret != KNOT_EOK) {
		/* IXFR failed, revert to AXFR. */
		if (pkt_type == KNOT_QUERY_IXFR) {
			ZONE_XFER_LOG(LOG_NOTICE, pkt_type, "fallback to AXFR");
			return zone_query_transfer(zone, master, KNOT_QUERY_AXFR);
		}

		/* Log connection errors. */
		ZONE_XFER_LOG(LOG_ERR, pkt_type, "failed (%s)", knot_strerror(ret));
	}

	return ret;
}

#undef ZONE_XFER_LOG

/*!
 * \todo Separate signing from zone loading and drop this function.
 *
 * DNSSEC signing is planned from two places - after zone loading and after
 * successful resign. This function just logs the message and reschedules the
 * DNSSEC timer.
 *
 * I would rather see the invocation of the signing from event_dnssec()
 * function. This would require to split refresh event to zone load and zone
 * publishing.
 */
static void schedule_dnssec(zone_t *zone, time_t refresh_at)
{
	// log a message

	char time_str[64] = { 0 };
	struct tm time_gm = { 0 };
	localtime_r(&refresh_at, &time_gm);
	strftime(time_str, sizeof(time_str), KNOT_LOG_TIME_FORMAT, &time_gm);
	log_zone_info(zone->name, "DNSSEC, next signing on %s", time_str);

	// schedule

	zone_events_schedule_at(zone, ZONE_EVENT_DNSSEC, refresh_at);
}

/*! \brief Get SOA from zone. */
static const knot_rdataset_t *zone_soa(zone_t *zone)
{
	return node_rdataset(zone->contents->apex, KNOT_RRTYPE_SOA);
}

/*! \brief Fetch SOA expire timer and add a timeout grace period. */
static uint32_t soa_graceful_expire(const knot_rdataset_t *soa)
{
	// Allow for timeouts.  Otherwise zones with very short
	// expiry may expire before the timeout is reached.
	return knot_soa_expire(soa) + 2 * conf()->max_conn_idle;
}

/*! \brief Schedule expire event, unless it is already scheduled. */
static void start_expire_timer(zone_t *zone, const knot_rdataset_t *soa)
{
	if (zone_events_is_scheduled(zone, ZONE_EVENT_EXPIRE)) {
		return;
	}

	zone_events_schedule(zone, ZONE_EVENT_EXPIRE, soa_graceful_expire(soa));
}

/* -- zone events handling callbacks --------------------------------------- */

int event_reload(zone_t *zone)
{
	assert(zone);

	/* Take zone file mtime and load it. */
	time_t mtime = zonefile_mtime(zone->conf->file);
	uint32_t dnssec_refresh = time(NULL);
	conf_zone_t *zone_config = zone->conf;
	zone_contents_t *contents = zone_load_contents(zone_config);
	if (!contents) {
		return KNOT_ERROR;
	}

	/* Store zonefile serial and apply changes from the journal. */
	zone->zonefile_serial = zone_contents_serial(contents);
	int result = zone_load_journal(zone, contents);
	if (result != KNOT_EOK) {
		goto fail;
	}

	/* Post load actions - calculate delta, sign with DNSSEC... */
	/*! \todo issue #242 dnssec signing should occur in the special event */
	result = zone_load_post(contents, zone, &dnssec_refresh);
	if (result != KNOT_EOK) {
		if (result == KNOT_ESPACE) {
			log_zone_error(zone->name, "journal size is too small "
			               "to fit the changes");
		} else {
			log_zone_error(zone->name, "failed to store changes into "
			               "journal (%s)", knot_strerror(result));
		}
		goto fail;
	}

	/* Check zone contents consistency. */
	result = zone_load_check(contents, zone_config);
	if (result != KNOT_EOK) {
		goto fail;
	}

	/* Everything went alright, switch the contents. */
	zone->zonefile_mtime = mtime;
	zone_contents_t *old = zone_switch_contents(zone, contents);
	uint32_t old_serial = zone_contents_serial(old);
	if (old != NULL) {
		synchronize_rcu();
		zone_contents_deep_free(&old);
	}

	/* Schedule notify and refresh after load. */
	if (zone_master(zone)) {
		zone_events_schedule(zone, ZONE_EVENT_REFRESH, ZONE_EVENT_NOW);
	}
	if (!zone_contents_is_empty(contents)) {
		zone_events_schedule(zone, ZONE_EVENT_NOTIFY, ZONE_EVENT_NOW);
		zone->bootstrap_retry = ZONE_EVENT_NOW;
	}

	/* Schedule zone resign. */
	if (zone->conf->dnssec_enable) {
		schedule_dnssec(zone, dnssec_refresh);
	}

	/* Periodic execution. */
	zone_events_schedule(zone, ZONE_EVENT_FLUSH, zone_config->dbsync_timeout);

	uint32_t current_serial = zone_contents_serial(zone->contents);
	log_zone_info(zone->name, "loaded, serial %u -> %u",
	              old_serial, current_serial);

	return zone_events_write_persistent(zone);

fail:
	zone_contents_deep_free(&contents);
	return result;
}

int event_refresh(zone_t *zone)
{
	assert(zone);

	const conf_iface_t *master = zone_master(zone);
	if (master == NULL) {
		/* If not slave zone, ignore. */
		return KNOT_EOK;
	}

	if (zone_contents_is_empty(zone->contents)) {
		/* No contents, schedule retransfer now. */
		zone_events_schedule(zone, ZONE_EVENT_XFER, ZONE_EVENT_NOW);
		return KNOT_EOK;
	}

	int ret = zone_query_execute(zone, KNOT_QUERY_NORMAL, master);
	const knot_rdataset_t *soa = zone_soa(zone);
	if (ret != KNOT_EOK) {
		/* Log connection errors. */
		ZONE_QUERY_LOG(LOG_WARNING, zone, master, "SOA query, outgoing",
		               "failed (%s)", knot_strerror(ret));
		/* Rotate masters if current failed. */
		zone_master_rotate(zone);
		/* Schedule next retry. */
		zone_events_schedule(zone, ZONE_EVENT_REFRESH, knot_soa_retry(soa));
		start_expire_timer(zone, soa);
	} else {
		/* SOA query answered, reschedule refresh timer. */
		zone_events_schedule(zone, ZONE_EVENT_REFRESH, knot_soa_refresh(soa));
	}

	return zone_events_write_persistent(zone);
}

int event_xfer(zone_t *zone)
{
	assert(zone);

	const conf_iface_t *master = zone_master(zone);
	if (master == NULL) {
		/* If not slave zone, ignore. */
		return KNOT_EOK;
	}

	/* Determine transfer type. */
	bool is_boostrap = zone_contents_is_empty(zone->contents);
	uint16_t pkt_type = KNOT_QUERY_IXFR;
	if (is_boostrap || zone->flags & ZONE_FORCE_AXFR) {
		pkt_type = KNOT_QUERY_AXFR;
	}

	/* Execute zone transfer and reschedule timers. */
	int ret = zone_query_transfer(zone, master, pkt_type);

	/* Handle failure during transfer. */
	if (ret != KNOT_EOK) {
		if (is_boostrap) {
			zone->bootstrap_retry = bootstrap_next(zone->bootstrap_retry);
			zone_events_schedule(zone, ZONE_EVENT_XFER, zone->bootstrap_retry);
		} else {
			const knot_rdataset_t *soa = zone_soa(zone);
			zone_events_schedule(zone, ZONE_EVENT_XFER, knot_soa_retry(soa));
			start_expire_timer(zone, soa);
		}

		return KNOT_EOK;
	}

	assert(!zone_contents_is_empty(zone->contents));
	const knot_rdataset_t *soa = zone_soa(zone);

	/* Rechedule events. */
	zone_events_schedule(zone, ZONE_EVENT_REFRESH, knot_soa_refresh(soa));
	zone_events_schedule(zone, ZONE_EVENT_NOTIFY,  ZONE_EVENT_NOW);
	zone_events_cancel(zone, ZONE_EVENT_EXPIRE);
	if (zone->conf->dbsync_timeout == 0) {
		zone_events_schedule(zone, ZONE_EVENT_FLUSH, ZONE_EVENT_NOW);
	} else if (!zone_events_is_scheduled(zone, ZONE_EVENT_FLUSH)) {
		zone_events_schedule(zone, ZONE_EVENT_FLUSH, zone->conf->dbsync_timeout);
	}

	/* Transfer cleanup. */
	zone->bootstrap_retry = ZONE_EVENT_NOW;
	zone->flags &= ~ZONE_FORCE_AXFR;

	/* Trim extra heap. */
	if (!is_boostrap) {
		mem_trim();
	}

	return KNOT_EOK;
}

int event_update(zone_t *zone)
{
	assert(zone);

	/* Process update list - forward if zone has master, or execute. */
	int ret = updates_execute(zone);
	UNUSED(ret); /* Don't care about the Knot code, RCODEs are set. */

	/* Trim extra heap. */
	mem_trim();

	/* Replan event if next update waiting. */
	pthread_mutex_lock(&zone->ddns_lock);

	const bool empty = EMPTY_LIST(zone->ddns_queue);

	pthread_mutex_unlock(&zone->ddns_lock);

	if (!empty) {
		zone_events_schedule(zone, ZONE_EVENT_UPDATE, ZONE_EVENT_NOW);
	}

	return KNOT_EOK;
}

int event_expire(zone_t *zone)
{
	assert(zone);

	zone_contents_t *expired = zone_switch_contents(zone, NULL);
	synchronize_rcu();

	/* Expire zonefile information. */
	zone->zonefile_mtime = 0;
	zone->zonefile_serial = 0;
	zone_contents_deep_free(&expired);

	log_zone_info(zone->name, "zone expired");

	/* Trim extra heap. */
	mem_trim();

	return KNOT_EOK;
}

int event_flush(zone_t *zone)
{
	assert(zone);

	/* Reschedule. */
	int next_timeout = zone->conf->dbsync_timeout;
	if (next_timeout > 0) {
		zone_events_schedule(zone, ZONE_EVENT_FLUSH, next_timeout);
	}

	/* Check zone contents. */
	if (zone_contents_is_empty(zone->contents)) {
		return KNOT_EOK;
	}

	return zone_flush_journal(zone);
}

int event_notify(zone_t *zone)
{
	assert(zone);

	/* Check zone contents. */
	if (zone_contents_is_empty(zone->contents)) {
		return KNOT_EOK;
	}

	/* Walk through configured remotes and send messages. */
	conf_remote_t *remote = 0;
	WALK_LIST(remote, zone->conf->acl.notify_out) {
		conf_iface_t *iface = remote->remote;

		int ret = zone_query_execute(zone, KNOT_QUERY_NOTIFY, iface);
		if (ret == KNOT_EOK) {
			ZONE_QUERY_LOG(LOG_INFO, zone, iface, "NOTIFY, outgoing",
			               "serial %u",
			               zone_contents_serial(zone->contents));
		} else {
			ZONE_QUERY_LOG(LOG_WARNING, zone, iface, "NOTIFY, outgoing",
			               "failed (%s)", knot_strerror(ret));
		}
	}

	return KNOT_EOK;
}

int event_dnssec(zone_t *zone)
{
	assert(zone);

	changeset_t ch;
	int ret = changeset_init(&ch, zone->name);
	if (ret != KNOT_EOK) {
		goto done;
	}

	uint32_t refresh_at = time(NULL);
	int sign_flags = 0;

	if (zone->flags & ZONE_FORCE_RESIGN) {
		log_zone_info(zone->name, "DNSSEC, dropping previous "
		              "signatures, resigning zone");
		zone->flags &= ~ZONE_FORCE_RESIGN;
		sign_flags = ZONE_SIGN_DROP_SIGNATURES;
	} else {
		log_zone_info(zone->name, "DNSSEC, signing zone");
		sign_flags = 0;
	}

	ret = knot_dnssec_zone_sign(zone->contents, zone->conf, &ch, sign_flags, &refresh_at);
	if (ret != KNOT_EOK) {
		goto done;
	}

	if (!changeset_empty(&ch)) {
		/* Apply change. */
		zone_contents_t *new_contents = NULL;
		int ret = apply_changeset(zone, &ch, &new_contents);
		if (ret != KNOT_EOK) {
			log_zone_error(zone->name, "DNSSEC, failed to sign zone (%s)",
				       knot_strerror(ret));
			goto done;
		}

		/* Write change to journal. */
		ret = zone_change_store(zone, &ch);
		if (ret != KNOT_EOK) {
			log_zone_error(zone->name, "DNSSEC, failed to sign zone (%s)",
				       knot_strerror(ret));
			update_rollback(&ch);
			update_free_zone(&new_contents);
			goto done;
		}

		/* Switch zone contents. */
		zone_contents_t *old_contents = zone_switch_contents(zone, new_contents);
		synchronize_rcu();
		update_free_zone(&old_contents);

		update_cleanup(&ch);
	}

	// Schedule dependent events.

	schedule_dnssec(zone, refresh_at);
	zone_events_schedule(zone, ZONE_EVENT_NOTIFY, ZONE_EVENT_NOW);
	if (zone->conf->dbsync_timeout == 0) {
		zone_events_schedule(zone, ZONE_EVENT_FLUSH, ZONE_EVENT_NOW);
	}

done:
	changeset_clear(&ch);
	return ret;
}

#undef ZONE_QUERY_LOG

/*! \brief Progressive bootstrap retry timer. */
uint32_t bootstrap_next(uint32_t timer)
{
	timer *= 2;
	timer += dnssec_random_uint32_t() % BOOTSTRAP_RETRY;
	if (timer > BOOTSTRAP_MAXTIME) {
		timer = BOOTSTRAP_MAXTIME;
	}
	return timer;
}
