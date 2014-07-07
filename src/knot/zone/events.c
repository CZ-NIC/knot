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

#include <assert.h>
#include <time.h>

#include "common/evsched.h"
#include "common/mempool.h"
#include "knot/server/server.h"
#include "knot/server/udp-handler.h"
#include "knot/server/tcp-handler.h"
#include "knot/updates/changesets.h"
#include "knot/dnssec/zone-events.h"
#include "knot/worker/pool.h"
#include "knot/zone/events.h"
#include "knot/zone/zone.h"
#include "knot/zone/zone-load.h"
#include "knot/zone/zonefile.h"
#include "libknot/rrtype/soa.h"
#include "libknot/dnssec/random.h"
#include "knot/nameserver/internet.h"
#include "knot/nameserver/update.h"
#include "knot/nameserver/notify.h"
#include "knot/nameserver/requestor.h"
#include "knot/nameserver/tsig_ctx.h"
#include "knot/nameserver/process_answer.h"

/* ------------------------- internal timers -------------------------------- */

#define ZONE_EVENT_IMMEDIATE 1 /* Fast-track to worker queue. */

/* ------------------------- bootstrap timer logic -------------------------- */

#define BOOTSTRAP_RETRY (30) /*!< Interval between AXFR bootstrap retries. */
#define BOOTSTRAP_MAXTIME (24*60*60) /*!< Maximum AXFR retry cap of 24 hours. */

/*! \brief Progressive bootstrap retry timer. */
static uint32_t bootstrap_next(uint32_t timer)
{
	timer *= 2;
	timer += knot_random_uint32_t() % BOOTSTRAP_RETRY;
	if (timer > BOOTSTRAP_MAXTIME) {
		timer = BOOTSTRAP_MAXTIME;
	}
	return timer;
}

/* ------------------------- zone query requesting -------------------------- */

/*! \brief Zone event logging. */
#define ZONE_QUERY_LOG(severity, zone, remote, what, msg...) \
	NS_PROC_LOG(severity, LOG_ZONE, &remote->addr, zone->conf->name, \
	            what " of '%s' with '%s': ", msg)

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

	knot_wire_set_id(pkt->wire, knot_random_uint16_t());
	knot_wire_set_aa(pkt->wire);
	knot_wire_set_opcode(pkt->wire, opcode);
	knot_pkt_put_question(pkt, zone->name, KNOT_CLASS_IN, query_type);

	/* Put current SOA (optional). */
	zone_contents_t *contents = zone->contents;
	if (pkt_type == KNOT_QUERY_IXFR) {  /* RFC1995, SOA in AUTHORITY. */
		knot_pkt_begin(pkt, KNOT_AUTHORITY);
		knot_rrset_t soa_rr = node_rrset(contents->apex, KNOT_RRTYPE_SOA);
		knot_pkt_put(pkt, COMPR_HINT_QNAME, &soa_rr, 0);
	} else if (pkt_type == KNOT_QUERY_NOTIFY) { /* RFC1996, SOA in ANSWER. */
		knot_pkt_begin(pkt, KNOT_ANSWER);
		knot_rrset_t soa_rr = node_rrset(contents->apex, KNOT_RRTYPE_SOA);
		knot_pkt_put(pkt, COMPR_HINT_QNAME, &soa_rr, 0);
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
	mm_ctx_mempool(&mm, DEFAULT_BLKSIZE);

	/* Create a query message. */
	knot_pkt_t *query = zone_query(zone, pkt_type, &mm);
	if (query == NULL) {
		return KNOT_ENOMEM;
	}

	/* Create requestor instance. */
	struct requestor re;
	requestor_init(&re, NS_PROC_ANSWER, &mm);

	/* Answer processing parameters. */
	struct process_answer_param param = { 0 };
	param.zone = zone;
	param.query = query;
	param.remote = &remote->addr;
	tsig_init(&param.tsig_ctx, remote->key);

	ret = tsig_sign_packet(&param.tsig_ctx, query);
	if (ret != KNOT_EOK) {
		goto fail;
	}

	/* Create a request. */
	struct request *req = requestor_make(&re, remote, query);
	if (req == NULL) {
		ret = KNOT_ENOMEM;
		goto fail;
	}

	/* Send the queries and process responses. */
	ret = requestor_enqueue(&re, req, &param);
	if (ret == KNOT_EOK) {
		struct timeval tv = { conf()->max_conn_reply, 0 };
		ret = requestor_exec(&re, &tv);
	}

fail:
	/* Cleanup. */
	tsig_cleanup(&param.tsig_ctx);
	requestor_clear(&re);
	mp_delete(mm.ctx);

	return ret;
}

/* @note Module specific, expects some variables set. */
#define ZONE_XFER_LOG(severity, pkt_type, msg...) \
	if (pkt_type == KNOT_QUERY_AXFR) { \
		ZONE_QUERY_LOG(severity, zone, master, "AXFR", msg); \
	} else { \
		ZONE_QUERY_LOG(severity, zone, master, "IXFR", msg); \
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
			ZONE_XFER_LOG(LOG_NOTICE, pkt_type, "Fallback to AXFR.");
			return zone_query_transfer(zone, master, KNOT_QUERY_AXFR);
		}

		/* Log connection errors. */
		ZONE_XFER_LOG(LOG_ERR, pkt_type, "%s", knot_strerror(ret));
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
	log_zone_info("DNSSEC: Zone %s - Next event on %s.\n",
	              zone->conf->name, time_str);

	// schedule

	zone_events_schedule_at(zone, ZONE_EVENT_DNSSEC, refresh_at);
}

/* -- zone events handling callbacks --------------------------------------- */

/*! \brief Fetch SOA expire timer and add a timeout grace period. */
static uint32_t soa_graceful_expire(const knot_rdataset_t *soa)
{
	// Allow for timeouts.  Otherwise zones with very short
	// expiry may expire before the timeout is reached.
	return knot_soa_expire(soa) + 2 * conf()->max_conn_idle;
}

typedef int (*zone_event_cb)(zone_t *zone);

static int event_reload(zone_t *zone)
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
	int result = zone_load_journal(contents, zone_config);
	if (result != KNOT_EOK) {
		goto fail;
	}

	/* Post load actions - calculate delta, sign with DNSSEC... */
	/*! \todo issue #242 dnssec signing should occur in the special event */
	result = zone_load_post(contents, zone, &dnssec_refresh);
	if (result != KNOT_EOK) {
		if (result == KNOT_ESPACE) {
			log_zone_error("Zone '%s' journal size is too small to fit the changes.\n",
			               zone_config->name);
		} else {
			log_zone_error("Zone '%s' failed to store changes in the journal - %s\n",
			               zone_config->name, knot_strerror(result));
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
	log_zone_info("Zone '%s' loaded (%u -> %u).\n", zone_config->name,
	              old_serial, current_serial);
	return KNOT_EOK;

fail:
	zone_contents_deep_free(&contents);
	return result;
}

static int event_refresh(zone_t *zone)
{
	assert(zone);

	zone_contents_t *contents = zone->contents;
	if (zone_contents_is_empty(contents)) {
		/* No contents, schedule retransfer now. */
		zone_events_schedule(zone, ZONE_EVENT_XFER, ZONE_EVENT_NOW);
		return KNOT_EOK;
	}

	const conf_iface_t *master = zone_master(zone);
	assert(master);

	int ret = zone_query_execute(zone, KNOT_QUERY_NORMAL, master);

	const knot_rdataset_t *soa = node_rdataset(contents->apex, KNOT_RRTYPE_SOA);
	if (ret != KNOT_EOK) {
		/* Log connection errors. */
		ZONE_QUERY_LOG(LOG_WARNING, zone, master, "SOA query", "%s", knot_strerror(ret));
		/* Rotate masters if current failed. */
		zone_master_rotate(zone);
		/* Schedule next retry. */
		zone_events_schedule(zone, ZONE_EVENT_REFRESH, knot_soa_retry(soa));
		if (zone_events_get_time(zone, ZONE_EVENT_EXPIRE) <= ZONE_EVENT_NOW) {
			/* Schedule zone expiration if not previously planned. */
			zone_events_schedule(zone, ZONE_EVENT_EXPIRE, soa_graceful_expire(soa));
		}
	} else {
		/* SOA query answered, reschedule refresh timer. */
		zone_events_schedule(zone, ZONE_EVENT_REFRESH, knot_soa_refresh(soa));
		/* Cancel possible expire. */
		zone_events_cancel(zone, ZONE_EVENT_EXPIRE);
	}

	return KNOT_EOK;
}

static int event_xfer(zone_t *zone)
{
	assert(zone);

	/* Determine transfer type. */
	bool is_bootstrap = false;
	uint16_t pkt_type = KNOT_QUERY_IXFR;
	if (zone_contents_is_empty(zone->contents) || zone->flags & ZONE_FORCE_AXFR) {
		pkt_type = KNOT_QUERY_AXFR;
		is_bootstrap = true;
	}

	/* Execute zone transfer and reschedule timers. */
	int ret = zone_query_transfer(zone, zone_master(zone), pkt_type);
	if (ret == KNOT_EOK) {
		assert(!zone_contents_is_empty(zone->contents));
		/* New zone transferred, reschedule zone expiration and refresh
		 * timers and send notifications to slaves. */
		const knot_rdataset_t *soa =
			node_rdataset(zone->contents->apex, KNOT_RRTYPE_SOA);
		zone_events_schedule(zone, ZONE_EVENT_REFRESH, knot_soa_refresh(soa));
		zone_events_schedule(zone, ZONE_EVENT_NOTIFY,  ZONE_EVENT_NOW);
		/* Sync zonefile immediately if configured. */
		if (zone->conf->dbsync_timeout == 0) {
			zone_events_schedule(zone, ZONE_EVENT_FLUSH, ZONE_EVENT_NOW);
		} else if (zone_events_get_time(zone, ZONE_EVENT_FLUSH) <= ZONE_EVENT_NOW) {
			/* Plan sync if not previously planned. */
			zone_events_schedule(zone, ZONE_EVENT_FLUSH, zone->conf->dbsync_timeout);
		}
		zone->bootstrap_retry = ZONE_EVENT_NOW;
		zone->flags &= ~ZONE_FORCE_AXFR;
		/* Trim extra heap. */
		if (!is_bootstrap) {
			mem_trim();
		}
	} else {
		/* Zone contents is still empty, increment bootstrap retry timer
		 * and try again. */
		zone->bootstrap_retry = bootstrap_next(zone->bootstrap_retry);
		zone_events_schedule(zone, ZONE_EVENT_XFER, zone->bootstrap_retry);
	}

	return KNOT_EOK;
}

static int event_update(zone_t *zone)
{
	assert(zone);

	struct request_data *update = zone_update_dequeue(zone);
	if (update == NULL) {
		return KNOT_EOK;
	}

	/* Forward if zone has master, or execute. */
	int ret = update_execute(zone, update);
	UNUSED(ret);

	/* Cleanup. */
	close(update->fd);
	knot_pkt_free(&update->query);
	free(update);

	/* Trim extra heap. */
	mem_trim();

	/* Replan event if next update waiting. */
	pthread_mutex_lock(&zone->ddns_lock);

	if (!EMPTY_LIST(zone->ddns_queue)) {
		zone_events_schedule(zone, ZONE_EVENT_UPDATE, ZONE_EVENT_NOW);
	}

	pthread_mutex_unlock(&zone->ddns_lock);


	return KNOT_EOK;
}

static int event_expire(zone_t *zone)
{
	assert(zone);

	zone_contents_t *expired = zone_switch_contents(zone, NULL);
	synchronize_rcu();

	/* Expire zonefile information. */
	zone->zonefile_mtime = 0;
	zone->zonefile_serial = 0;
	zone_contents_deep_free(&expired);

	log_zone_info("Zone '%s' expired.\n", zone->conf->name);

	/* Trim extra heap. */
	mem_trim();

	return KNOT_EOK;
}

static int event_flush(zone_t *zone)
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

static int event_notify(zone_t *zone)
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
			ZONE_QUERY_LOG(LOG_INFO, zone, iface, "NOTIFY", "sent (serial %u).",
			               zone_contents_serial(zone->contents));
		} else {
			ZONE_QUERY_LOG(LOG_WARNING, zone, iface, "NOTIFY", "%s", knot_strerror(ret));
		}
	}

	return KNOT_EOK;
}

static int event_dnssec(zone_t *zone)
{
	assert(zone);

	changesets_t *chs = changesets_create(1);
	if (chs == NULL) {
		return KNOT_ENOMEM;
	}

	changeset_t *ch = changesets_get_last(chs);
	assert(ch);

	int ret = KNOT_ERROR;
	char *zname = knot_dname_to_str(zone->name);
	char *msgpref = sprintf_alloc("DNSSEC: Zone %s -", zname);
	free(zname);
	if (msgpref == NULL) {
		ret = KNOT_ENOMEM;
		goto done;
	}

	uint32_t refresh_at = time(NULL);
	if (zone->flags & ZONE_FORCE_RESIGN) {
		log_zone_info("%s Complete resign started (dropping all "
			      "previous signatures)...\n", msgpref);

		zone->flags &= ~ZONE_FORCE_RESIGN;
		ret = knot_dnssec_zone_sign_force(zone->contents, zone->conf,
		                                  ch, &refresh_at);
	} else {
		log_zone_info("%s Signing zone...\n", msgpref);
		ret = knot_dnssec_zone_sign(zone->contents, zone->conf,
		                            ch, KNOT_SOA_SERIAL_UPDATE,
		                            &refresh_at);
	}
	if (ret != KNOT_EOK) {
		goto done;
	}

	if (!changesets_empty(chs)) {
		ret = zone_change_apply_and_store(&chs, zone, "DNSSEC", NULL);
		if (ret != KNOT_EOK) {
			log_zone_error("%s Could not sign zone (%s).\n",
				       msgpref, knot_strerror(ret));
			goto done;
		}
	}

	// Schedule dependent events.

	schedule_dnssec(zone, refresh_at);
	zone_events_schedule(zone, ZONE_EVENT_NOTIFY, ZONE_EVENT_NOW);
	if (zone->conf->dbsync_timeout == 0) {
		zone_events_schedule(zone, ZONE_EVENT_FLUSH, ZONE_EVENT_NOW);
	}

done:
	changesets_free(&chs, NULL);
	free(msgpref);
	return ret;
}

#undef ZONE_QUERY_LOG

/* -- Zone event replanning functions --------------------------------------- */

/*!< \brief Replans event for new zone according to old zone. */
static void replan_event(zone_t *zone, const zone_t *old_zone, zone_event_type_t e)
{
	const time_t event_time = zone_events_get_time(old_zone, e);
	if (event_time > ZONE_EVENT_NOW) {
		zone_events_schedule_at(zone, e, event_time);
	}
}

/*!< \brief Replans events that are dependent on the SOA record. */
static void replan_soa_events(zone_t *zone, const zone_t *old_zone)
{
	if (!zone_master(zone)) {
		// Events only valid for slaves.
		return;
	}

	if (zone_master(old_zone)) {
		// Replan SOA events.
		replan_event(zone, old_zone, ZONE_EVENT_REFRESH);
		replan_event(zone, old_zone, ZONE_EVENT_EXPIRE);
	} else {
		// Plan SOA events anew.
		if (!zone_contents_is_empty(zone->contents)) {
			const knot_rdataset_t *soa = node_rdataset(zone->contents->apex,
			                                           KNOT_RRTYPE_SOA);
			assert(soa);
			zone_events_schedule(zone, ZONE_EVENT_REFRESH, knot_soa_refresh(soa));
		}
	}
}

/*!< \brief Replans transfer event. */
static void replan_xfer(zone_t *zone, const zone_t *old_zone)
{
	if (!zone_master(zone)) {
		// Only valid for slaves.
		return;
	}

	if (zone_master(old_zone)) {
		// Replan the transfer from old zone.
		replan_event(zone, old_zone, ZONE_EVENT_XFER);
	} else if (zone_contents_is_empty(zone->contents)) {
		// Plan transfer anew.
		zone->bootstrap_retry = bootstrap_next(zone->bootstrap_retry);
		zone_events_schedule(zone, ZONE_EVENT_XFER, zone->bootstrap_retry);
	}
}

/*!< \brief Replans flush event. */
static void replan_flush(zone_t *zone, const zone_t *old_zone)
{
	if (zone->conf->dbsync_timeout <= 0) {
		// Immediate sync scheduled after events.
		return;
	}

	const time_t flush_time = zone_events_get_time(old_zone, ZONE_EVENT_FLUSH);
	if (flush_time <= ZONE_EVENT_NOW) {
		// Not scheduled previously.
		zone_events_schedule(zone, ZONE_EVENT_FLUSH, zone->conf->dbsync_timeout);
		return;
	}

	// Pick time to schedule: either reuse or schedule sooner than old event.
	const time_t schedule_at = MIN(time(NULL) + zone->conf->dbsync_timeout, flush_time);
	zone_events_schedule_at(zone, ZONE_EVENT_FLUSH, schedule_at);
}

/*!< \brief Creates new DDNS q in the new zone - q contains references from the old zone. */
static void duplicate_ddns_q(zone_t *zone, zone_t *old_zone)
{
	struct request_data *d, *nxt;
	WALK_LIST_DELSAFE(d, nxt, old_zone->ddns_queue) {
		add_tail(&zone->ddns_queue, (node_t *)d);
	}

	// Reset the list, new zone will free the data.
	init_list(&old_zone->ddns_queue);
}

/*!< Replans DDNS event. */
static void replan_update(zone_t *zone, zone_t *old_zone)
{
	pthread_mutex_lock(&old_zone->ddns_lock);

	if (!EMPTY_LIST(old_zone->ddns_queue)) {
		duplicate_ddns_q(zone, (zone_t *)old_zone);
		// \todo #254 Old zone *must* have the event planned, but it was not always so
		zone_events_schedule(zone, ZONE_EVENT_UPDATE, ZONE_EVENT_NOW);
	}

	pthread_mutex_unlock(&old_zone->ddns_lock);
}

/*!< Replans DNSSEC event. Not whole resign needed, \todo #247 */
static void replan_dnssec(zone_t *zone)
{
	if (zone->conf->dnssec_enable) {
		/* Keys could have changed, force resign. */
		zone_events_schedule(zone, ZONE_EVENT_DNSSEC, ZONE_EVENT_NOW);
	}
}

/* -- internal API --------------------------------------------------------- */

static bool valid_event(zone_event_type_t type)
{
	return (type > ZONE_EVENT_INVALID && type < ZONE_EVENT_COUNT);
}

/*! \brief Return remaining time to planned event (seconds). */
static time_t time_until(time_t planned)
{
	time_t now = time(NULL);
	return now < planned ? (planned - now) : 0;
}

/*!
 * \brief Find next scheduled zone event.
 *
 * \param events  Zone events.
 *
 * \return Zone event type, or ZONE_EVENT_INVALID if no event is scheduled.
 */
static zone_event_type_t get_next_event(zone_events_t *events)
{
	if (!events) {
		return ZONE_EVENT_INVALID;
	}

	zone_event_type_t next_type = ZONE_EVENT_INVALID;
	time_t next = 0;

	for (int i = 0; i < ZONE_EVENT_COUNT; i++) {
		time_t current = events->time[i];
		if (current == 0) {
			continue;
		}

		if (next == 0 || current < next) {
			next = current;
			next_type = i;
		}
	}

	return next_type;
}

/*!
 * \brief Set time of a given event type.
 */
static void event_set_time(zone_events_t *events, zone_event_type_t type, time_t time)
{
	assert(events);
	assert(valid_event(type));

	events->time[type] = time;
}

/*!
 * \brief Get time of a given event type.
 */
static time_t event_get_time(zone_events_t *events, zone_event_type_t type)
{
	assert(events);
	assert(valid_event(type));

	return events->time[type];
}

/*!
 * \brief Cancel scheduled item, schedule first enqueued item.
 *
 * The events mutex must be locked when calling this function.
 */
static void reschedule(zone_events_t *events)
{
	assert(events);
	assert(pthread_mutex_trylock(&events->mx) == EBUSY);

	if (!events->event || events->running || events->frozen) {
		return;
	}

	zone_event_type_t type = get_next_event(events);
	if (!valid_event(type)) {
		return;
	}

	time_t diff = time_until(event_get_time(events, type));

	evsched_schedule(events->event, diff * 1000);
}

/* -- callbacks control ---------------------------------------------------- */

typedef struct event_info_t {
	zone_event_type_t type;
	const zone_event_cb callback;
	const char *name;
} event_info_t;

static const event_info_t EVENT_INFO[] = {
        { ZONE_EVENT_RELOAD,  event_reload,  "reload" },
        { ZONE_EVENT_REFRESH, event_refresh, "refresh" },
        { ZONE_EVENT_XFER,    event_xfer,    "transfer" },
        { ZONE_EVENT_UPDATE,  event_update,  "update" },
        { ZONE_EVENT_EXPIRE,  event_expire,  "expiration" },
        { ZONE_EVENT_FLUSH,   event_flush,   "journal flush" },
        { ZONE_EVENT_NOTIFY,  event_notify,  "notify" },
        { ZONE_EVENT_DNSSEC,  event_dnssec,  "DNSSEC resign" },
        { 0 }
};

static const event_info_t *get_event_info(zone_event_type_t type)
{
	const event_info_t *info;
	for (info = EVENT_INFO; info->callback != NULL; info++) {
		if (info->type == type) {
			return info;
		}
	}

	assert(0);
	return NULL;
}

/*!
 * \brief Zone event wrapper, expected to be called from a worker thread.
 *
 * 1. Takes the next planned event.
 * 2. Resets the event's scheduled time.
 * 3. Perform the event's callback.
 * 4. Schedule next event planned event.
 */
static void event_wrap(task_t *task)
{
	assert(task);
	assert(task->ctx);

	zone_t *zone = task->ctx;
	zone_events_t *events = &zone->events;

	pthread_mutex_lock(&events->mx);
	zone_event_type_t type = get_next_event(events);
	if (!valid_event(type)) {
		events->running = false;
		pthread_mutex_unlock(&events->mx);
		return;
	}
	event_set_time(events, type, 0);
	pthread_mutex_unlock(&events->mx);

	const event_info_t *info = get_event_info(type);
	int result = info->callback(zone);
	if (result != KNOT_EOK) {
		log_zone_error("Zone '%s' event '%s' failed - %s\n", zone->conf->name,
		               info->name, knot_strerror(result));
	}

	pthread_mutex_lock(&events->mx);
	events->running = false;
	reschedule(events);
	pthread_mutex_unlock(&events->mx);
}

/*!
 * \brief Called by scheduler thread if the event occurs.
 */
static int event_dispatch(event_t *event)
{
	assert(event);
	assert(event->data);

	zone_events_t *events = event->data;

	pthread_mutex_lock(&events->mx);
	if (!events->running && !events->frozen) {
		events->running = true;
		worker_pool_assign(events->pool, &events->task);
	}
	pthread_mutex_unlock(&events->mx);

	return KNOT_EOK;
}

/* -- public API ----------------------------------------------------------- */

int zone_events_init(zone_t *zone)
{
	if (!zone) {
		return KNOT_EINVAL;
	}

	zone_events_t *events = &zone->events;

	memset(&zone->events, 0, sizeof(zone->events));
	pthread_mutex_init(&events->mx, NULL);
	events->task.ctx = zone;
	events->task.run = event_wrap;

	return KNOT_EOK;
}

int zone_events_setup(zone_t *zone, worker_pool_t *workers, evsched_t *scheduler)
{
	if (!zone || !workers || !scheduler) {
		return KNOT_EINVAL;
	}

	event_t *event;
	event = evsched_event_create(scheduler, event_dispatch, &zone->events);
	if (!event) {
		return KNOT_ENOMEM;
	}

	zone->events.event = event;
	zone->events.pool = workers;

	return KNOT_EOK;
}

void zone_events_deinit(zone_t *zone)
{
	if (!zone) {
		return;
	}

	evsched_cancel(zone->events.event);
	evsched_event_free(zone->events.event);

	pthread_mutex_destroy(&zone->events.mx);

	memset(&zone->events, 0, sizeof(zone->events));
}

void zone_events_schedule_at(zone_t *zone, zone_event_type_t type, time_t time)
{
	if (!zone || !valid_event(type)) {
		return;
	}

	zone_events_t *events = &zone->events;

	pthread_mutex_lock(&events->mx);
	event_set_time(events, type, time);
	reschedule(events);
	pthread_mutex_unlock(&events->mx);
}

void zone_events_enqueue(zone_t *zone, zone_event_type_t type)
{
	if (!zone || !valid_event(type)) {
		return;
	}

	zone_events_t *events = &zone->events;

	pthread_mutex_lock(&events->mx);

	/* Possible only if no event is running at the moment. */
	if (!events->running && !events->frozen) {
		events->running = true;
		event_set_time(events, type, ZONE_EVENT_IMMEDIATE);
		worker_pool_assign(events->pool, &events->task);
		pthread_mutex_unlock(&events->mx);
		return;
	}

	pthread_mutex_unlock(&events->mx);

	/* Execute as soon as possible. */
	zone_events_schedule(zone, type, ZONE_EVENT_NOW);
}

void zone_events_schedule(zone_t *zone, zone_event_type_t type, unsigned dt)
{
	time_t abstime = time(NULL) + dt;
	return zone_events_schedule_at(zone, type, abstime);
}

void zone_events_cancel(zone_t *zone, zone_event_type_t type)
{
	zone_events_schedule_at(zone, type, 0);
}

void zone_events_freeze(zone_t *zone)
{
	if (!zone) {
		return;
	}

	zone_events_t *events = &zone->events;

	/* Prevent new events being enqueued. */
	pthread_mutex_lock(&events->mx);
	events->frozen = true;
	pthread_mutex_unlock(&events->mx);

	/* Cancel current event. */
	evsched_cancel(events->event);
}

void zone_events_start(zone_t *zone)
{
	if (!zone) {
		return;
	}

	pthread_mutex_lock(&zone->events.mx);
	reschedule(&zone->events);
	pthread_mutex_unlock(&zone->events.mx);
}

time_t zone_events_get_time(const struct zone_t *zone, zone_event_type_t type)
{
	if (zone == NULL) {
		return KNOT_EINVAL;
	}

	time_t event_time = KNOT_ENOENT;
	zone_events_t *events = (zone_events_t *)&zone->events;

	pthread_mutex_lock(&events->mx);

	/* Get next valid event. */
	if (valid_event(type)) {
		event_time = event_get_time(events, type);
	}

	pthread_mutex_unlock(&events->mx);

	return event_time;
}

const char *zone_events_get_name(zone_event_type_t type)
{
	/* Get information about the event and time. */
	const event_info_t *info = get_event_info(type);
	if (info == NULL) {
		return NULL;
	}

	return info->name;
}

time_t zone_events_get_next(const struct zone_t *zone, zone_event_type_t *type)
{
	if (zone == NULL || type == NULL) {
		return KNOT_EINVAL;
	}

	time_t next_time = KNOT_ENOENT;
	zone_events_t *events = (zone_events_t *)&zone->events;

	pthread_mutex_lock(&events->mx);

	/* Get time of next valid event. */
	*type = get_next_event(events);
	if (valid_event(*type)) {
		next_time = event_get_time(events, *type);
	} else {
		*type = ZONE_EVENT_INVALID;
	}

	pthread_mutex_unlock(&events->mx);

	return next_time;
}

void zone_events_update(zone_t *zone, const zone_t *old_zone)
{
	replan_soa_events(zone, old_zone);
	replan_xfer(zone, old_zone);
	replan_flush(zone, old_zone);
	replan_event(zone, old_zone, ZONE_EVENT_NOTIFY);
	replan_update(zone, (zone_t *)old_zone);
	replan_dnssec(zone);
}

void zone_events_replan_ddns(struct zone_t *zone, const struct zone_t *old_zone)
{
	if (old_zone) {
		replan_update(zone, (zone_t *)old_zone);
	}
}

