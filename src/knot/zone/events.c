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
#include "knot/server/server.h"
#include "knot/updates/changesets.h"
#include "knot/worker/pool.h"
#include "knot/worker/task.h"
#include "knot/zone/events.h"
#include "knot/zone/zone.h"
#include "knot/zone/zone-load.h"
#include "knot/zone/zonefile.h"
#include "libknot/rdata/soa.h"

/* -- zone events handling callbacks --------------------------------------- */

typedef int (*zone_event_cb)(zone_t *zone);

static int event_reload(zone_t *zone)
{
	assert(zone);

	/* Take zone file mtime and load it. */
	time_t mtime = zonefile_mtime(zone->conf->file);
	conf_zone_t *zone_config = zone->conf;
	zone_contents_t *contents = zone_load_contents(zone_config);
	if (!contents) {
		return KNOT_ERROR; // TODO: specific error code
	}

	/* Apply changes in journal. */
	int result = zone_load_journal(contents, zone_config);
	if (result != KNOT_EOK) {
		goto fail;
	}

	/* Post load actions - calculate delta, sign with DNSSEC... */
	result = zone_load_post(contents, zone);
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
	if (old != NULL) {
		synchronize_rcu();
		zone_contents_deep_free(&old);
	}

	log_zone_info("Zone '%s' loaded.\n", zone_config->name);
	return KNOT_EOK;

fail:
	zone_contents_deep_free(&contents);
	return result;
}

static int event_refresh(zone_t *zone)
{
	assert(zone);
#warning TODO: implement event_refresh
#if 0
	assert(event);

	dbg_zones("zone: REFRESH/RETRY timer event\n");
	rcu_read_lock();
	zone_t *zone = (zone_t *)event->data;
	if (zone == NULL) {
		rcu_read_unlock();
		return KNOT_EINVAL;
	}

	if (zone->flags & ZONE_DISCARDED) {
		rcu_read_unlock();
		return KNOT_EOK;
	}

	/* Create XFR request. */
	knot_ns_xfr_t *rq = xfr_task_create(zone, XFR_TYPE_SOA, XFR_FLAG_TCP);
	rcu_read_unlock(); /* rq now holds a reference to zone */
	if (!rq) {
		return KNOT_EINVAL;
	}

	const conf_iface_t *master = zone_master(zone);
	xfr_task_setaddr(rq, &master->addr, &master->via);
	rq->tsig_key = master->key;

	/* Check for contents. */
	int ret = KNOT_EOK;
	if (!zone->contents) {

		/* Bootstrap over TCP. */
		rq->type = XFR_TYPE_AIN;
		rq->flags = XFR_FLAG_TCP;
		evsched_end_process(event->sched);

		/* Check transfer state. */
		pthread_mutex_lock(&zone->lock);
		if (zone->xfr_in.state == XFR_PENDING) {
			pthread_mutex_unlock(&zone->lock);
			xfr_task_free(rq);
			return KNOT_EOK;
		} else {
			zone->xfr_in.state = XFR_PENDING;
		}

		/* Issue request. */
#warning "XFR enqueue."
		pthread_mutex_unlock(&zone->lock);
		return ret;
	}

	/* Reschedule as RETRY timer. */
	uint32_t retry_tmr = zones_jitter(zones_soa_retry(zone));
	evsched_schedule(event, retry_tmr);
	dbg_zones("zone: RETRY of '%s' after %u seconds\n",
	          zone->conf->name, retry_tmr / 1000);

	/* Issue request. */
	evsched_end_process(event->sched);
#warning "XFR enqueue."
#endif

//	zone_schedule_event(zone, ZONE_EVENT_REFRESH, time);

	return KNOT_ERROR;
}

static int event_expire(zone_t *zone)
{
	assert(zone);

	zone_contents_t *expired = zone_switch_contents(zone, NULL);
	synchronize_rcu();
	zone_contents_deep_free(&expired);

	log_zone_info("Zone '%s' expired.\n", zone->conf->name);

	return KNOT_EOK;
}

static int event_flush(zone_t *zone)
{
#warning TODO: implement event_flush
#if 0
	assert(event);
	dbg_zones("zone: zonefile SYNC timer event\n");

	/* Fetch zone. */
	zone_t *zone = (zone_t *)event->data;
	if (!zone) {
		return KNOT_EINVAL;
	}

	int ret = zones_zonefile_sync_from_ev(zone);

	/* Reschedule. */
	rcu_read_lock();
	int next_timeout = zone->conf->dbsync_timeout;
	if (next_timeout > 0) {
		zones_schedule_zonefile_sync(zone, next_timeout * 1000);
	}
	rcu_read_unlock();
	return ret;
#endif
	return KNOT_ERROR;
}

static int event_dnssec(zone_t *zone)
{
	assert(zone);

#warning TODO: implement event_dnssec
	return KNOT_ERROR;
#if 0
	knot_changesets_t *chs = knot_changesets_create();
	if (chs == NULL) {
		return KNOT_ENOMEM;
	}

	knot_changeset_t *ch = knot_changesets_create_changeset(chs);
	if (ch == NULL) {
		return KNOT_ENOMEM;
	}

	char *zname = knot_dname_to_str(zone->name);
	msgpref = sprintf_alloc("DNSSEC: Zone %s -", zname);
	free(zname);
	if (msgpref == NULL) {
		ret = KNOT_ENOMEM;
		goto done;
	}

	if (force) {
		log_zone_info("%s Complete resign started (dropping all "
			      "previous signatures)...\n", msgpref);
	} else {
		log_zone_info("%s Signing zone...\n", msgpref);
	}

	uint32_t new_serial = zones_next_serial(zone);

	if (force) {
		ret = knot_dnssec_zone_sign_force(zone->contents, zone->conf,
		                                  ch, refresh_at, new_serial);
	} else {
		ret = knot_dnssec_zone_sign(zone->contents, zone->conf,
		                            ch, KNOT_SOA_SERIAL_UPDATE,
		                            refresh_at, new_serial);
	}
	if (ret != KNOT_EOK) {
		goto done;
	}

	if (!zones_changesets_empty(chs)) {
		zone_contents_t *new_c = NULL;
		ret = zone_change_apply_and_store(chs, zone, &new_c, "DNSSEC");
		chs = NULL; // freed by zone_change_apply_and_store()
		if (ret != KNOT_EOK) {
			log_zone_error("%s Could not sign zone (%s).\n",
				       msgpref, knot_strerror(ret));
			goto done;
		}
	}

	log_zone_info("%s Successfully signed.\n", msgpref);

done:
	knot_changesets_free(&chs);
	free(msgpref);
	return ret;
	knot_

	zones_dnssec_


	fprintf(stderr, "RESIGNING ZONE %p\n", zone);
//	zone_schedule_event(zone, ZONE_EVENT_REFRESH, time);
#endif
}

/* -- internal API --------------------------------------------------------- */

static bool valid_event(zone_event_type_t type)
{
	return (type >= 0 && type < ZONE_EVENT_COUNT);
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
 * \brief Cancel scheduled item, schedule first enqueued item.
 *
 * The events mutex must be locked when calling this function.
 */
static void reschedule(zone_events_t *events)
{
	assert(events);
	assert(pthread_mutex_trylock(&events->mx) == EBUSY);

	if (!events->event || events->running) {
		return;
	}

	zone_event_type_t type = get_next_event(events);
	if (!valid_event) {
		evsched_cancel(events->event);
		return;
	}

	time_t now = time(NULL);
	time_t planned = events->time[type];
	time_t diff = now < planned ? (planned - now) : 0;

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
	{ ZONE_EVENT_EXPIRE,  event_expire,  "expiration" },
	{ ZONE_EVENT_FLUSH,   event_flush,   "journal flush" },
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
		log_zone_error("[%s] %s failed - %s\n", zone->conf->name,
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
	if (!events->running) {
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

	assert(zone->events.running == false);
	pthread_mutex_destroy(&zone->events.mx);

	memset(&zone->events, 0, sizeof(zone->events));
}

void zone_events_schedule(zone_t *zone, zone_event_type_t type, time_t time)
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

void zone_events_cancel(zone_t *zone, zone_event_type_t type)
{
	zone_events_schedule(zone, type, 0);
}

void zone_events_cancel_all(zone_t *zone)
{
	if (!zone) {
		return;
	}

	zone_events_t *events = &zone->events;

	pthread_mutex_lock(&events->mx);
	for (int i = 0; i < ZONE_EVENT_COUNT; i++) {
		event_set_time(events, i, 0);
	}
	reschedule(events);
	pthread_mutex_unlock(&events->mx);
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

/* ------------ Legacy API to be converted (not functional now) ------------- */
#warning TODO: vvv legacy API to be converted vvv


int zones_schedule_refresh(zone_t *zone, int64_t timeout)
{
	if (!zone) {
		return KNOT_EINVAL;
	}
#warning TODO: reimplement schedule_refresh
#if 0
	/* Cancel REFRESH/EXPIRE timer. */
//	evsched_cancel(zone->xfr_in.expire);
//	evsched_cancel(zone->xfr_in.timer);

	/* Check XFR/IN master server. */
	pthread_mutex_lock(&zone->lock);
	rcu_read_lock();
	if (zone_master(zone) != NULL) {

		knot_rdataset_t *soa = zone_contents_soa(zone->contents);

		/* Schedule EXPIRE timer. */
		if (zone->contents != NULL) {
			int64_t expire_tmr = knot_soa_expire(soa);
			// Allow for timeouts.  Otherwise zones with very short
			// expiry may expire before the timeout is reached.
			expire_tmr += 2 * (conf()->max_conn_idle * 1000);
//			evsched_schedule(zone->xfr_in.expire, expire_tmr);

		}

		/* Schedule REFRESH timer. */
		if (timeout < 0) {
			if (zone->contents) {
				timeout = knot_soa_refresh(soa);
			} else {
				timeout = zone->xfr_in.bootstrap_retry;
			}
		}
//		evsched_schedule(zone->xfr_in.timer, timeout);

	}
	rcu_read_unlock();
	pthread_mutex_unlock(&zone->lock);
#endif

	return KNOT_EOK;
}

int zones_schedule_notify(zone_t *zone, server_t *server)
{
	if (!zone) {
		return KNOT_EINVAL;
	}

#warning TODO: reimplement schedule_notify
#if 0
	/* Do not issue NOTIFY queries if stub. */
	if (!zone->contents) {
		return KNOT_EOK;
	}

	/* Schedule NOTIFY to slaves. */
	conf_zone_t *cfg = zone->conf;
	conf_remote_t *r = 0;
	WALK_LIST(r, cfg->acl.notify_out) {

		/* Fetch remote. */
		conf_iface_t *cfg_if = r->remote;

		/* Create request. */
		knot_ns_xfr_t *rq = xfr_task_create(zone, XFR_TYPE_NOTIFY, XFR_FLAG_UDP);
		if (!rq) {
			log_zone_error("Failed to create NOTIFY for '%s', "
			               "not enough memory.\n", cfg->name);
			continue;
		}

		xfr_task_setaddr(rq, &cfg_if->addr, &cfg_if->via);
		rq->tsig_key = cfg_if->key;

		rq->data = (void *)((long)cfg->notify_retries);
#warning "XFR enqueue."
//		if (xfr_enqueue(server->xfr, rq) != KNOT_EOK) {
//			log_zone_error("Failed to enqueue NOTIFY for '%s'.\n",
//			               cfg->name);
//			continue;
//		}
	}
#endif

	return KNOT_EOK;
}

int zones_schedule_dnssec(zone_t *zone, time_t unixtime)
{
	if (!zone) {
		return KNOT_EINVAL;
	}
#warning TODO: reimplement schedule_dnssec
#if 0
	char *zname = knot_dname_to_str(zone->name);

	// absolute time -> relative time

	time_t now = time(NULL);
	int32_t relative = 0;
	if (unixtime <= now) {
		log_zone_warning("DNSSEC: Zone %s: Signature life time too low, "
		                 "set higher value in configuration!\n", zname);
	} else {
		relative = unixtime - now;
	}

	// log the message

	char time_str[64] = {'\0'};
	struct tm time_gm = {0};

	gmtime_r(&unixtime, &time_gm);

	strftime(time_str, sizeof(time_str), KNOT_LOG_TIME_FORMAT, &time_gm);

	log_zone_info("DNSSEC: Zone %s: Next signing planned on %s.\n",
	              zname, time_str);

	free(zname);

	// schedule


//	evsched_schedule(zone->dnssec.timer, relative * 1000);
#endif
	return KNOT_EOK;
}

int zones_cancel_dnssec(zone_t *zone)
{
	if (!zone) {
		return KNOT_EINVAL;
	}
#warning TODO: reimplement cancel_dnssec
//	evsched_cancel(zone->dnssec.timer);

	return KNOT_EOK;
}