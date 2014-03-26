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
#include "knot/zone/load.h"
#include "knot/zone/zone.h"

/* -- zone events handling callbacks --------------------------------------- */

typedef int (*zone_event_cb)(zone_t *zone);

static int event_reload(zone_t *zone)
{
	assert(zone);

	zone_contents_t *content = zone_load_contents(zone->conf);
	if (!content) {
		return KNOT_ERROR; // TODO: specific error code
	}

	int result = apply_journal(content, zone->conf);
	if (result != KNOT_EOK) {
		zone_contents_free(&content);
		return result;
	}

	// TODO: do diff and sign

	zone_contents_t *old = zone_switch_contents(zone, content);
	if (old != NULL) {
		synchronize_rcu();
		zone_contents_deep_free(&old);
	}

	log_zone_info("Zone '%s' loaded.\n", zone->conf->name);

	return KNOT_EOK;
}

static int event_refresh(zone_t *zone)
{
	assert(zone);

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
#warning Implement me.
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
		ret = zones_store_and_apply_chgsets(chs, zone, &new_c, "DNSSEC",
						    XFR_TYPE_UPDATE);
		chs = NULL; // freed by zones_store_and_apply_chgsets()
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
