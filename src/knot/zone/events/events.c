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

#include "common-knot/evsched.h"
#include "common/namedb/namedb.h"
#include "knot/server/server.h"
#include "knot/worker/pool.h"
#include "knot/zone/zone.h"
#include "knot/zone/events/events.h"
#include "knot/zone/events/handlers.h"
#include "knot/zone/events/replan.h"
#include "knot/zone/timers.h"

/* ------------------------- internal timers -------------------------------- */

#define ZONE_EVENT_IMMEDIATE 1 /* Fast-track to worker queue. */

/* -- internal API ---------------------------------------------------------- */

typedef int (*zone_event_cb)(zone_t *zone);

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

/* -- callbacks control ----------------------------------------------------- */

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
		log_zone_error(zone->name, "zone %s failed (%s)", info->name,
		               knot_strerror(result));
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

/* -- public API ------------------------------------------------------------ */

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

int zone_events_setup(struct zone_t *zone, worker_pool_t *workers,
                      evsched_t *scheduler, knot_namedb_t *timers_db)
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
	zone->events.timers_db = timers_db;

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
	time_t current = event_get_time(events, type);
	if (time == 0 || current == 0 || time < current) {
		event_set_time(events, type, time);
		reschedule(events);
	}
	pthread_mutex_unlock(&events->mx);
}

bool zone_events_is_scheduled(zone_t *zone, zone_event_type_t type)
{
	return zone_events_get_time(zone, type) > 0;
}

void zone_events_enqueue(zone_t *zone, zone_event_type_t type)
{
	if (!zone || !valid_event(type)) {
		return;
	}

	zone_events_t *events = &zone->events;

	pthread_mutex_lock(&events->mx);

	/* Bypass scheduler if no event is running. */
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

void zone_events_update(zone_t *zone, zone_t *old_zone)
{
	replan_events(zone, old_zone);
}

void zone_events_replan_ddns(struct zone_t *zone, const struct zone_t *old_zone)
{
	if (old_zone) {
		replan_update(zone, (zone_t *)old_zone);
	}
}
