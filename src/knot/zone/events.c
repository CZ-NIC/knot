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
#include "knot/worker/pool.h"
#include "knot/worker/task.h"
#include "knot/zone/events.h"
#include "knot/zone/zone.h"

/* -- zone events handling callbacks --------------------------------------- */

typedef void (*zone_event_cb)(zone_t *zone);

#include <stdio.h>
static void event_reload(zone_t *zone)
{
	assert(zone);

	fprintf(stderr, "LOADING ZONE %p\n", zone);
}

static void event_refresh(zone_t *zone)
{
	assert(zone);

	fprintf(stderr, "REFRESHING ZONE %p\n", zone);
//	zone_schedule_event(zone, ZONE_EVENT_REFRESH, time);
}

static void event_expire(zone_t *zone)
{
	assert(zone);

	fprintf(stderr, "EXPIRING ZONE %p\n", zone);
}

static void event_dnssec(zone_t *zone)
{
	assert(zone);

	fprintf(stderr, "RESIGNING ZONE %p\n", zone);
//	zone_schedule_event(zone, ZONE_EVENT_REFRESH, time);
}

/* -- internal API --------------------------------------------------------- */

static bool valid_event(zone_event_type_t type)
{
	return (type > 0 && type < ZONE_EVENT_COUNT);
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
 * Make sure this is not called multiple times simultaneously.
 */
static void reschedule(zone_events_t *events)
{
	assert(events);
	assert(events->event);

	evsched_cancel(events->event);

	zone_event_type_t type = get_next_event(events);
	if (!valid_event) {
		return;
	}

	time_t now = time(NULL);
	time_t planned = events->time[type];
	time_t diff = now < planned ? (planned - now) : 0;

	evsched_schedule(events->event, diff * 1000);
}

/* -- callbacks control ---------------------------------------------------- */

/*!
 * \brief Get callback for given type of event.
 */
static zone_event_cb get_event_callback(zone_event_type_t type)
{
	switch (type) {
	case ZONE_EVENT_RELOAD:   return event_reload;
	case ZONE_EVENT_REFRESH:  return event_refresh;
	case ZONE_EVENT_EXPIRE:   return event_expire;
	case ZONE_EVENT_DNSSEC:   return event_dnssec;
	default: return NULL;
	}
}

/*!
 * \brief Zone event wrapper, expected to be called from worker thread.
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

	zone_event_type_t type = get_next_event(events);
	if (!valid_event(type)) {
		return;
	}

	zone_event_cb run = get_event_callback(type);
	assert(run);

	event_set_time(events, type, 0);
	run(zone);
	reschedule(events);
}

/*!
 * \brief Called by scheduler thread if the event occurs.
 */
static int event_dispatch(event_t *event)
{
	assert(event);
	assert(event->data);

	zone_events_t *events = event->data;
	worker_pool_assign(events->pool, &events->task);

	return KNOT_EOK;
}

/* -- public API ----------------------------------------------------------- */

int zone_events_init(zone_t *zone, server_t *server)
{
	if (!zone || !server) {
		return KNOT_EINVAL;
	}

	event_t *event = evsched_event_create(&server->sched, event_dispatch,
					      &zone->events);
	if (!event) {
		return KNOT_ENOMEM;
	}

	memset(&zone->events, 0, sizeof(zone->events));

	zone->events.event = event;
	zone->events.pool = server->workers;
	zone->events.task.ctx = zone;
	zone->events.task.run = event_wrap;

	return KNOT_EOK;
}

void zone_events_deinit(zone_t *zone)
{
	if (!zone) {
		return;
	}

	evsched_cancel(zone->events.event);
	evsched_event_free(zone->events.event);

	memset(&zone->events, 0, sizeof(zone->events));
}

void zone_events_schedule(zone_t *zone, zone_event_type_t type, time_t time)
{
	if (!zone || !valid_event(type)) {
		return;
	}

	event_set_time(&zone->events, type, time);
}

void zone_events_cancel(zone_t *zone, zone_event_type_t type)
{
	zone_events_schedule(zone, type, 0);

	reschedule(&zone->events);
}

void zone_events_cancel_all(zone_t *zone)
{
	if (!zone) {
		return;
	}

	for (int i = 0; i < ZONE_EVENT_COUNT; i++) {
		event_set_time(&zone->events, i, 0);
	}

	reschedule(&zone->events);
}
