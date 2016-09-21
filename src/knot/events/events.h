/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#pragma once

#include <pthread.h>
#include <stdbool.h>
#include <sys/time.h>

#include "knot/conf/conf.h"
#include "knot/common/evsched.h"
#include "knot/worker/pool.h"
#include "libknot/db/db.h"

/* Timer special values. */
#define ZONE_EVENT_NOW 0

struct zone;

typedef enum zone_event_type {
	ZONE_EVENT_INVALID = -1,
	// supported event types
	ZONE_EVENT_LOAD = 0,
	ZONE_EVENT_REFRESH,
	ZONE_EVENT_UPDATE,
	ZONE_EVENT_EXPIRE,
	ZONE_EVENT_FLUSH,
	ZONE_EVENT_NOTIFY,
	ZONE_EVENT_DNSSEC,
	// terminator
	ZONE_EVENT_COUNT,
} zone_event_type_t;

typedef struct zone_events {
	pthread_mutex_t mx;		//!< Mutex protecting the struct.
	bool running;			//!< Some zone event is being run.
	bool frozen;			//!< Terminated, don't schedule new events.

	event_t *event;			//!< Scheduler event.
	worker_pool_t *pool;		//!< Server worker pool.
	knot_db_t *timers_db;		//!< Persistent zone timers database.

	task_t task;			//!< Event execution context.
	time_t time[ZONE_EVENT_COUNT];	//!< Event execution times.
} zone_events_t;

/*!
 * \brief Initialize zone events.
 *
 * The function will not set up the scheduling, use \ref zone_events_enable
 * to do that.
 *
 * \param zone  Pointer to zone (context of execution).
 *
 * \return KNOT_E*
 */
int zone_events_init(struct zone *zone);

/*!
 * \brief Set up zone events execution.
 *
 * \param zone       Zone to setup.
 * \param workers    Worker thread pool.
 * \param scheduler  Event scheduler.
 * \param timers_db  Persistent timers database. Can be NULL.
 *
 * \return KNOT_E*
 */
int zone_events_setup(struct zone *zone, worker_pool_t *workers,
                      evsched_t *scheduler, knot_db_t *timers_db);

/*!
 * \brief Deinitialize zone events.
 *
 * \param zone  Zone whose events we want to deinitialize.
 */
void zone_events_deinit(struct zone *zone);

/*!
 * \brief Enqueue event type for asynchronous execution.
 *
 * \note This is similar to the scheduling an event for NOW, but it can
 *       bypass the event scheduler if no event is running at the moment.
 *
 * \param zone  Zone to schedule new event for.
 * \param type  Type of event.
 */
void zone_events_enqueue(struct zone *zone, zone_event_type_t type);

/*!
 * \brief Schedule new zone event to absolute time.
 *
 * If the event is already scheduled, the new time will be set only if the
 * new time is earlier than the currently scheduled one. An exception is
 * a zero time, which causes event cancellation.
 *
 * \param zone  Zone to schedule new event for.
 * \param type  Type of event.
 * \param time  Absolute time.
 */
void zone_events_schedule_at(struct zone *zone, zone_event_type_t type, time_t time);

/*!
 * \brief Schedule new zone event using relative time to current time.
 *
 * The function internally uses \ref zone_events_schedule_at.
 *
 * \param zone  Zone to schedule new event for.
 * \param type  Type of event.
 * \param dt    Relative time.
 */
void zone_events_schedule(struct zone *zone, zone_event_type_t type, unsigned dt);

/*!
 * \brief Check if zone event is scheduled.
 *
 * \param zone  Zone to check event of.
 * \param type  Type of event.
 */
bool zone_events_is_scheduled(struct zone *zone, zone_event_type_t type);

/*!
 * \brief Cancel one zone event.
 *
 * \param zone  Zone to cancel event in.
 * \param type  Type of event to cancel.
 */
void zone_events_cancel(struct zone *zone, zone_event_type_t type);

/*!
 * \brief Freeze all zone events and prevent new events from running.
 *
 * \param zone  Zone to freeze events for.
 */
void zone_events_freeze(struct zone *zone);

/*!
 * \brief Start the events processing.
 *
 * \param zone  Zone to start processing for.
 */
void zone_events_start(struct zone *zone);

/*!
 * \brief Return time of the occurrence of the given event.
 *
 * \param zone  Zone to get event time from.
 * \param type  Event type.
 *
 * \retval time of the event when event found
 * \retval 0 when the event is not planned
 * \retval negative value if event is invalid
 */
time_t zone_events_get_time(const struct zone *zone, zone_event_type_t type);

/*!
 * \brief Return text name of the event.
 *
 * \param type  Type of event.
 *
 * \retval String with event name if it exists.
 * \retval NULL if the event does not exist.
 */
const char *zone_events_get_name(zone_event_type_t type);

/*!
 * \brief Return time and type of the next event.
 *
 * \param zone  Zone to get next event from.
 * \param type  [out] Type of the next event will be stored in the parameter.
 *
 * \return time of the next event or an error (negative number)
 */
time_t zone_events_get_next(const struct zone *zone, zone_event_type_t *type);

/*!
 * \brief Replans zone events after config change. Will reuse events where applicable.
 *
 * \param conf      Configuration.
 * \param zone      Zone with new config.
 * \param old_zone  Zone with old config.
 */
void zone_events_update(conf_t *conf, struct zone *zone, struct zone *old_zone);

/*!
 * \brief Replans DDNS processing event if DDNS queue is not empty.
 *
 * \param zone      Zone with new config.
 * \param old_zone  Zone with old config.
 */
void zone_events_replan_ddns(struct zone *zone, struct zone *old_zone);
