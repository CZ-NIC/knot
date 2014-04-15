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

#pragma once

#include <pthread.h>
#include <stdbool.h>

#include "common/evsched.h"
#include "knot/worker/pool.h"
#include "knot/worker/task.h"

/* Timer special values. */
#define ZONE_EVENT_NOW 0

struct zone_t;

struct server_t;

typedef enum zone_event_type {
	ZONE_EVENT_INVALID = -1,
	// supported event types
	ZONE_EVENT_RELOAD = 0,
	ZONE_EVENT_REFRESH,
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

	event_t *event;			//!< Scheduler event.
	worker_pool_t *pool;		//!< Server worker pool.

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
 */
int zone_events_init(struct zone_t *zone);

/*!
 * \brief Set up zone events execution.
 *
 * \param workers    Worker thread pool.
 * \param scheduler  Event scheduler.
 */
int zone_events_setup(struct zone_t *zone, worker_pool_t *workers,
		      evsched_t *scheduler);

/*!
 * \brief Deinitialize zone events.
 */
void zone_events_deinit(struct zone_t *zone);

/*!
 * \brief Schedule new zone event to absolute time.
 */
void zone_events_schedule_at(struct zone_t *zone, zone_event_type_t type, time_t time);

/*!
 * \brief Schedule new zone event using relative time to current time.
 */
void zone_events_schedule(struct zone_t *zone, zone_event_type_t type, unsigned dt);

/*!
 * \brief Cancel one zone event.
 */
void zone_events_cancel(struct zone_t *zone, zone_event_type_t type);

/*!
 * \brief Cancel all zone events.
 */
void zone_events_cancel_all(struct zone_t *zone);

/*!
 * \brief Start the events processing.
 */
void zone_events_start(struct zone_t *zone);

/* ------------ Legacy API to be converted (not functional now) ------------- */

#define REFRESH_DEFAULT -1

/*!
 * \brief Update zone timers.
 *
 * REFRESH/RETRY/EXPIRE timers are updated according to SOA.
 *
 * \param zone Related zone.
 * \param time Specific timeout or REFRESH_DEFAULT for default.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EINVAL
 * \retval KNOT_ERROR
 */
int zones_schedule_refresh(struct zone_t *zone, int64_t timeout);

/*!
 * \brief Schedule NOTIFY after zone update.
 * \param zone Related zone.
 *
 * \retval KNOT_EOK
 * \retval KNOT_ERROR
 */
int zones_schedule_notify(struct zone_t *zone, struct server_t *server);

/*!
 * \brief Schedule DNSSEC event.
 * \param zone Related zone.
 * \param unixtime When to schedule.
 * \param force Force sign or not
 *
 * \return Error code, KNOT_OK if successful.
 */
int zones_schedule_dnssec(struct zone_t *zone, time_t unixtime);

