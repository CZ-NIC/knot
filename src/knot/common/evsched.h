/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
/*!
 * \file evsched.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \brief Event scheduler.
 *
 * \addtogroup common_lib
 * @{
 */

#pragma once

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/time.h>

#include "knot/server/dthreads.h"
#include "contrib/ucw/heap.h"

/* Forward decls. */
struct evsched;
struct event;

/*!
 * \brief Event callback.
 *
 * Pointer to whole event structure is passed to the callback.
 * Callback should return 0 on success and negative integer on error.
 *
 * Example callback:
 * \code
 * void print_callback(event_t *t) {
 *    printf("Callback: %s\n", t->data);
 * }
 * \endcode
 */
typedef void (*event_cb_t)(struct event *);

/*!
 * \brief Event structure.
 */
typedef struct event {
	struct heap_val hpos;
	struct timeval tv; /*!< Event scheduled time. */
	void *data;        /*!< Usable data ptr. */
	event_cb_t cb;     /*!< Event callback. */
	struct evsched *sched; /*!< Scheduler for this event. */
} event_t;

/*!
 * \brief Event scheduler structure.
 */
typedef struct evsched {
	volatile bool running;     /*!< True if running. */
	pthread_mutex_t heap_lock; /*!< Event heap locking. */
	pthread_cond_t notify;     /*!< Event heap notification. */
	struct heap heap;          /*!< Event heap. */
	void *ctx;                 /*!< Scheduler context. */
	dt_unit_t *thread;
} evsched_t;

/*!
 * \brief Initialize event scheduler instance.
 *
 * \retval New instance on success.
 * \retval NULL on error.
 */
int evsched_init(evsched_t *sched, void *ctx);

/*!
 * \brief Deinitialize and free event scheduler instance.
 *
 * \param sched Pointer to event scheduler instance.
 */
void evsched_deinit(evsched_t *sched);

/*!
 * \brief Create a callback event.
 *
 * \note Scheduler takes ownership of scheduled events. Created, but unscheduled
 *       events are in the ownership of the caller.
 *
 * \param sched Pointer to event scheduler instance.
 * \param cb Callback handler.
 * \param data Data for callback.
 *
 * \retval New instance on success.
 * \retval NULL on error.
 */
event_t *evsched_event_create(evsched_t *sched, event_cb_t cb, void *data);

/*!
 * \brief Dispose event instance.
 *
 * \param s Pointer to event scheduler instance.
 * \param ev Event instance.
 */
void evsched_event_free(event_t *ev);

/*!
 * \brief Schedule an event.
 *
 * \note This function checks if the event was already scheduled, if it was
 *       then it replaces this timer with the newer value.
 *       Running events are not canceled or waited for.
 *
 * \param ev Prepared event.
 * \param dt Time difference in milliseconds from now (dt is relative).
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL
 */
int evsched_schedule(evsched_t *sched, event_t *ev, uint32_t dt);

/*!
 * \brief Cancel a scheduled event.
 *
 * \warning May block until current running event is finished (as it cannot
 *          interrupt running event).
 *
 * \warning Never cancel event in it's callback. As it never finishes,
 *          it deadlocks.
 *
 * \param s Event scheduler.
 * \param ev Scheduled event.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EINVAL
 */
int evsched_cancel(event_t *ev);

void evsched_start(evsched_t *sched);
void evsched_stop(evsched_t *sched);
void evsched_join(evsched_t *sched);

/*! @} */
