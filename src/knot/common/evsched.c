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

#include <sys/time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "libknot/libknot.h"
#include "knot/common/evsched.h"

/*! \brief Some implementations of timercmp >= are broken, this is for compat.*/
static inline int timercmp_ge(struct timeval *a, struct timeval *b) {
	return timercmp(a, b, >) || timercmp(a, b, ==);
}

static int compare_event_heap_nodes(event_t *e1, event_t *e2)
{
	if (timercmp(&e1->tv, &e2->tv, <)) return -1;
	if (timercmp(&e1->tv, &e2->tv, >)) return 1;
	return 0;
}

/*!
 * \brief Get time T (now) + dt miliseconds.
 */
static struct timeval timeval_in(uint32_t dt)
{
	struct timeval tv = { 0 };
	gettimeofday(&tv, NULL);

	/* Add number of seconds. */
	tv.tv_sec += dt / 1000;

	/* Add the number of microseconds. */
	tv.tv_usec += (dt % 1000) * 1000;

	/* Check for overflow. */
	while (tv.tv_usec > 999999) {
		tv.tv_sec += 1;
		tv.tv_usec -= 1 * 1000 * 1000;
	}

	return tv;
}

int evsched_init(evsched_t *sched, void *ctx)
{
	memset(sched, 0, sizeof(evsched_t));
	sched->ctx = ctx;

	/* Initialize event calendar. */
	pthread_mutex_init(&sched->run_lock, 0);
	pthread_mutex_init(&sched->heap_lock, 0);
	pthread_cond_init(&sched->notify, 0);
	heap_init(&sched->heap, compare_event_heap_nodes, 0);

	return KNOT_EOK;
}

void evsched_deinit(evsched_t *sched)
{
	if (sched == NULL) {
		return;
	}

	/* Deinitialize event calendar. */
	pthread_mutex_destroy(&sched->run_lock);
	pthread_mutex_destroy(&sched->heap_lock);
	pthread_cond_destroy(&sched->notify);

	while (! EMPTY_HEAP(&sched->heap))
	{
		event_t *e = *HHEAD(&sched->heap);
		heap_delmin(&sched->heap);
		evsched_event_free(e);
	}

	free(sched->heap.data);

	/* Clear the structure. */
	memset(sched, 0, sizeof(evsched_t));
}

event_t *evsched_event_create(evsched_t *sched, event_cb_t cb, void *data)
{
	/* Create event. */
	if (sched == NULL) {
		return NULL;
	}

	/* Allocate. */
	event_t *e = malloc(sizeof(event_t));
	if (e == NULL) {
		return NULL;
	}

	/* Initialize. */
	memset(e, 0, sizeof(event_t));
	e->sched = sched;
	e->cb = cb;
	e->data = data;

	return e;
}

void evsched_event_free(event_t *ev)
{
	if (ev == NULL) {
		return;
	}

	free(ev);
}

int evsched_schedule(event_t *ev, uint32_t dt)
{
	if (ev == NULL) {
		return KNOT_EINVAL;
	}

	struct timeval new_time = timeval_in(dt);

	/* Lock calendar. */
	evsched_t *sched = ev->sched;
	pthread_mutex_lock(&sched->heap_lock);

	ev->tv = new_time;

	/* Make sure it's not already enqueued. */
	int found = 0;
	if ((found = heap_find(&sched->heap, ev))) {
		heap_replace(&sched->heap, found, ev);
	} else {
		heap_insert(&sched->heap, ev);
	}

	/* Unlock calendar. */
	pthread_cond_broadcast(&sched->notify);
	pthread_mutex_unlock(&sched->heap_lock);

	return KNOT_EOK;
}

static int evsched_try_cancel(evsched_t *sched, event_t *ev)
{
	int found = 0;

	if (sched == NULL || ev == NULL) {
		return KNOT_EINVAL;
	}

	/* Make sure not running. If an event is starting, we race for this lock
	 * and either win or lose. If we lose, we may find it in heap because
	 * it rescheduled itself. Either way, it will be marked as last running. */
	pthread_mutex_lock(&sched->run_lock);

	/* Lock calendar. */
	pthread_mutex_lock(&sched->heap_lock);

	if ((found = heap_find(&sched->heap, ev))) {
		heap_delete(&sched->heap, found);
	}

	/* Last running event was (probably) the one we're trying to cancel. */
	if (sched->last_ev == ev) {
		sched->last_ev = NULL;   /* Invalidate it. */
		found = KNOT_EAGAIN; /* Let's try again if it didn't reschedule itself. */
	}

	/* Unlock calendar. */
	pthread_cond_broadcast(&sched->notify);
	pthread_mutex_unlock(&sched->heap_lock);

	/* Enable running events. */
	pthread_mutex_unlock(&sched->run_lock);

	if (found > 0) {        /* Event canceled. */
		return KNOT_EOK;
	} else if (found < 0) { /* Error */
		return found;
	}

	return KNOT_ENOENT;     /* Not found. */
}

int evsched_cancel(event_t *ev)
{
	if (ev == NULL || ev->sched == NULL) {
		return KNOT_EINVAL;
	}

	/* Event may have already run, try again. */
	int ret = KNOT_EAGAIN;
	while (ret == KNOT_EAGAIN) {
		ret = evsched_try_cancel(ev->sched, ev);
	}

	/* Reset event timer. */
	memset(&ev->tv, 0, sizeof(struct timeval));
	/* Now we're sure event is canceled or finished. */
	return KNOT_EOK;
}

event_t* evsched_begin_process(evsched_t *sched)
{
	/* Check. */
	if (!sched) {
		return NULL;
	}

	/* Lock calendar. */
	pthread_mutex_lock(&sched->heap_lock);

	while(1) {

		/* Check event heap. */
		if (!EMPTY_HEAP(&sched->heap)) {

			/* Get current time. */
			struct timeval dt;
			gettimeofday(&dt, 0);

			/* Get next event. */
			event_t *next_ev = *((event_t**)HHEAD(&sched->heap));
			assert(next_ev != NULL);

			/* Immediately return. */
			if (timercmp_ge(&dt, &next_ev->tv)) {
				sched->last_ev = next_ev;
				sched->running = true;
				heap_delmin(&sched->heap);
				pthread_mutex_unlock(&sched->heap_lock);
				pthread_mutex_lock(&sched->run_lock);
				return next_ev;
			}

			/* Wait for next event or interrupt. Unlock calendar. */
			/* FIXME: Blocks this the possibility to add any event earlier? */
			struct timespec ts;
			ts.tv_sec = next_ev->tv.tv_sec;
			ts.tv_nsec = next_ev->tv.tv_usec * 1000L;
			pthread_cond_timedwait(&sched->notify, &sched->heap_lock, &ts);
		} else {
			/* Block until an event is scheduled. Unlock calendar.*/
			pthread_cond_wait(&sched->notify, &sched->heap_lock);
		}
	}

	/* Unlock heap, this shouldn't happen. */
	pthread_mutex_unlock(&sched->heap_lock);
	return NULL;
}

int evsched_end_process(evsched_t *sched)
{
	if (!sched) {
		return KNOT_EINVAL;
	}

	/* \note This enables event cancellation & running on next event. */
	if(sched->running) {
		if (pthread_mutex_unlock(&sched->run_lock) != 0) {
			return KNOT_ERROR;
		}
		sched->running = false; /* Mark as not running. */
	} else {
		return KNOT_ENOTRUNNING;
	}

	return KNOT_EOK;
}
