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
#include "knot/server/dthreads.h"
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

/*! \brief Event scheduler loop. */
static int evsched_run(dthread_t *thread)
{
	evsched_t *sched = (evsched_t*)thread->data;
	if (sched == NULL) {
		return KNOT_EINVAL;
	}

	/* Run event loop. */
	pthread_mutex_lock(&sched->heap_lock);
	while (!dt_is_cancelled(thread)) {
		if (EMPTY_HEAP(&sched->heap)) {
			pthread_cond_wait(&sched->notify, &sched->heap_lock);
			continue;
		}

		/* Get current time. */
		struct timeval dt;
		gettimeofday(&dt, 0);

		/* Get next event. */
		event_t *ev = *((event_t**)HHEAD(&sched->heap));
		assert(ev != NULL);

		if (timercmp_ge(&dt, &ev->tv)) {
			heap_delmin(&sched->heap);
			ev->cb(ev);
		} else {
			/* Wait for next event or interrupt. Unlock calendar. */
			struct timespec ts;
			ts.tv_sec = ev->tv.tv_sec;
			ts.tv_nsec = ev->tv.tv_usec * 1000L;
			pthread_cond_timedwait(&sched->notify, &sched->heap_lock, &ts);
		}
	}
	pthread_mutex_unlock(&sched->heap_lock);

	return KNOT_EOK;
}

int evsched_init(evsched_t *sched, void *ctx)
{
	memset(sched, 0, sizeof(evsched_t));
	sched->ctx = ctx;

	/* Initialize event calendar. */
	pthread_mutex_init(&sched->heap_lock, 0);
	pthread_cond_init(&sched->notify, 0);
	heap_init(&sched->heap, compare_event_heap_nodes, 0);

	sched->thread = dt_create(1, evsched_run, NULL, sched);

	if (sched->thread == NULL) {
		evsched_deinit(sched);
		return KNOT_ENOMEM;
	}

	return KNOT_EOK;
}

void evsched_deinit(evsched_t *sched)
{
	if (sched == NULL) {
		return;
	}

	/* Deinitialize event calendar. */
	pthread_mutex_destroy(&sched->heap_lock);
	pthread_cond_destroy(&sched->notify);

	while (!EMPTY_HEAP(&sched->heap)) {
		event_t *e = (event_t *)*HHEAD(&sched->heap);
		heap_delmin(&sched->heap);
		evsched_event_free(e);
	}

	free(sched->heap.data);

	if (sched->thread != NULL) {
		dt_delete(&sched->thread);
	}

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
	e->hpos.pos=0;

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
	if (ev == NULL || ev->sched == NULL) {
		return KNOT_EINVAL;
	}

	struct timeval new_time = timeval_in(dt);

	evsched_t *sched = ev->sched;

	/* Lock calendar. */
	pthread_mutex_lock(&sched->heap_lock);

	ev->tv = new_time;

	/* Make sure it's not already enqueued. */
	int found = heap_find(&sched->heap, (heap_val_t *)ev);
	if (found > 0) {
		heap_replace(&sched->heap, found, (heap_val_t *)ev);
	} else {
		heap_insert(&sched->heap, (heap_val_t *)ev);
	}

	/* Unlock calendar. */
	pthread_cond_signal(&sched->notify);
	pthread_mutex_unlock(&sched->heap_lock);

	return KNOT_EOK;
}

int evsched_cancel(event_t *ev)
{
	if (ev == NULL || ev->sched == NULL) {
		return KNOT_EINVAL;
	}

	evsched_t *sched = ev->sched;

	/* Lock calendar. */
	pthread_mutex_lock(&sched->heap_lock);

	int found = heap_find(&sched->heap, (heap_val_t *)ev);
	if (found > 0) {
		heap_delete(&sched->heap, found);
	}

	/* Unlock calendar. */
	pthread_cond_signal(&sched->notify);
	pthread_mutex_unlock(&sched->heap_lock);

	/* Reset event timer. */
	memset(&ev->tv, 0, sizeof(struct timeval));

	return KNOT_EOK;
}

void evsched_start(evsched_t *sched)
{
	dt_start(sched->thread);
}

void evsched_stop(evsched_t *sched)
{
	pthread_mutex_lock(&sched->heap_lock);
	dt_stop(sched->thread);
	pthread_cond_signal(&sched->notify);
	pthread_mutex_unlock(&sched->heap_lock);
}

void evsched_join(evsched_t *sched)
{
	dt_join(sched->thread);
}
