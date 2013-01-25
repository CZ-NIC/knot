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
#include <config.h>

#include "common/evsched.h"

/*! \todo Fix properly (issue #1581). */
#ifndef HAVE_PSELECT
#define OPENBSD_SLAB_BROKEN
#endif

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
 * \brief Set event timer to T (now) + dt miliseconds.
 */
static void evsched_settimer(event_t *e, uint32_t dt)
{
	if (!e) {
		return;
	}

	/* Get absolute time T. */
	gettimeofday(&e->tv, 0);

	/* Add number of seconds. */
	e->tv.tv_sec += dt / 1000;

	/* Add the number of microseconds. */
	e->tv.tv_usec += (dt % 1000) * 1000;

	/* Check for overflow. */
	while (e->tv.tv_usec > 999999) {
		e->tv.tv_sec += 1;
		e->tv.tv_usec -= 1 * 1000 * 1000;
	}
}

/*! \brief Singleton application-wide event scheduler. */
evsched_t *s_evsched = 0;

evsched_t *evsched_new()
{
	evsched_t *s = malloc(sizeof(evsched_t));
	if (!s) {
		return 0;
	}
	memset(s, 0, sizeof(evsched_t));

	/* Initialize event calendar. */
	pthread_mutex_init(&s->rl, 0);
	pthread_mutex_init(&s->mx, 0);
	pthread_cond_init(&s->notify, 0);
	pthread_mutex_init(&s->cache.lock, 0);
#ifndef OPENBSD_SLAB_BROKEN
	slab_cache_init(&s->cache.alloc, sizeof(event_t));
#endif
	heap_init(&s->heap, compare_event_heap_nodes, 0);
	return s;
}

void evsched_delete(evsched_t **s)
{
	if (!s) {
		return;
	}
	if (!*s) {
		return;
	}

	/* Deinitialize event calendar. */
	pthread_mutex_destroy(&(*s)->rl);
	pthread_mutex_destroy(&(*s)->mx);
	pthread_cond_destroy(&(*s)->notify);

	while (! EMPTY_HEAP(&(*s)->heap))	/* FIXME: Would be faster to simply walk through the array */
	{
		event_t *e = *((event_t**)(HHEAD(&(*s)->heap)));
		heap_delmin(&(*s)->heap);
		evsched_event_free((*s), e);
	}
	
	free((*s)->heap.data);
	(*s)->heap.data = NULL;;

#ifndef OPENBSD_SLAB_BROKEN
	/* Free allocator. */
	slab_cache_destroy(&(*s)->cache.alloc);
#endif
	pthread_mutex_destroy(&(*s)->cache.lock);

	/* Free scheduler. */
	free(*s);
	*s = 0;
}

event_t *evsched_event_new(evsched_t *s, int type)
{
	if (!s) {
		return 0;
	}

	/* Allocate. */
#ifndef OPENBSD_SLAB_BROKEN
	pthread_mutex_lock(&s->cache.lock);
	event_t *e = slab_cache_alloc(&s->cache.alloc);
	pthread_mutex_unlock(&s->cache.lock);
#else
	event_t *e = malloc(sizeof(event_t));
#endif
        if (e == NULL) {
		return NULL;
	}

	/* Initialize. */
	memset(e, 0, sizeof(event_t));
	e->type = type;
	return e;
}

void evsched_event_free(evsched_t *s, event_t *ev)
{
	if (!s || !ev) {
		return;
	}

#ifndef OPENBSD_SLAB_BROKEN
	pthread_mutex_lock(&s->cache.lock);
	slab_free(ev);
	pthread_mutex_unlock(&s->cache.lock);
#else
	free(ev);
#endif
}

event_t* evsched_next(evsched_t *s)
{
	/* Check. */
	if (!s) {
		return 0;
	}

	/* Lock calendar. */
	pthread_mutex_lock(&s->mx);

	while(1) {

		/* Check event queue. */
		if (!EMPTY_HEAP(&s->heap)) {

			/* Get current time. */
			struct timeval dt;
			gettimeofday(&dt, 0);

			/* Get next event. */
			event_t *next_ev = *((event_t**)HHEAD(&s->heap));

			/* Immediately return. */
			if (timercmp_ge(&dt, &next_ev->tv)) {
				s->cur = next_ev;
                heap_delmin(&s->heap);
				pthread_mutex_unlock(&s->mx);
				pthread_mutex_lock(&s->rl);

				/* Check back for late cancellation. */
				if (s->cur == NULL) {
					pthread_mutex_unlock(&s->rl);
					pthread_mutex_lock(&s->mx);
					continue;
                }
				
				return next_ev;
			}

			/* Wait for next event or interrupt. Unlock calendar. */
			/* FIXME: Blocks this the possibility to add any event earlier? */
			struct timespec ts;
			ts.tv_sec = next_ev->tv.tv_sec;
			ts.tv_nsec = next_ev->tv.tv_usec * 1000L;
			pthread_cond_timedwait(&s->notify, &s->mx, &ts);
		} else {
			/* Block until an event is scheduled. Unlock calendar.*/
			pthread_cond_wait(&s->notify, &s->mx);
		}
	}

	/* Unlock calendar, this shouldn't happen. */
	pthread_mutex_unlock(&s->mx);
	return 0;

}

int evsched_event_finished(evsched_t *s)
{
	if (!s) {
		return -1;
	}

	/* Mark as finished. */
	if (s->cur) {
		s->cur = NULL;
		pthread_mutex_unlock(&s->rl);
		return 0;
	}

	/* Finished event is not current. */
	return -1;
}

int evsched_schedule(evsched_t *s, event_t *ev, uint32_t dt)
{
	if (!s || !ev) {
		return -1;
	}

	/* Update event timer. */
	evsched_settimer(ev, dt);
	ev->parent = s;
	
	/* Lock calendar. */
	pthread_mutex_lock(&s->mx);
	
	heap_insert(&s->heap, ev);

	/* Unlock calendar. */
	pthread_cond_broadcast(&s->notify);
	pthread_mutex_unlock(&s->mx);

	return 0;
}

event_t* evsched_schedule_cb(evsched_t *s, event_cb_t cb, void *data, uint32_t dt)
{
	if (!s) {
		return 0;
	}

	/* Create event. */
	event_t *e = evsched_event_new(s, EVSCHED_CB);
	if (!e) {
		return 0;
	}
	e->cb = cb;
	e->data = data;

	/* Schedule. */
	if (evsched_schedule(s, e, dt) != 0) {
		evsched_event_free(s, e);
		e = 0;
	}

	return e;
}

event_t* evsched_schedule_term(evsched_t *s, uint32_t dt)
{
	if (!s) {
		return 0;
	}

	/* Create event. */
	event_t *e = evsched_event_new(s, EVSCHED_TERM);
	if (!e) {
		return 0;
	}

	/* Schedule. */
	if (evsched_schedule(s, e, dt) != 0) {
		evsched_event_free(s, e);
		e = 0;
	}

	return e;
}

int evsched_cancel(evsched_t *s, event_t *ev)
{
	int found;

	if (!s || !ev) {
		return -1;
	}

	/* Make sure not running. */
	pthread_mutex_lock(&s->rl);

	/* Lock calendar. */
	pthread_mutex_lock(&s->mx);

	if ((found = heap_find(&s->heap, ev))) {
		heap_delete(&s->heap, found);
	}
	
	/* Check if not being processed, invalidate if yes.
	 * Could happen if next 'cur' was set, but
	 * the evsched_next() waits until we release rl.
	 */
	if (s->cur == ev) {
		s->cur = NULL; /* Invalidate */
        found = 1; /* Mark as found (although not in heap). */
	}

	/* Unlock calendar. */
	pthread_cond_broadcast(&s->notify);
	pthread_mutex_unlock(&s->mx);

	/* Enable running events. */
	pthread_mutex_unlock(&s->rl);

	return found;
}

