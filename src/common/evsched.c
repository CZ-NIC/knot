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

#include "common/evsched.h"

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

	/* Initialize event calendar. */
	pthread_mutex_init(&s->rl, 0);
	pthread_mutex_init(&s->mx, 0);
	pthread_cond_init(&s->notify, 0);
	pthread_mutex_init(&s->cache.lock, 0);
	slab_cache_init(&s->cache.alloc, sizeof(event_t));
	init_list(&s->calendar);
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
	node *n = 0, *nxt = 0;
	WALK_LIST_DELSAFE(n, nxt, (*s)->calendar) {
		evsched_event_free((*s), (event_t*)n);
	}

	/* Free allocator. */
	slab_cache_destroy(&(*s)->cache.alloc);
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
	pthread_mutex_lock(&s->cache.lock);
	event_t *e = slab_cache_alloc(&s->cache.alloc);
	pthread_mutex_unlock(&s->cache.lock);

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

	pthread_mutex_lock(&s->cache.lock);
	slab_free(ev);
	pthread_mutex_unlock(&s->cache.lock);
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
		if (!EMPTY_LIST(s->calendar)) {

			/* Get current time. */
			struct timeval dt;
			gettimeofday(&dt, 0);

			/* Get next event. */
			event_t *next_ev = HEAD(s->calendar);

			/* Immediately return. */
			if (timercmp(&dt, &next_ev->tv, >=)) {
				rem_node(&next_ev->n);
				pthread_mutex_unlock(&s->mx);
				pthread_mutex_lock(&s->rl);
				s->current = next_ev;
				return next_ev;
			}

			/* Wait for next event or interrupt. Unlock calendar. */
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
	if (s->current) {
		s->current = 0;
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

	/* Lock calendar. */
	pthread_mutex_lock(&s->mx);

	/* Schedule event. */
	node *n = 0, *prev = 0;
	if (!EMPTY_LIST(s->calendar)) {
		WALK_LIST(n, s->calendar) {
			event_t* cur = (event_t *)n;
			if (timercmp(&cur->tv, &ev->tv, <)) {
				prev = n;
			} else {
				break;
			}
		}
	}

	/* Append to list. */
	ev->parent = s;
	if (prev) {
		insert_node(&ev->n, prev);
	} else {
		add_head(&s->calendar, &ev->n);
	}


	/* Unlock calendar. */
	pthread_cond_signal(&s->notify);
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
	if (!s || !ev) {
		return -1;
	}

	/* Make sure not running. */
	pthread_mutex_lock(&s->rl);

	/* Lock calendar. */
	pthread_mutex_lock(&s->mx);

	/* Find in list. */
	event_t *n = 0;
	int found = 0;
	WALK_LIST(n, s->calendar) {
		if (n == ev) {
			found = 1;
			break;
		}
	}

	/* Remove from list. */
	if (found) {
		rem_node(&ev->n);
	}

	/* Unlock calendar. */
	pthread_cond_signal(&s->notify);
	pthread_mutex_unlock(&s->mx);

	/* Enable running events. */
	pthread_mutex_unlock(&s->rl);

	return 0;
}

