#include <string.h>
#include <stdlib.h>

#include "common.h"
#include "lib/evqueue.h"

static inline int evqueue_lock(evqueue_t *q)
{
	return pthread_mutex_lock(&q->mx);
}

static inline int evqueue_unlock(evqueue_t *q)
{
	return pthread_mutex_unlock(&q->mx);
}

evqueue_t *evqueue_new()
{
	evqueue_t* q = malloc(sizeof(evqueue_t));
	if (evqueue_init(q) < 0) {
		free(q);
		q = 0;
	}

	return q;
}

int evqueue_init(evqueue_t *q)
{
	/* Initialize queue. */
	init_list(&q->q);

	/* Initialize synchronisation. */
	if (pthread_mutex_init(&q->mx, 0) != 0) {
		return -1;
	}

	if (pthread_cond_init(&q->notify, 0) != 0) {
		pthread_mutex_destroy(&q->mx);
		return -1;
	}

	return 0;
}

int evqueue_clear(evqueue_t *q)
{
	if (!q) {
		return -1;
	}

	if (evqueue_lock(q) != 0) {
		return -2;
	}

	int i = 0;
	node *n = 0, *nxt = 0;
	WALK_LIST_DELSAFE (n, nxt, q->q) {
		free(n);
		++i;
	}

	evqueue_unlock(q);
	return i;
}

void evqueue_free(evqueue_t **q)
{
	/* Invalidate pointer to queue. */
	evqueue_t *eq = *q;
	*q = 0;

	/* Clear queue. */
	evqueue_clear(eq);

	/* Deinitialize. */
	pthread_mutex_destroy(&eq->mx);
	pthread_cond_destroy(&eq->notify);
	free(eq);
}

void *evqueue_get(evqueue_t *q)
{
	void *ret = 0;

	/* Lock event queue. */
	if (!q) {
		return ret;
	}

	if (evqueue_lock(q) != 0) {
		return ret;
	}

	/* Take first event. */
	event_t *ev = (event_t*)HEAD(q->q);
	if (ev) {
		rem_node((node *)ev);
		ret = ev->data;
		free(ev);
	}

	/* Unlock and return. */
	evqueue_unlock(q);
	return ret;
}

int evqueue_add(evqueue_t *q, void *item)
{
	if (!q) {
		return -1;
	}

	/* Create item. */
	event_t *ev = malloc(sizeof(event_t));
	ev->data = item;

	/* Lock event queue. */
	if (evqueue_lock(q) != 0) {
		free(ev);
		return -1;
	}

	/* Insert into queue. */
	add_tail(&q->q, (node *)ev);
	evqueue_unlock(q);
	return 0;
}

