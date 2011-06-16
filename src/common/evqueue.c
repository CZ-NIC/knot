#include <string.h>
#include <stdlib.h>
#include <unistd.h>

//#include "knot/common.h"
#include "common/evqueue.h"
//#include "knot/other/error.h"

/*! \brief Singleton application-wide event queue. */
evqueue_t *s_evqueue = 0;

evqueue_t *evqueue_new()
{
	evqueue_t* q = malloc(sizeof(evqueue_t));

	/* Initialize fds. */
	if (pipe(q->fds) < 0) {
		free(q);
		q = 0;
	}

	return q;
}

void evqueue_free(evqueue_t **q)
{
	/* Invalidate pointer to queue. */
	evqueue_t *eq = *q;
	*q = 0;

	/* Deinitialize. */
	close(eq->fds[EVQUEUE_READFD]);
	close(eq->fds[EVQUEUE_WRITEFD]);
	free(eq);
}

int evqueue_poll(evqueue_t *q, const sigset_t *sigmask)
{
	/* Check. */
	if (!q) {
		return /*KNOT_EINVAL*/ -1;
	}

	/* Prepare fd set. */
	fd_set rfds;
	FD_ZERO(&rfds);
	FD_SET(q->fds[EVQUEUE_READFD], &rfds);

	/* Wait for events. */
	int ret = pselect(q->fds[EVQUEUE_READFD] + 1, &rfds,
			  0, 0, 0, sigmask);
	if (ret < 0) {
//		return knot_map_errno(EINTR, EINVAL, ENOMEM);
		return -1;
	}

	return ret;
}

int evqueue_read(evqueue_t *q, void *dst, size_t len)
{
	/* Read data. */
	return read(q->fds[EVQUEUE_READFD], dst, len);
}

int evqueue_write(evqueue_t *q, const void *dst, size_t len)
{
	return write(q->fds[EVQUEUE_WRITEFD], dst, len);
}

int evqueue_get(evqueue_t *q, event_t *ev)
{
	/* Check. */
	if (!q || !ev) {
		return /*KNOT_EINVAL*/ -1;
	}

	/* Read data. */
	int ret = evqueue_read(q, ev, sizeof(event_t));
	if (ret != sizeof(event_t)) {
//		return knot_map_errno(EINVAL, EINTR, EAGAIN);
		return -1;
	}

	return /*KNOT_EOK*/ 0;
}

int evqueue_add(evqueue_t *q, const event_t *ev)
{
	/* Check. */
	if (!q || !ev) {
		return /*KNOT_EINVAL*/ -1;
	}

	/* Write data. */
	int ret = evqueue_write(q, ev, sizeof(event_t));
	if (ret != sizeof(event_t)) {
//		return knot_map_errno(EINVAL, EINTR, EAGAIN);
		return -1;
	}

	return /*KNOT_EOK*/ 0;
}

