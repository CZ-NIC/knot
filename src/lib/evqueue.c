#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "common.h"
#include "lib/evqueue.h"

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
		return -1;
	}

	/* Prepare fd set. */
	fd_set rfds;
	FD_ZERO(&rfds);
	FD_SET(q->fds[EVQUEUE_READFD], &rfds);

	/* Wait for events. */
	return pselect(q->fds[EVQUEUE_READFD] + 1, &rfds,
	               0, 0, 0, sigmask);

}

int evqueue_get(evqueue_t *q, event_t *ev)
{
	/* Check. */
	if (!q || !ev) {
		return -1;
	}

	/* Read data. */
	int ret = read(q->fds[EVQUEUE_READFD], ev, sizeof(event_t));
	if (ret != sizeof(event_t)) {
		return -2;
	}

	return 0;
}

int evqueue_add(evqueue_t *q, const event_t *ev)
{
	/* Check. */
	if (!q || !ev) {
		return -1;
	}

	/* Write data. */
	int ret = write(q->fds[EVQUEUE_WRITEFD], ev, sizeof(event_t));
	if (ret != sizeof(event_t)) {
		return -2;
	}

	return 0;
}

