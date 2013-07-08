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

#include <config.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "common/evqueue.h"
#include "common/fdset.h"

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
	/* Check. */
	if (!q) {
		return;
	}

	/* Invalidate pointer to queue. */
	evqueue_t *eq = *q;
	*q = 0;

	/* Deinitialize. */
	for (int i = 0; i < 2; ++i) {
		if (eq->fds[i] > -1) {
			close(eq->fds[i]);
		}
	}
	free(eq);
}

int evqueue_poll(evqueue_t *q, const struct timespec *ts,
		 const sigset_t *sigmask)
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
	int ret = fdset_pselect(q->fds[EVQUEUE_READFD] + 1, &rfds,
	                        0, 0, ts, sigmask);
	if (ret < 0) {
		return -1;
	}

	return ret;
}

int evqueue_read(evqueue_t *q, void *dst, size_t len)
{
	if (!q || !dst || len == 0) {
		return -1;
	}

	return read(q->fds[EVQUEUE_READFD], dst, len);
}

int evqueue_write(evqueue_t *q, const void *src, size_t len)
{
	if (!q || !src || len == 0) {
		return -1;
	}

	return write(q->fds[EVQUEUE_WRITEFD], src, len);
}

int evqueue_get(evqueue_t *q, event_t *ev)
{
	/* Check. */
	if (!q || !ev) {
		return -1;
	}

	/* Read data. */
	int ret = evqueue_read(q, ev, sizeof(event_t));
	if (ret != sizeof(event_t)) {
		return -1;
	}

	/* Set parent. */
	ev->parent = q;

	return 0;
}

int evqueue_add(evqueue_t *q, const event_t *ev)
{
	/* Check. */
	if (!q || !ev) {
		return -1;
	}

	/* Write data. */
	int ret = evqueue_write(q, ev, sizeof(event_t));
	if (ret != sizeof(event_t)) {
		return -1;
	}

	return 0;
}
