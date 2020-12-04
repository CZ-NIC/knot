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
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>
#include "knot/common/epoll_set.h"
#include "contrib/time.h"
#include "libknot/errcode.h"

/* Realloc memory or return error (part of fdset_resize). */
#define MEM_RESIZE(tmp, p, n) \
	if ((tmp = realloc((p), (n) * sizeof(*p))) == NULL) \
		return KNOT_ENOMEM; \
	(p) = tmp;

static int epoll_set_resize(epoll_set_t *set, unsigned size)
{
	void *tmp = NULL;
	MEM_RESIZE(tmp, set->ctx, size);
	MEM_RESIZE(tmp, set->ev, size);
	MEM_RESIZE(tmp, set->timeout, size);
	set->size = size;
	return KNOT_EOK;
}

int epoll_set_init(epoll_set_t *set, unsigned size)
{
	if (set == NULL) {
		return KNOT_EINVAL;
	}

	memset(set, 0, sizeof(epoll_set_t));
	set->epoll_fd = epoll_create1(0);
	assert(set->epoll_fd >= 0);
	return epoll_set_resize(set, size);
}

int epoll_set_clear(epoll_set_t* set)
{
	if (set == NULL) {
		return KNOT_EINVAL;
	}

	free(set->ctx);
	free(set->ev);
	free(set->timeout);
	memset(set, 0, sizeof(epoll_set_t));
	return KNOT_EOK;
}

void epoll_set_close(epoll_set_t* set)
{
	close(set->epoll_fd);
	set->epoll_fd = -1;
}

int epoll_set_add(epoll_set_t *set, int fd, unsigned events, void *ctx)
{
	if (set == NULL || fd < 0) {
		return KNOT_EINVAL;
	}

	/* Realloc needed. */
	if (set->n == set->size && epoll_set_resize(set, set->size + FDSET_INIT_SIZE))
		return KNOT_ENOMEM;

	/* Initialize. */
	int i = set->n++;
	set->ev[i].data.fd = fd;
	set->ev[i].events = events;
	set->ctx[i] = ctx;
	set->timeout[i] = 0;
	struct epoll_event ev = {
		.data.u64 = i,
		.events = events
	};
	epoll_ctl(set->epoll_fd, EPOLL_CTL_ADD, fd, &ev);
	/* Return index to this descriptor. */
	return i;
}

int epoll_set_remove(epoll_set_t *set, unsigned i)
{
	if (set == NULL || i >= set->n) {
		return KNOT_EINVAL;
	}

	/* Decrement number of elms. */
	--set->n;

	/* Nothing else if it is the last one.
	 * Move last -> i if some remain. */
	unsigned last = set->n; /* Already decremented */
	if (i < last) {
		set->ev[i] = set->ev[last];
		set->timeout[i] = set->timeout[last];
		set->ctx[i] = set->ctx[last];
		struct epoll_event ev = {
			.data.u64 = i,
			.events = set->ev[i].events
		};
		epoll_ctl(set->epoll_fd, EPOLL_CTL_MOD, set->ev[last].data.fd, &ev);
	}

	return KNOT_EOK;
}

int epoll_set_set_watchdog(epoll_set_t* set, int i, int interval)
{
	if (set == NULL || i >= set->n) {
		return KNOT_EINVAL;
	}

	/* Lift watchdog if interval is negative. */
	if (interval < 0) {
		set->timeout[i] = 0;
		return KNOT_EOK;
	}

	/* Update clock. */
	struct timespec now = time_now();

	set->timeout[i] = now.tv_sec + interval; /* Only seconds precision. */
	return KNOT_EOK;
}

int epoll_set_sweep(epoll_set_t* set, epoll_set_sweep_cb_t cb, void *data)
{
	if (set == NULL || cb == NULL) {
		return KNOT_EINVAL;
	}

	/* Get time threshold. */
	struct timespec now = time_now();

	unsigned i = 0;
	while (i < set->n) {

		/* Check sweep state, remove if requested. */
		if (set->timeout[i] > 0 && set->timeout[i] <= now.tv_sec) {
			if (cb(set, i, data) == EPOLL_SET_SWEEP) {
				if (epoll_set_remove(set, i) == KNOT_EOK)
					continue; /* Stay on the index. */
			}
		}

		/* Next descriptor. */
		++i;
	}

	return KNOT_EOK;
}
