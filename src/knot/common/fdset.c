/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#ifdef ENABLE_POLL

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>
#include "knot/common/fdset.h"
#include "contrib/time.h"
#include "libknot/errcode.h"

/* Realloc memory or return error (part of fdset_resize). */
#define MEM_RESIZE(tmp, p, n) \
	if ((tmp = realloc((p), (n) * sizeof(*p))) == NULL) \
		return KNOT_ENOMEM; \
	(p) = tmp;

static int fdset_resize(fdset_t *set, const unsigned size)
{
	void *tmp = NULL;
	MEM_RESIZE(tmp, set->ctx, size);
	MEM_RESIZE(tmp, set->pfd, size);
	MEM_RESIZE(tmp, set->timeout, size);
	set->size = size;
	return KNOT_EOK;
}

int fdset_init(fdset_t *set, const unsigned size)
{
	if (set == NULL) {
		return KNOT_EINVAL;
	}

	memset(set, 0, sizeof(fdset_t));
	return fdset_resize(set, size);
}

int fdset_clear(fdset_t* set)
{
	if (set == NULL) {
		return KNOT_EINVAL;
	}

	free(set->ctx);
	free(set->pfd);
	free(set->timeout);
	memset(set, 0, sizeof(fdset_t));
	return KNOT_EOK;
}

int fdset_add(fdset_t *set, const int fd, const unsigned events, void *ctx)
{
	if (set == NULL || fd < 0) {
		return KNOT_EINVAL;
	}

	/* Realloc needed. */
	if (set->n == set->size && fdset_resize(set, set->size + FDSET_INIT_SIZE))
		return KNOT_ENOMEM;

	/* Initialize. */
	const int i = set->n++;
	set->pfd[i].fd = fd;
	set->pfd[i].events = events;
	set->pfd[i].revents = 0;
	set->ctx[i] = ctx;
	set->timeout[i] = 0;

	/* Return index to this descriptor. */
	return i;
}

//TODO should be static, but it is a dependency in tests (? remove from
//     tests or something ?)
int fdset_remove(fdset_t *set, const unsigned idx)
{
	if (set == NULL || idx >= set->n) {
		return KNOT_EINVAL;
	}

	const unsigned last = --set->n;
	/* Nothing else if it is the last one.
	 * Move last -> i if some remain. */
	if (idx < last) {
		set->pfd[idx] = set->pfd[last];
		set->timeout[idx] = set->timeout[last];
		set->ctx[idx] = set->ctx[last];
	}

	return KNOT_EOK;
}

int fdset_poll(fdset_t *set, fdset_it_t *it, const unsigned offset, const int timeout)
{
	it->ctx = set;
	it->idx = offset;
	it->unprocessed = poll(&set->pfd[offset], set->n - offset, 1000 * timeout);
	while (it->unprocessed > 0 && set->pfd[it->idx].revents == 0) {
		it->idx++;
	}
	return it->unprocessed;
}

int fdset_set_watchdog(fdset_t* set, const unsigned idx, const int interval)
{
	if (set == NULL || idx >= set->n) {
		return KNOT_EINVAL;
	}

	/* Lift watchdog if interval is negative. */
	if (interval < 0) {
		set->timeout[idx] = 0;
		return KNOT_EOK;
	}

	/* Update clock. */
	const struct timespec now = time_now();
	set->timeout[idx] = now.tv_sec + interval; /* Only seconds precision. */

	return KNOT_EOK;
}

int fdset_get_fd(const fdset_t *set, const unsigned idx)
{
	if (set == NULL || idx >= set->n) {
		return KNOT_EINVAL;
	}

	return set->pfd[idx].fd;
}


unsigned fdset_get_length(const fdset_t *set)
{
	assert(set);
	return set->n;
}

int fdset_sweep(fdset_t* set, const fdset_sweep_cb_t cb, void *data)
{
	if (set == NULL || cb == NULL) {
		return KNOT_EINVAL;
	}

	/* Get time threshold. */
	const struct timespec now = time_now();
	unsigned idx = 0;
	while (idx < set->n) {
		/* Check sweep state, remove if requested. */
		if (set->timeout[idx] > 0 && set->timeout[idx] <= now.tv_sec) {
			const int fd = fdset_get_fd(set, idx);
			if (cb(set, fd, data) == FDSET_SWEEP) {
				if (fdset_remove(set, idx) == KNOT_EOK) {
					continue; /* Stay on the index. */
				}
			}
		}
		++idx;
	}
	return KNOT_EOK;
}

void fdset_it_next(fdset_it_t *it)
{
	if (--it->unprocessed > 0) {
		while (it->ctx->pfd[++it->idx].revents == 0); /* nop */
	}
}

int fdset_it_done(const fdset_it_t *it)
{
	return it->unprocessed <= 0;
}

int fdset_it_remove(fdset_it_t *it)
{
	if (it == NULL || it->ctx == NULL) {
		return KNOT_EINVAL;
	}

	fdset_t *set = it->ctx;
	const unsigned idx = fdset_it_get_idx(it);
	fdset_remove(set, idx);
	/* Iterator should return on last valid already processed element. */
	/* On `next` call (in for-loop) will point on first unprocessed. */
	--it->idx;
	return KNOT_EOK;
}

int fdset_it_get_fd(const fdset_it_t *it)
{
	if (it == NULL) {
		return KNOT_EINVAL;
	}

	return it->ctx->pfd[it->idx].fd;
}

unsigned fdset_it_get_idx(const fdset_it_t *it)
{
	assert(it);
	return it->idx;
}

int fdset_it_ev_is_pollin(const fdset_it_t *it)
{
	assert(it);
	return it->ctx->pfd[it->idx].revents & POLLIN;
}

int fdset_it_ev_is_err(const fdset_it_t *it)
{
	assert(it);
	return it->ctx->pfd[it->idx].revents & (POLLERR|POLLHUP|POLLNVAL);
}

#endif
