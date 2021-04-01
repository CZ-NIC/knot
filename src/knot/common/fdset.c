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

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "knot/common/fdset.h"
#include "contrib/time.h"
#include "contrib/macros.h"

#define MEM_RESIZE(p, n) { \
	void *tmp = NULL; \
	if ((tmp = realloc((p), (n) * sizeof(*p))) == NULL) { \
		return KNOT_ENOMEM; \
	} \
	(p) = tmp; \
}

static int fdset_resize(fdset_t *set, const unsigned size)
{
	assert(set);

	MEM_RESIZE(set->ctx, size);
	MEM_RESIZE(set->timeout, size);
#ifdef HAVE_EPOLL
	MEM_RESIZE(set->ev, size);
#else
	MEM_RESIZE(set->pfd, size);
#endif
	set->size = size;
	return KNOT_EOK;
}

int fdset_init(fdset_t *set, const unsigned size)
{
	if (set == NULL) {
		return KNOT_EINVAL;
	}

	memset(set, 0, sizeof(*set));

#ifdef HAVE_EPOLL
	set->efd = epoll_create1(0);
	if (set->efd < 0) {
		return knot_map_errno();
	}
#endif
	int ret = fdset_resize(set, size);
#ifdef HAVE_EPOLL
	if (ret != KNOT_EOK) {
		close(set->efd);
	}
#endif
	return ret;
}

void fdset_clear(fdset_t *set)
{
	if (set == NULL) {
		return;
	}

	free(set->ctx);
	free(set->timeout);
#ifdef HAVE_EPOLL
	free(set->ev);
	free(set->recv_ev);
	close(set->efd);
#else
	free(set->pfd);
#endif
	memset(set, 0, sizeof(*set));
}

int fdset_add(fdset_t *set, const int fd, const fdset_event_t events, void *ctx)
{
	if (set == NULL || fd < 0) {
		return KNOT_EINVAL;
	}

	if (set->n == set->size &&
	    fdset_resize(set, set->size + FDSET_RESIZE_STEP) != KNOT_EOK) {
		return KNOT_ENOMEM;
	}

	const int idx = set->n++;
	set->ctx[idx] = ctx;
	set->timeout[idx] = 0;
#ifdef HAVE_EPOLL
	set->ev[idx].data.fd = fd;
	set->ev[idx].events = events;
	struct epoll_event ev = {
		.data.u64 = idx,
		.events = events
	};
	if (epoll_ctl(set->efd, EPOLL_CTL_ADD, fd, &ev) != 0) {
		return knot_map_errno();
	}
#else
	set->pfd[idx].fd = fd;
	set->pfd[idx].events = events;
	set->pfd[idx].revents = 0;
#endif

	return idx;
}

int fdset_remove(fdset_t *set, const unsigned idx)
{
	if (set == NULL || idx >= set->n) {
		return KNOT_EINVAL;
	}

	const int fd = fdset_get_fd(set, idx);
#ifdef HAVE_EPOLL
	/* This is necessary as DDNS duplicates file descriptors! */
	(void)epoll_ctl(set->efd, EPOLL_CTL_DEL, fd, NULL);
#endif
	close(fd);

	const unsigned last = --set->n;
	/* Nothing else if it is the last one. Move last -> i if some remain. */
	if (idx < last) {
		set->ctx[idx] = set->ctx[last];
		set->timeout[idx] = set->timeout[last];
#ifdef HAVE_EPOLL
		set->ev[idx] = set->ev[last];
		struct epoll_event ev = {
			.data.u64 = idx,
			.events = set->ev[idx].events
		};
		if (epoll_ctl(set->efd, EPOLL_CTL_MOD, set->ev[last].data.fd, &ev) != 0) {
			return knot_map_errno();
		}
#else
		set->pfd[idx] = set->pfd[last];
#endif
	}

	return KNOT_EOK;
}

int fdset_poll(fdset_t *set, fdset_it_t *it, const unsigned offset, const int timeout_ms)
{
	if (it == NULL) {
		return KNOT_EINVAL;
	}
	it->unprocessed = 0;

	if (set == NULL) {
		return KNOT_EINVAL;
	}

	it->set = set;
	it->idx = offset;
#ifdef HAVE_EPOLL
	if (set->recv_size != set->size) {
		MEM_RESIZE(set->recv_ev, set->size);
		set->recv_size = set->size;
	}
	it->ptr = set->recv_ev;
	it->dirty = 0;
	/*
	 *  NOTE: Can't skip offset without bunch of syscalls!!
	 *  Because of that it waits for `ctx->n` (every socket). Offset is set when TCP
	 *  trotlling is ON. Sometimes it can return with sockets where none of them are
	 *  connection socket, but it should not be common.
	 *  But it can cause problems when adopted in other use-case.
	 */
	it->unprocessed = epoll_wait(set->efd, set->recv_ev, set->n, timeout_ms);
#ifndef NDEBUG
	/* In specific circumstances with valgrind, it sometimes happens that
	 * `set->n < it->unprocessed`. */
	if (it->unprocessed > 0 && unlikely(it->unprocessed > set->n)) {
		assert(it->unprocessed == 232);
		it->unprocessed = 0;
		for (unsigned i = 0; i < set->recv_size; ++i) {
			const uint64_t idx = set->recv_ev[i].data.u64;
			if (idx > set->n) {
				break;
			} else if (set->recv_ev[i].events != 0) {
				it->unprocessed++;
			}
		}
	}
#endif
	return it->unprocessed;
#else
	it->unprocessed = poll(&set->pfd[offset], set->n - offset, timeout_ms);
#ifndef NDEBUG
	/* In specific circumstances with valgrind, it sometimes happens that
	 * `set->n < it->unprocessed`. */
	if (it->unprocessed > 0 && unlikely(it->unprocessed > set->n - offset)) {
		assert(it->unprocessed == 7);
		it->unprocessed = 0;
		for (unsigned i = offset; i < set->n - offset; i++) {
			if (set->pfd[i].revents != 0) {
				it->unprocessed++;
			}
		}
	}
#endif
	while (it->unprocessed > 0 && set->pfd[it->idx].revents == 0) {
		it->idx++;
	}
	return it->unprocessed;
#endif
}

void fdset_it_commit(fdset_it_t *it)
{
	if (it == NULL) {
		return;
	}
#ifdef HAVE_EPOLL
	/* NOTE: reverse iteration to avoid as much "remove last" operations
	 *       as possible. I'm not sure about performance improvement. It
	 *       will skip some syscalls at begin of iteration, but what
	 *       performance increase do we get is a question.
	 */
	fdset_t *set = it->set;
	for (int i = set->n - 1; it->dirty > 0 && i >= 0; --i) {
		if (set->ev[i].events == FDSET_REMOVE_FLAG) {
			(void)fdset_remove(set, i);
			it->dirty--;
		}
	}
	assert(it->dirty == 0);
#endif
}

int fdset_set_watchdog(fdset_t *set, const unsigned idx, const int interval)
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

void fdset_sweep(fdset_t *set, const fdset_sweep_cb_t cb, void *data)
{
	if (set == NULL || cb == NULL) {
		return;
	}

	/* Get time threshold. */
	const struct timespec now = time_now();
	unsigned idx = 0;
	while (idx < set->n) {
		/* Check sweep state, remove if requested. */
		if (set->timeout[idx] > 0 && set->timeout[idx] <= now.tv_sec) {
			const int fd = fdset_get_fd(set, idx);
			if (cb(set, fd, data) == FDSET_SWEEP) {
				(void)fdset_remove(set, idx);
			}
		}
		++idx;
	}
}
