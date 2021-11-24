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
#if defined(HAVE_EPOLL) || defined(HAVE_KQUEUE)
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

#if defined(HAVE_EPOLL) || defined(HAVE_KQUEUE)
#ifdef HAVE_EPOLL
	set->pfd = epoll_create1(0);
#elif HAVE_KQUEUE
	set->pfd = kqueue();
#endif
	if (set->pfd < 0) {
		return knot_map_errno();
	}
#endif
	int ret = fdset_resize(set, size);
#if defined(HAVE_EPOLL) || defined(HAVE_KQUEUE)
	if (ret != KNOT_EOK) {
		close(set->pfd);
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
#if defined(HAVE_EPOLL) || defined(HAVE_KQUEUE)
	free(set->ev);
	free(set->recv_ev);
	close(set->pfd);
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
	if (epoll_ctl(set->pfd, EPOLL_CTL_ADD, fd, &ev) != 0) {
		return knot_map_errno();
	}
#elif HAVE_KQUEUE
	EV_SET(&set->ev[idx], fd, events, EV_ADD, 0, 0, (void *)(intptr_t)idx);
	if (kevent(set->pfd, &set->ev[idx], 1, NULL, 0, NULL) < 0) {
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
	if (epoll_ctl(set->pfd, EPOLL_CTL_DEL, fd, NULL) != 0) {
		close(fd);
		return knot_map_errno();
	}
#elif HAVE_KQUEUE
	/* Return delete flag back to original filter number. */
#if defined(__NetBSD__)
	if ((signed short)set->ev[idx].filter < 0)
#else
	if (set->ev[idx].filter >= 0)
#endif
	{
		set->ev[idx].filter = ~set->ev[idx].filter;
	}
	set->ev[idx].flags = EV_DELETE;
	if (kevent(set->pfd, &set->ev[idx], 1, NULL, 0, NULL) < 0) {
		close(fd);
		return knot_map_errno();
	}
#endif
	close(fd);

	const unsigned last = --set->n;
	/* Nothing else if it is the last one. Move last -> i if some remain. */
	if (idx < last) {
		set->ctx[idx] = set->ctx[last];
		set->timeout[idx] = set->timeout[last];
#if defined(HAVE_EPOLL) || defined (HAVE_KQUEUE)
		set->ev[idx] = set->ev[last];
#ifdef HAVE_EPOLL
		struct epoll_event ev = {
			.data.u64 = idx,
			.events = set->ev[idx].events
		};
		if (epoll_ctl(set->pfd, EPOLL_CTL_MOD, set->ev[last].data.fd, &ev) != 0) {
			return knot_map_errno();
		}
#elif HAVE_KQUEUE
		EV_SET(&set->ev[idx], set->ev[last].ident, set->ev[last].filter,
		       EV_ADD, 0, 0, (void *)(intptr_t)idx);
		if (kevent(set->pfd, &set->ev[idx], 1, NULL, 0, NULL) < 0) {
			return knot_map_errno();
		}
#endif
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
#if defined(HAVE_EPOLL) || defined(HAVE_KQUEUE)
	if (set->recv_size != set->size) {
		MEM_RESIZE(set->recv_ev, set->size);
		set->recv_size = set->size;
	}
	it->ptr = set->recv_ev;
	it->dirty = 0;
#ifdef HAVE_EPOLL
	if (set->n == 0) {
		return 0;
	}
	if ((it->unprocessed = epoll_wait(set->pfd, set->recv_ev, set->recv_size,
	                                  timeout_ms)) == -1) {
		return knot_map_errno();
	}
#ifndef NDEBUG
	/* In specific circumstances with valgrind, it sometimes happens that
	 * `set->n < it->unprocessed`. */
	if (it->unprocessed > 0 && unlikely(it->unprocessed > set->n)) {
		assert(it->unprocessed == 232);
		it->unprocessed = 0;
	}
#endif
#elif HAVE_KQUEUE
	struct timespec timeout = {
		.tv_sec = timeout_ms / 1000,
		.tv_nsec = (timeout_ms % 1000) * 1000000
	};
	if ((it->unprocessed = kevent(set->pfd, NULL, 0, set->recv_ev, set->recv_size,
	                              (timeout_ms >= 0) ? &timeout : NULL)) == -1) {
		return knot_map_errno();
	}
#endif
	/*
	 *  NOTE: Can't skip offset without bunch of syscalls!
	 *  Because of that it waits for `ctx->n` (every socket). Offset is set when TCP
	 *  throttling is ON. Sometimes it can return with sockets where none of them is
	 *  connected socket, but it should not be common.
	 */
	while (it->unprocessed > 0 && fdset_it_get_idx(it) < it->idx) {
		it->ptr++;
		it->unprocessed--;
	}
	return it->unprocessed;
#else
	it->unprocessed = poll(&set->pfd[offset], set->n - offset, timeout_ms);
#ifndef NDEBUG
	/* In specific circumstances with valgrind, it sometimes happens that
	 * `set->n < it->unprocessed`. */
	if (it->unprocessed > 0 && unlikely(it->unprocessed > set->n - offset)) {
		assert(it->unprocessed == 7);
		it->unprocessed = 0;
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
#if defined(HAVE_EPOLL) || defined(HAVE_KQUEUE)
	/* NOTE: reverse iteration to avoid as much "remove last" operations
	 *       as possible. I'm not sure about performance improvement. It
	 *       will skip some syscalls at begin of iteration, but what
	 *       performance increase do we get is a question.
	 */
	fdset_t *set = it->set;
	for (int i = set->n - 1; it->dirty > 0 && i >= 0; --i) {
#ifdef HAVE_EPOLL
		if (set->ev[i].events == FDSET_REMOVE_FLAG)
#else
#if defined(__NetBSD__)
		if ((signed short)set->ev[i].filter < 0)
#else
		if (set->ev[i].filter >= 0)
#endif
#endif
		{
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
				continue;
			}
		}
		++idx;
	}
}
