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
#include "libknot/errcode.h"
#include "contrib/time.h"

#define MEM_RESIZE(p, n) { \
	void *tmp = NULL; \
	if ((tmp = realloc((p), (n) * sizeof(*p))) == NULL) { \
		return KNOT_ENOMEM; \
	} \
	(p) = tmp; \
}

#ifdef HAVE_AIO
#ifndef IOCB_CMD_POLL
#define IOCB_CMD_POLL 5 /* from 4.18 */
#endif

#ifdef __x86_64__
#define read_barrier() __asm__ __volatile__("lfence" ::: "memory")
#else
#ifdef __i386__
#define read_barrier() __asm__ __volatile__("" : : : "memory")
#else
#define read_barrier() __sync_synchronize()
#endif
#endif

#define AIO_RING_MAGIC 0xa10a10a1
struct aio_ring {
	unsigned id; /** kernel internal index number */
	unsigned nr; /** number of io_events */
	unsigned head;
	unsigned tail;

	unsigned magic;
	unsigned compat_features;
	unsigned incompat_features;
	unsigned header_length; /** size of aio_ring */

	struct io_event events[0];
};

inline static int io_setup(unsigned nr, aio_context_t *ctxp)
{
	return syscall(__NR_io_setup, nr, ctxp);
}

inline static int io_destroy(aio_context_t ctx)
{
	return syscall(__NR_io_destroy, ctx);
}

inline static int io_submit(aio_context_t ctx, long nr, struct iocb **iocbpp)
{
	return syscall(__NR_io_submit, ctx, nr, iocbpp);
}

/* Code based on axboe/fio:
 * https://github.com/axboe/fio/blob/702906e9e3e03e9836421d5e5b5eaae3cd99d398/engines/libaio.c#L149-L172
 */
inline static int io_getevents(aio_context_t ctx, long min_nr, long max_nr,
			       struct io_event *events,
			       struct timespec *timeout)
{
	int i = 0;

	struct aio_ring *ring = (struct aio_ring *)ctx;
	if (ring == NULL || ring->magic != AIO_RING_MAGIC) {
		goto do_syscall;
	}

	while (i < max_nr) {
		unsigned head = ring->head;
		if (head == ring->tail) {
			/* There are no more completions */
			break;
		} else {
			/* There is another completion to reap */
			events[i] = ring->events[head];
			read_barrier();
			ring->head = (head + 1) % ring->nr;
			i++;
		}
	}

	if (i == 0 && timeout != NULL && timeout->tv_sec == 0 &&
	    timeout->tv_nsec == 0) {
		/* Requested non blocking operation. */
		return 0;
	}

	if (i && i >= min_nr) {
		return i;
	}

do_syscall:
	return syscall(__NR_io_getevents, ctx, min_nr - i, max_nr - i,
	               &events[i], timeout);
}

#endif

static int fdset_resize(fdset_t *set, const unsigned size)
{
	assert(set);

	MEM_RESIZE(set->ctx, size);
	MEM_RESIZE(set->timeout, size);
#if defined(HAVE_EPOLL) || defined(HAVE_AIO)
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
#elif HAVE_AIO
	int ret = io_setup(1024, &set->aioctx);
	if (ret < 0) {
		return knot_map_errno();
	}
#endif
	return fdset_resize(set, size);
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
#elif HAVE_AIO
	free(set->ev);
	io_destroy(set->aioctx);
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
#elif HAVE_AIO
	set->ev[idx].aio_fildes = fd;
	set->ev[idx].aio_lio_opcode = IOCB_CMD_POLL;
	set->ev[idx].aio_buf = events;
	set->ev[idx].aio_data = idx;
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
#elif HAVE_AIO
		set->ev[idx] = set->ev[last];
		set->ev[idx].aio_data = idx;
#else
		set->pfd[idx] = set->pfd[last];
#endif
	}

	return KNOT_EOK;
}

int fdset_poll(fdset_t *set, fdset_it_t *it, const unsigned offset, const int timeout_ms)
{
	if (set == NULL || it == NULL) {
		return KNOT_EINVAL;
	}

	it->fdset = set;
	it->idx = offset;
#if defined(HAVE_EPOLL) || defined(HAVE_AIO)
	if (set->recv_size != set->size) {
		MEM_RESIZE(set->recv_ev, set->size);
		set->recv_size = set->size;
	}
	it->ptr = set->recv_ev;
	it->dirty = 0;
#ifdef HAVE_EPOLL
	/*
	 *  NOTE: Can't skip offset without bunch of syscalls!!
	 *  Because of that it waits for `ctx->n` (every socket). Offset is set when TCP
	 *  trotlling is ON. Sometimes it can return with sockets where none of them are
	 *  connection socket, but it should not be common.
	 *  But it can cause problems when adopted in other use-case.
	 */
	return it->unprocessed = epoll_wait(set->efd, set->recv_ev, set->n, timeout_ms);
#else
    struct timespec to = {
		.tv_nsec = (timeout_ms % 1000) * 1000000,
		.tv_sec = timeout_ms / 1000
	};

	struct iocb *list_of_iocb[set->n - offset];
	for (int i = 0; i + offset < set->n; ++i) {
		list_of_iocb[i] = &(set->ev[i + offset]);
	}

	int ret = 0;
	ret = io_submit(set->aioctx, set->n - offset, list_of_iocb);
	if (ret < 0) {
	 	return knot_map_errno();
	}
	return it->unprocessed = io_getevents(set->aioctx, 1, set->recv_size, set->recv_ev, timeout_ms > 0 ? &to : NULL);
#endif
#else
	it->unprocessed = poll(&set->pfd[offset], set->n - offset, timeout_ms);
	while (it->unprocessed > 0 && set->pfd[it->idx].revents == 0) {
		it->idx++;
	}
	return it->unprocessed;
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
