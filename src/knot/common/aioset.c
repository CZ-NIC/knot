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
#include <linux/aio_abi.h>
#include <sys/syscall.h>
#include "knot/common/aioset.h"
#include "contrib/time.h"
#include "libknot/errcode.h"

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

/* Stolen from kernel arch/x86_64.h */
#ifdef __x86_64__
#define read_barrier() __asm__ __volatile__("lfence" ::: "memory")
#else
#ifdef __i386__
#define read_barrier() __asm__ __volatile__("" : : : "memory")
#else
#define read_barrier() __sync_synchronize()
#endif
#endif

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

#ifndef IOCB_CMD_POLL
#define IOCB_CMD_POLL 5 /* from 4.18 */
#endif

/* Realloc memory or return error (part of fdset_resize). */
#define MEM_RESIZE(tmp, p, n) \
	if ((tmp = realloc((p), (n) * sizeof(*p))) == NULL) \
		return KNOT_ENOMEM; \
	(p) = tmp;

static int epoll_set_resize(aioset_t *set, unsigned size)
{
	void *tmp = NULL;
	MEM_RESIZE(tmp, set->usrctx, size);
	MEM_RESIZE(tmp, set->timeout, size);
	MEM_RESIZE(tmp, set->ev, size);
	set->size = size;
	return KNOT_EOK;
}

int aioset_init(aioset_t *set, unsigned size)
{
	if (set == NULL) {
		return KNOT_EINVAL;
	}

	memset(set, 0, sizeof(aioset_t));

	int ret = io_setup(128, &set->ctx);
	if (ret < 0) {
		return KNOT_ENOMEM;
	}
	
	return epoll_set_resize(set, size);
}

int aioset_clear(aioset_t* set)
{
	if (set == NULL) {
		return KNOT_EINVAL;
	}

	free(set->usrctx);
	free(set->timeout);
	free(set->ev);
	memset(set, 0, sizeof(aioset_t));
	return KNOT_EOK;
}

void aioset_close(aioset_t* set)
{
	io_destroy(set->ctx);
}

int aioset_add(aioset_t *set, int fd, unsigned events, void *ctx)
{
	if (set == NULL || fd < 0) {
		return KNOT_EINVAL;
	}

	/* Realloc needed. */
	if (set->n == set->size && epoll_set_resize(set, set->size + FDSET_INIT_SIZE))
		return KNOT_ENOMEM;

	/* Initialize. */
	int i = set->n++;
	set->ev[i].aio_fildes = fd;
	set->ev[i].aio_lio_opcode = IOCB_CMD_POLL;
	set->ev[i].aio_buf = events;
	set->usrctx[i] = ctx;
	set->timeout[i] = 0;
	return i;
}

int aioset_wait(aioset_t *set, struct io_event *ev, size_t ev_size, struct timespec *timeout)
{
	struct iocb *list_of_iocb[set->n];
	for (int i = 0; i < set->n; ++i) {
		list_of_iocb[i] = &(set->ev[i]);
	}

	int ret = io_submit(set->ctx, set->n, list_of_iocb);
	if (ret < 0) {
		return ret;
	}
	ret = io_getevents(set->ctx, 1, set->n, ev, timeout);

	return ret;
}

int aioset_remove(aioset_t *set, unsigned i)
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
		set->usrctx[i] = set->usrctx[last];
	}

	return KNOT_EOK;
}

int aioset_set_watchdog(aioset_t* set, int i, int interval)
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

int aioset_sweep(aioset_t* set, epoll_set_sweep_cb_t cb, void *data)
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
				if (aioset_remove(set, i) == KNOT_EOK)
					continue; /* Stay on the index. */
			}
		}

		/* Next descriptor. */
		++i;
	}

	return KNOT_EOK;
}
