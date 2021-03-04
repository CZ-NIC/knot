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

#define USE_AIO 1

#ifdef USE_AIO

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>
#include <poll.h>
#include <linux/aio_abi.h>
#include <sys/syscall.h>
#include "knot/common/aio_ctx.h"
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

static int aio_ctx_resize(aio_ctx_t *set, unsigned size)
{
	void *tmp = NULL;
	MEM_RESIZE(tmp, set->usrctx, size);
	MEM_RESIZE(tmp, set->timeout, size);
	MEM_RESIZE(tmp, set->ev, size);
	set->size = size;
	return KNOT_EOK;
}

int aio_ctx_init(aio_ctx_t *set, unsigned size)
{
	if (set == NULL) {
		return KNOT_EINVAL;
	}

	memset(set, 0, sizeof(aio_ctx_t));

	int ret = io_setup(size, &set->ctx);
	if (ret < 0) {
		return KNOT_ENOMEM;
	}
	
	return aio_ctx_resize(set, size);
}

int aio_ctx_clear(aio_ctx_t* set)
{
	if (set == NULL) {
		return KNOT_EINVAL;
	}

	aio_context_t bck = set->ctx;
	memset(set, 0, sizeof(aio_ctx_t));
	set->ctx = bck;
	return KNOT_EOK;
}

void aio_ctx_close(aio_ctx_t* set)
{
	io_destroy(set->ctx);
}

int aio_ctx_add(aio_ctx_t *set, int fd, unsigned events, void *ctx)
{
	if (set == NULL || fd < 0) {
		return KNOT_EINVAL;
	}

	/* Realloc needed. */
	if (set->n == set->size && aio_ctx_resize(set, set->size + AIO_INIT_SIZE))
		return KNOT_ENOMEM;

	/* Initialize. */
	int i = set->n++;
	set->ev[i].aio_fildes = fd;
	set->ev[i].aio_lio_opcode = IOCB_CMD_POLL;
	set->ev[i].aio_buf = events;
	set->ev[i].aio_data = 0;
	set->usrctx[i] = ctx;
	set->timeout[i] = 0;
	return i;
}

int aio_ctx_wait(aio_ctx_t *ctx, aio_it_t *it, size_t offset, size_t ev_size, int timeout)
{
	if (ctx->recv_size != ctx->size) {
		void *tmp = NULL;
		MEM_RESIZE(tmp, ctx->recv_ev, ctx->size);
		ctx->recv_size = ctx->size;
	}

	it->ctx = ctx;
	it->ptr = ctx->recv_ev;
	it->left = 0;

    struct timespec to = {
		.tv_nsec = 0,
		.tv_sec = timeout
	};

	struct iocb *list_of_iocb[ev_size];
	for (int i = offset; i < offset + ev_size; ++i) {
		list_of_iocb[i - offset] = &(ctx->ev[i]);
	}

	int ret = 0;
	ret = io_submit(ctx->ctx, ev_size, list_of_iocb);
	if (ret < 0) {
		return ret;
	}
	return it->left = io_getevents(ctx->ctx, 1, ev_size, ctx->recv_ev, timeout > 0 ? &to : NULL);
}

static int aio_ctx_remove(aio_ctx_t *set, unsigned i)
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

int aio_ctx_remove_it(aio_ctx_t *set, aio_it_t *it)
{
	unsigned i = aio_it_get_idx(it);
	if (set == NULL || i >= set->n) {
		return KNOT_EINVAL;
	}

	// /* Decrement number of elms. */
	// --set->n;

	// /* Nothing else if it is the last one.
	//  * Move last -> i if some remain. */
	// unsigned last = set->n; /* Already decremented */
	// if (i < last) {
	// 	set->ev[i] = set->ev[last];
	// 	set->timeout[i] = set->timeout[last];
	// 	set->usrctx[i] = set->usrctx[last];
	// }
	((struct iocb *)it->ptr->obj)->aio_data = 1;

	return KNOT_EOK;
}

int aio_ctx_set_watchdog(aio_ctx_t* set, int i, int interval)
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

int aio_ctx_get_fd(aio_ctx_t *ctx, unsigned i)
{
	if (ctx == NULL || i >= ctx->n) {
		return KNOT_EINVAL;
	}

	return ctx->ev[i].aio_fildes;
}

unsigned aio_ctx_get_length(aio_ctx_t *ctx)
{
	assert(ctx);
	return ctx->n;
}

int aio_ctx_sweep(aio_ctx_t* set, aio_ctx_sweep_cb_t cb, void *data)
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
			unsigned fd = aio_ctx_get_fd(set, i);
			if (cb(set, fd, data) == AIO_CTX_SWEEP) {
				if (aio_ctx_remove(set, i) == KNOT_EOK)
					continue; /* Stay on the index. */
			}
		}

		/* Next descriptor. */
		++i;
	}

	return KNOT_EOK;
}

void aio_it_next(aio_it_t *it)
{
	it->left--;
	if (it->left >= 0) {
		it->ptr++;
	}
}

int aio_it_done(aio_it_t *it)
{
	return it->left <= 0;
}

void aio_it_commit(aio_it_t *it)
{
	aio_ctx_t *ctx = it->ctx;
	for (int i = 0; i < ctx->n; ++i) {
		if (ctx->ev[i].aio_data) {
			aio_ctx_remove(ctx, i);
		}
	}
}

int aio_it_get_fd(aio_it_t *it)
{
	assert(it != NULL);
	return ((struct iocb *)it->ptr->obj)->aio_fildes;
}

unsigned aio_it_get_idx(aio_it_t *it)
{
	assert(it != NULL);
	return ((struct iocb *)it->ptr->obj - it->ctx->ev);
}

int aio_it_ev_is_poll(aio_it_t *it)
{
	assert(it);
	return ((struct iocb *)it->ptr->obj)->aio_buf & (POLLIN);
}

int aio_it_ev_is_err(aio_it_t *it)
{
	assert(it);
	return ((struct iocb *)it->ptr->obj)->aio_buf & (POLLERR|POLLHUP|POLLNVAL);
}

#endif