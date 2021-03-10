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

#define USE_EPOLL 1

#ifdef USE_EPOLL

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>
#include "knot/common/epoll_ctx.h"
#include "contrib/time.h"
#include "libknot/errcode.h"

/* Realloc memory or return error (part of fdset_resize). */
#define MEM_RESIZE(tmp, p, n) \
	if ((tmp = realloc((p), (n) * sizeof(*p))) == NULL) \
		return KNOT_ENOMEM; \
	(p) = tmp;

static int epoll_ctx_resize(epoll_ctx_t *set, unsigned size)
{
	void *tmp = NULL;
	MEM_RESIZE(tmp, set->usrctx, size);
	MEM_RESIZE(tmp, set->timeout, size);
	MEM_RESIZE(tmp, set->ev, size);
	set->size = size;
	return KNOT_EOK;
}

int epoll_ctx_init(epoll_ctx_t *ctx, unsigned size)
{
	if (ctx == NULL) {
		return KNOT_EINVAL;
	}

	memset(ctx, 0, sizeof(epoll_ctx_t));

	ctx->efd = epoll_create1(0);
	if (ctx->efd < 0) {
		return KNOT_ENOMEM;
	}
	
	return epoll_ctx_resize(ctx, size);
}

int epoll_ctx_clear(epoll_ctx_t* set)
{
	if (set == NULL) {
		return KNOT_EINVAL;
	}

	int bck = set->efd;
	memset(set, 0, sizeof(epoll_ctx_t));
	set->efd = bck;
	return KNOT_EOK;
}

void epoll_ctx_close(epoll_ctx_t* set)
{
	close(set->efd);
}

int epoll_ctx_add(epoll_ctx_t *set, int fd, unsigned events, void *ctx)
{
	if (set == NULL || fd < 0) {
		return KNOT_EINVAL;
	}

	/* Realloc needed. */
	if (set->n == set->size && epoll_ctx_resize(set, set->size + FDSET_INIT_SIZE))
		return KNOT_ENOMEM;

	/* Initialize. */
	int i = set->n++;
	set->ev[i].data.fd = fd;
	set->ev[i].events = events;
	set->usrctx[i] = ctx;
	set->timeout[i] = 0;
	struct epoll_event ev = {
		.data.u64 = i,
		.events = events
	};
	epoll_ctl(set->efd, EPOLL_CTL_ADD, fd, &ev);

	return i;
}

static int epoll_ctx_remove(epoll_ctx_t *set, unsigned i)
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
		struct epoll_event ev = {
			.data.u64 = i,
			.events = set->ev[i].events
		};
		epoll_ctl(set->efd, EPOLL_CTL_MOD, set->ev[last].data.fd, &ev);

	}

	return KNOT_EOK;
}

int epoll_ctx_remove_it(epoll_ctx_t *set, epoll_it_t *it)
{
	int i = it->ptr->data.u64;
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
		struct epoll_event ev = {
			.data.u64 = i,
			.events = set->ev[i].events
		};
		epoll_ctl(set->efd, EPOLL_CTL_MOD, set->ev[last].data.fd, &ev);

	}
	it->ptr--;
	return KNOT_EOK;
}

int epoll_ctx_wait(epoll_ctx_t *ctx, epoll_it_t *it, unsigned offset, unsigned ev_size, int timeout)
{
	if (ctx->recv_size != ctx->size) {
		void *tmp = NULL;
		MEM_RESIZE(tmp, ctx->recv_ev, ctx->size);
		ctx->recv_size = ctx->size;
	}
	
	it->ctx = ctx;
	it->ptr = ctx->recv_ev;
	it->offset = offset;

	/*
	 *  NOTE: Can't skip offset without bunch of syscalls!!
	 *  Becouse of that wait for offset + ev_size. Offset is set when TCP trotlling is ON.
	 *  Sometimes it can acceptsockets and none of them are higher than offet, but it
	 *  should not be common.
	 *  It can cause problems when implemented in other use-case.
	 */
	return it->left = epoll_wait(ctx->efd, ctx->recv_ev, offset + ev_size, timeout * 1000);
}

int epoll_ctx_set_watchdog(epoll_ctx_t *set, unsigned i, int interval)
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

unsigned epoll_ctx_get_length(epoll_ctx_t *ctx)
{
	return ctx->n;
}

int epoll_ctx_get_fd(epoll_ctx_t *set, unsigned i)
{
	if (set == NULL || i >= set->n) {
		return KNOT_EINVAL;
	}

	return set->ev[i].data.u64;
}

int epoll_ctx_sweep(epoll_ctx_t* set, epoll_ctx_sweep_cb_t cb, void *data)
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
			int fd = epoll_ctx_get_fd(set, i);
			if (cb(set, fd, data) == EPOLL_CTX_SWEEP) {
				if (epoll_ctx_remove(set, i) == KNOT_EOK)
					continue; /* Stay on the index. */
			}
		}

		/* Next descriptor. */
		++i;
	}

	return KNOT_EOK;
}

void epoll_it_next(epoll_it_t *it)
{
	it->ptr++;
	it->left--;
	while (it->left > 0 && it->ptr->data.u64 < it->offset) {
		it->ptr++;
		it->left--;
	}
}

int epoll_it_done(epoll_it_t *it)
{
	return it->left <= 0;
}

int epoll_it_get_fd(epoll_it_t *it)
{
	assert(it != NULL);
	return it->ctx->ev[epoll_it_get_idx(it)].data.fd;
}

unsigned epoll_it_get_idx(epoll_it_t *it)
{
	assert(it != NULL);
	return it->ptr->data.u64;
}

int epoll_it_ev_is_poll(epoll_it_t *it)
{
	assert(it != NULL);
	return it->ptr->events & EPOLLIN;
}

int epoll_it_ev_is_err(epoll_it_t *it)
{
	assert(it != NULL);
	return it->ptr->events & (EPOLLERR|EPOLLHUP);
}


#endif