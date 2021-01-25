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

#ifdef HAVE_EPOLL

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>
#include "knot/common/epoll_ctx.h"
#include "contrib/time.h"
#include "libknot/errcode.h"

/* Realloc memory or return error (part of epoll_ctx_resize). */
#define MEM_RESIZE(tmp, p, n) \
	if ((tmp = realloc((p), (n) * sizeof(*p))) == NULL) \
		return KNOT_ENOMEM; \
	(p) = tmp;

static int epoll_ctx_resize(epoll_ctx_t *set, const unsigned size)
{
	void *tmp = NULL;
	MEM_RESIZE(tmp, set->usrctx, size);
	MEM_RESIZE(tmp, set->timeout, size);
	MEM_RESIZE(tmp, set->ev, size);
	set->size = size;
	return KNOT_EOK;
}

int epoll_ctx_init(epoll_ctx_t *ctx, const unsigned size)
{
	if (ctx == NULL) {
		return KNOT_EINVAL;
	}

	memset(ctx, 0, sizeof(epoll_ctx_t));

	ctx->efd = epoll_create1(0);
	if (ctx->efd < 0) {
		return KNOT_EMFILE;
	}

	return epoll_ctx_resize(ctx, size);
}

int epoll_ctx_clear(epoll_ctx_t* ctx)
{
	if (ctx == NULL) {
		return KNOT_EINVAL;
	}

	int bck = ctx->efd;
	free(ctx->ev);
	free(ctx->usrctx);
	free(ctx->timeout);
	free(ctx->recv_ev);
	memset(ctx, 0, sizeof(epoll_ctx_t));
	ctx->efd = bck;
	return KNOT_EOK;
}

void epoll_ctx_close(const epoll_ctx_t* ctx)
{
	close(ctx->efd);
}

int epoll_ctx_add(epoll_ctx_t *ctx, const int fd, const unsigned events, void *usrctx)
{
	if (ctx == NULL || fd < 0) {
		return KNOT_EINVAL;
	}

	/* Realloc needed. */
	if (ctx->n == ctx->size && epoll_ctx_resize(ctx, ctx->size + EPOLL_INIT_SIZE))
		return KNOT_ENOMEM;

	/* Initialize. */
	const int i = ctx->n++;
	ctx->ev[i].data.fd = fd;
	ctx->ev[i].events = events;
	ctx->usrctx[i] = usrctx;
	ctx->timeout[i] = 0;
	struct epoll_event ev = {
		.data.u64 = i,
		.events = events
	};
	epoll_ctl(ctx->efd, EPOLL_CTL_ADD, fd, &ev);

	return i;
}

static int epoll_ctx_remove(epoll_ctx_t *ctx, const unsigned idx)
{
	if (ctx == NULL || idx >= ctx->n) {
		return KNOT_EINVAL;
	}

	epoll_ctl(ctx->efd, EPOLL_CTL_DEL, ctx->ev[idx].data.fd, NULL);
	const unsigned last = --ctx->n;
	/* Nothing else if it is the last one.
	 * Move last -> i if some remain. */
	if (idx < last) {
		ctx->ev[idx] = ctx->ev[last];
		ctx->timeout[idx] = ctx->timeout[last];
		ctx->usrctx[idx] = ctx->usrctx[last];
		struct epoll_event ev = {
			.data.u64 = idx,
			.events = ctx->ev[idx].events
		};
		epoll_ctl(ctx->efd, EPOLL_CTL_MOD, ctx->ev[last].data.fd, &ev);
	}

	return KNOT_EOK;
}

int epoll_ctx_wait(epoll_ctx_t *ctx, epoll_it_t *it, const unsigned offset, const int timeout)
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
	 *  Because of that it waits for `ctx->n` (every socket). Offset is set when TCP
	 *  trotlling is ON. Sometimes it can return with sockets where none of them are
	 *  connection socket, but it should not be common.
	 *  But it can cause problems when adopted in other use-case.
	 */
	return it->unprocessed = epoll_wait(ctx->efd, ctx->recv_ev, ctx->n, timeout * 1000);
}

int epoll_ctx_set_watchdog(epoll_ctx_t *ctx, const unsigned idx, const int interval)
{
	if (ctx == NULL || idx >= ctx->n) {
		return KNOT_EINVAL;
	}

	/* Lift watchdog if interval is negative. */
	if (interval < 0) {
		ctx->timeout[idx] = 0;
		return KNOT_EOK;
	}

	/* Update clock. */
	const struct timespec now = time_now();
	ctx->timeout[idx] = now.tv_sec + interval; /* Only seconds precision. */
	return KNOT_EOK;
}

int epoll_ctx_get_fd(const epoll_ctx_t *ctx, const unsigned idx)
{
	if (ctx == NULL || idx >= ctx->n) {
		return KNOT_EINVAL;
	}

	return ctx->ev[idx].data.u64;
}

unsigned epoll_ctx_get_length(const epoll_ctx_t *ctx)
{
	assert(ctx);
	return ctx->n;
}

int epoll_ctx_sweep(epoll_ctx_t* ctx, const epoll_ctx_sweep_cb_t cb, void *data)
{
	if (ctx == NULL || cb == NULL) {
		return KNOT_EINVAL;
	}

	/* Get time threshold. */
	const struct timespec now = time_now();
	unsigned idx = 0;
	while (idx < ctx->n) {
		/* Check sweep state, remove if requested. */
		if (ctx->timeout[idx] > 0 && ctx->timeout[idx] <= now.tv_sec) {
			const int fd = epoll_ctx_get_fd(ctx, idx);
			if (cb(ctx, fd, data) == EPOLL_CTX_SWEEP) {
				if (epoll_ctx_remove(ctx, idx) == KNOT_EOK) {
					continue; /* Stay on the index. */
				}
			}
		}
		++idx;
	}

	return KNOT_EOK;
}

void epoll_it_next(epoll_it_t *it)
{
	do {
		it->ptr++;
		it->unprocessed--;
	} while (it->unprocessed > 0 && epoll_it_get_idx(it) < it->offset);
}

int epoll_it_done(const epoll_it_t *it)
{
	return it->unprocessed <= 0;
}

int epoll_it_remove(epoll_it_t *it)
{
	if (it == NULL || it->ctx == NULL) {
		return KNOT_EINVAL;
	}
	epoll_ctx_t *ctx = it->ctx;
	const int idx = epoll_it_get_idx(it);
	epoll_ctx_remove(ctx, idx);
	/* Iterator should return on last valid already processed element. */
	/* On `next` call (in for-loop) will point on first unprocessed. */
	it->ptr--;
	return KNOT_EOK;
}

int epoll_it_get_fd(const epoll_it_t *it)
{
	assert(it != NULL);
	return it->ctx->ev[epoll_it_get_idx(it)].data.fd;
}

unsigned epoll_it_get_idx(const epoll_it_t *it)
{
	assert(it != NULL);
	return it->ptr->data.u64;
}

int epoll_it_ev_is_pollin(const epoll_it_t *it)
{
	assert(it != NULL);
	return it->ptr->events & EPOLLIN;
}

int epoll_it_ev_is_err(const epoll_it_t *it)
{
	assert(it != NULL);
	return it->ptr->events & (EPOLLERR|EPOLLHUP);
}

#endif
