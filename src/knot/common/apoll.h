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

#pragma once

#ifdef HAVE_EPOLL
	#include "knot/common/epoll_ctx.h"

	#define apoll_t			epoll_ctx_t
	#define apoll_it_t		epoll_it_t
	#define apoll_sweep_state	epoll_ctx_sweep_state_t

	#define APOLL_CTX_KEEP		EPOLL_CTX_KEEP
	#define APOLL_CTX_SWEEP		EPOLL_CTX_SWEEP

	#define APOLL_POLLIN		EPOLLIN

	#define APOLL_CTX_INIT_SIZE	EPOLL_INIT_SIZE

	#define apoll_init(ctx, size)		epoll_ctx_init(ctx, size)
	#define apoll_close(ctx)		epoll_ctx_close(ctx)
	#define apoll_clear(ctx)		epoll_ctx_clear(ctx)
	#define apoll_add(ctx, fd, events, usrctx) epoll_ctx_add(ctx, fd, events, usrctx)
	#define apoll_set_watchdog(ctx, idx, interval) epoll_ctx_set_watchdog(ctx, idx, interval)
	#define apoll_get_length(ctx)		epoll_ctx_get_length(ctx)
	#define apoll_get_fd(ctx, idx)		epoll_ctx_get_fd(ctx, idx)
	#define apoll_poll(ctx, it, offset, timeout) epoll_ctx_wait(ctx, it, offset, timeout)
	#define apoll_sweep(ctx, cb, data)	epoll_ctx_sweep(ctx, cb, data)
	#define apoll_it_next(it)		epoll_it_next(it)
	#define apoll_it_done(it)		epoll_it_done(it)
	#define apoll_it_remove(it)		epoll_it_remove(it)
	#define apoll_it_get_fd(it)		epoll_it_get_fd(it)
	#define apoll_it_get_idx(it)		epoll_it_get_idx(it)
	#define apoll_it_ev_is_pollin(it)	epoll_it_ev_is_pollin(it)
	#define apoll_it_ev_is_error(it)	epoll_it_ev_is_err(it)
#else
	#include "knot/common/fdset.h"

	#define apoll_t			fdset_t
	#define apoll_it_t		fdset_it_t
	#define apoll_sweep_state	fdset_sweep_state_t

	#define APOLL_CTX_KEEP		FDSET_KEEP
	#define APOLL_CTX_SWEEP		FDSET_SWEEP

	#define APOLL_POLLIN		POLLIN

	#define APOLL_CTX_INIT_SIZE	FDSET_INIT_SIZE

	#define apoll_init(ctx, size)		fdset_init(ctx, size)
	#define apoll_close(ctx)
	#define apoll_clear(ctx)		fdset_clear(ctx)
	#define apoll_add(ctx, fd, events, usrctx) fdset_add(ctx, fd, events, usrctx)
	#define apoll_set_watchdog(ctx, idx, interval) fdset_set_watchdog(ctx, idx, interval)
	#define apoll_get_length(ctx)		fdset_get_length(ctx)
	#define apoll_get_fd(ctx, idx)		fdset_get_fd(ctx, idx)
	#define apoll_poll(ctx, it, offset, timeout) fdset_poll(ctx, it, offset, timeout)
	#define apoll_sweep(ctx, cb, data)	fdset_sweep(ctx, cb, data)
	#define apoll_it_next(it)		fdset_it_next(it)
	#define apoll_it_done(it)		fdset_it_done(it)
	#define apoll_it_remove(it)		fdset_it_remove(it)
	#define apoll_it_get_fd(it)		fdset_it_get_fd(it)
	#define apoll_it_get_idx(it)		fdset_it_get_idx(it)
	#define apoll_it_ev_is_pollin(it)	fdset_it_ev_is_pollin(it)
	#define apoll_it_ev_is_error(it)	fdset_it_ev_is_err(it)
#endif
