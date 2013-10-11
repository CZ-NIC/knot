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
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "common/fdset.h"
#include "libknot/common.h"

/* Workarounds for clock_gettime() not available on some platforms. */
#ifdef HAVE_CLOCK_GETTIME
#define time_now(x) clock_gettime(CLOCK_MONOTONIC, (x))
typedef struct timespec timev_t;
#elif HAVE_GETTIMEOFDAY
#include <sys/time.h>
#define time_now(x) gettimeofday((x), NULL)
typedef struct timeval timev_t;
#else
#error Neither clock_gettime() nor gettimeofday() found. At least one is required.
#endif

/* Realloc memory or return error (part of fdset_resize). */
#define MEM_RESIZE(tmp, p, n) \
	if ((tmp = realloc((p), (n))) == NULL) \
		return KNOT_ENOMEM; \
	(p) = tmp;

static int fdset_resize(fdset_t *set, unsigned size)
{
	void *tmp = NULL;
	MEM_RESIZE(tmp, set->ctx, size * sizeof(void*));
	MEM_RESIZE(tmp, set->pfd, size * sizeof(struct pollfd));
	MEM_RESIZE(tmp, set->timeout, size * sizeof(timev_t));
	set->size = size;
	return KNOT_EOK;
}

int fdset_init(fdset_t *set, unsigned size)
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

int fdset_add(fdset_t *set, int fd, unsigned events, void *ctx)
{
	if (set == NULL || fd < 0) {
		return KNOT_EINVAL;
	}

	/* Realloc needed. */
	if (set->n == set->size && fdset_resize(set, set->size + FDSET_INIT_SIZE))
		return KNOT_ENOMEM;

	/* Initialize. */
	int i = set->n++;
	set->pfd[i].fd = fd;
	set->pfd[i].events = events;
	set->pfd[i].revents = 0;
	set->ctx[i] = ctx;
	set->timeout[i] = 0;

	/* Return index to this descriptor. */
	return i;
}

int fdset_remove(fdset_t *set, unsigned i)
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
		set->pfd[i] = set->pfd[last];
		set->timeout[i] = set->timeout[last];
		set->ctx[i] = set->ctx[last];
	}

	return KNOT_EOK;
}

int fdset_set_watchdog(fdset_t* set, int i, int interval)
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
	timev_t now;
	if (time_now(&now) < 0)
		return KNOT_ERROR;

	set->timeout[i] = now.tv_sec + interval; /* Only seconds precision. */
	return KNOT_EOK;
}

int fdset_sweep(fdset_t* set, fdset_sweep_cb_t cb, void *data)
{
	if (set == NULL || cb == NULL) {
		return KNOT_EINVAL;
	}

	/* Get time threshold. */
	timev_t now;
	if (time_now(&now) < 0) {
		return KNOT_ERROR;
	}

	unsigned i = 0;
	while (i < set->n) {

		/* Check sweep state, remove if requested. */
		if (set->timeout[i] > 0 && set->timeout[i] <= now.tv_sec) {
			if (cb(set, i, data) == FDSET_SWEEP) {
				if (fdset_remove(set, i) == KNOT_EOK)
					continue; /* Stay on the index. */
			}
		}

		/* Next descriptor. */
		++i;
	}

	return KNOT_EOK;
}

/* OpenBSD compatibility. */
#if !defined(HAVE_PSELECT) || defined(PSELECT_COMPAT)
/*
 * Like select(2) but set the signals to block while waiting in
 * select.  This version is not entirely race condition safe.  Only
 * operating system support can make it so.
 *
 * Copyright (c) 2001-2011, NLnet Labs. All rights reserved.
 *
 * This software is open source.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * Neither the name of the NLNET LABS nor the names of its contributors may
 * be used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>

static int
pselect_compat (int n,
                fd_set *readfds,
                fd_set *writefds,
                fd_set *exceptfds,
                const struct timespec *timeout,
                const sigset_t *sigmask)
{
	int result;
	sigset_t saved_sigmask;
	struct timeval saved_timeout;

	if (sigmask && sigprocmask(SIG_SETMASK, sigmask, &saved_sigmask) == -1)
		return -1;

	if (timeout) {
		saved_timeout.tv_sec = timeout->tv_sec;
		saved_timeout.tv_usec = timeout->tv_nsec / 1000;
		result = select(n, readfds, writefds, exceptfds, &saved_timeout);
	} else {
		result = select(n, readfds, writefds, exceptfds, NULL);
	}

	if (sigmask && sigprocmask(SIG_SETMASK, &saved_sigmask, NULL) == -1)
		return -1;

	return result;
}

int fdset_pselect(int n, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
                  const struct timespec *timeout, const sigset_t *sigmask)
{
	return pselect_compat(n, readfds, writefds, exceptfds, timeout, sigmask);
}

#else

int fdset_pselect(int n, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
                  const struct timespec *timeout, const sigset_t *sigmask)
{
	return pselect(n, readfds, writefds, exceptfds, timeout, sigmask);
}
#endif
