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

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <config.h>

/* OpenBSD compatibility. */
#ifndef HAVE_PSELECT
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
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#include <unistd.h>
#include <signal.h>

static int
pselect (int n,
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

#endif

#include "common/evqueue.h"

/*! \brief Singleton application-wide event queue. */
evqueue_t *s_evqueue = 0;

evqueue_t *evqueue_new()
{
	evqueue_t* q = malloc(sizeof(evqueue_t));

	/* Initialize fds. */
	if (pipe(q->fds) < 0) {
		free(q);
		q = 0;
	}

	return q;
}

void evqueue_free(evqueue_t **q)
{
	/* Check. */
	if (!q) {
		return;
	}

	/* Invalidate pointer to queue. */
	evqueue_t *eq = *q;
	*q = 0;

	/* Deinitialize. */
	close(eq->fds[EVQUEUE_READFD]);
	close(eq->fds[EVQUEUE_WRITEFD]);
	free(eq);
}

int evqueue_poll(evqueue_t *q, const struct timespec *ts,
		 const sigset_t *sigmask)
{
	/* Check. */
	if (!q) {
		return -1;
	}

	/* Prepare fd set. */
	fd_set rfds;
	FD_ZERO(&rfds);
	FD_SET(q->fds[EVQUEUE_READFD], &rfds);

	/* Wait for events. */
	int ret = pselect(q->fds[EVQUEUE_READFD] + 1, &rfds, 0, 0, ts, sigmask);
	if (ret < 0) {
		return -1;
	}

	return ret;
}

int evqueue_read(evqueue_t *q, void *dst, size_t len)
{
	if (!q || !dst || len == 0) {
		return -1;
	}

	return read(q->fds[EVQUEUE_READFD], dst, len);
}

int evqueue_write(evqueue_t *q, const void *src, size_t len)
{
	if (!q || !src || len == 0) {
		return -1;
	}

	return write(q->fds[EVQUEUE_WRITEFD], src, len);
}

int evqueue_get(evqueue_t *q, event_t *ev)
{
	/* Check. */
	if (!q || !ev) {
		return -1;
	}

	/* Read data. */
	int ret = evqueue_read(q, ev, sizeof(event_t));
	if (ret != sizeof(event_t)) {
		return -1;
	}

	/* Set parent. */
	ev->parent = q;

	return 0;
}

int evqueue_add(evqueue_t *q, const event_t *ev)
{
	/* Check. */
	if (!q || !ev) {
		return -1;
	}

	/* Write data. */
	int ret = evqueue_write(q, ev, sizeof(event_t));
	if (ret != sizeof(event_t)) {
		return -1;
	}

	return 0;
}

