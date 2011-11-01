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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* Required for RTLD_DEFAULT. */
#endif

#include <dlfcn.h>
#include <string.h>
#include <stdio.h>
#include "common/fdset.h"
#include <config.h>

struct fdset_backend_t _fdset_backend = {
};

/*! \brief Set backend implementation. */
static void fdset_set_backend(struct fdset_backend_t *backend) {
	memcpy(&_fdset_backend, backend, sizeof(struct fdset_backend_t));
}

/* Linux epoll API. */
#ifdef HAVE_EPOLL_WAIT
  #include "common/fdset_epoll.h"
#endif /* HAVE_EPOLL_WAIT */

/* BSD kqueue API */
#ifdef HAVE_KQUEUE
  #include "common/fdset_kqueue.h"
#endif /* HAVE_KQUEUE */

/* POSIX poll API */
#ifdef HAVE_POLL
  #include "common/fdset_poll.h"
#endif /* HAVE_POLL */

/*! \brief Bootstrap polling subsystem (it is called automatically). */
void __attribute__ ((constructor)) fdset_init()
{
	/* Preference: epoll */
#ifdef HAVE_EPOLL_WAIT
	if (dlsym(RTLD_DEFAULT, "epoll_wait") != 0) {
		fdset_set_backend(&FDSET_EPOLL);
		return;
	}
#endif

	/* Preference: kqueue */
#ifdef HAVE_KQUEUE
	if (dlsym(RTLD_DEFAULT, "kqueue") != 0) {
		fdset_set_backend(&FDSET_KQUEUE);
		return;
	}
#endif

	/* Fallback: poll */
#ifdef HAVE_POLL
	if (dlsym(RTLD_DEFAULT, "poll") != 0) {
		fdset_set_backend(&FDSET_POLL);
		return;
	}
#endif

	/* This shouldn't happen. */
	fprintf(stderr, "fdset: fatal error - no valid fdset backend found\n");
	return;
}
