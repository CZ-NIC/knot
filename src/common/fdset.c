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
