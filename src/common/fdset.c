#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* Required for RTLD_DEFAULT. */
#endif

#include <dlfcn.h>
#include <string.h>
#include <stdio.h>
#include "common/fdset.h"
#include "config.h"

struct fdset_backend_t _fdset_backend = {
};

/*! \brief Set backend implementation. */
static void fdset_set_backend(struct fdset_backend_t *backend) {
	_fdset_backend.fdset_new = backend->fdset_new;
	_fdset_backend.fdset_destroy = backend->fdset_destroy;
	_fdset_backend.fdset_add = backend->fdset_add;
	_fdset_backend.fdset_remove = backend->fdset_remove;
	_fdset_backend.fdset_wait = backend->fdset_wait;
	_fdset_backend.fdset_begin = backend->fdset_begin;
	_fdset_backend.fdset_end = backend->fdset_end;
	_fdset_backend.fdset_next = backend->fdset_next;
	_fdset_backend.fdset_method = backend->fdset_method;
}

/* Linux epoll API. */
#ifdef HAVE_EPOLL_WAIT
  /*! \todo Implement correctly. */
  #include "common/fdset_epoll.c"
#endif /* HAVE_EPOLL_WAIT */

/* BSD kqueue API */
#ifdef HAVE_KQUEUE
  #warning "fixme: missing kqueue backend"
  //#include "common/fdset_kqueue.h"
#endif /* HAVE_KQUEUE */

/* POSIX poll API */
#ifdef HAVE_POLL
#ifndef HAVE_EPOLL_WAIT
  #include "common/fdset_poll.c"
#endif
#endif /* HAVE_POLL */

/*! \brief Bootstrap polling subsystem (it is called automatically). */
void __attribute__ ((constructor)) fdset_init()
{
	/* Preference: epoll */
#ifdef HAVE_EPOLL_WAIT
//	if (dlsym(RTLD_DEFAULT, "epoll_wait") != 0) {
//		fdset_set_backend(&_fdset_epoll);
//		return;
//	}
#endif

	/* Preference: kqueue */
#ifdef HAVE_KQUEUE
//	if (dlsym(RTLD_DEFAULT, "kqueue") != 0) {
//		fdset_set_backend(&_fdset_kqueue);
//		return;
//	}
#endif

	/* Preference: poll */
#ifdef HAVE_POLL
	if (dlsym(RTLD_DEFAULT, "poll") != 0) {
		fdset_set_backend(&_fdset_poll);
		return;
	}
#endif

	/* This shouldn't happen. */
	fprintf(stderr, "fdset: fatal error - no valid fdset backend found\n");
	return;
}
