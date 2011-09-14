#include "os_fdset.h"
#include "config.h"

/* Attempt to use epoll_wait(). */
#ifdef HAVE_EPOLL_WAIT
  #include "os_fdset_epoll.c"
#else
  /* Attempt to use kqueue(). */
  #ifdef HAVE_KQUEUE
    #warning "os_fdset: kqueue backend N/A, fallback to poll()"
    #include "os_fdset_poll.c"
  #else
    /* poll() API */
    #ifdef HAVE_POLL
      #include "os_fdset_poll.c"
    #else
      #error "os_fdset: no socket polling API found"
    #endif /* HAVE_POLL */
  #endif /* HAVE_KQUEUE */
#endif /* HAVE_EPOLL_WAIT */

/*! \todo Implement switchable backends on run-time. */
///*! \brief Bootstrap polling subsystem (it is called automatically). */
//#include <stdio.h>
//#define _GNU_SOURCE /* Required for RTLD_DEFAULT. */
//#include <dlfcn.h>
//void __attribute__ ((constructor)) os_fdset_init()
//{
//	int poll_ok = dlsym(RTLD_DEFAULT, "poll") != 0;
//	int epoll_ok = dlsym(RTLD_DEFAULT, "epoll_wait") != 0;
//	int kqueue_ok = dlsym(RTLD_DEFAULT, "kqueue") != 0;

//	fprintf(stderr, "using polling subsystem %s (poll %d epoll %d kqueue %d)\n",
//		os_fdset_method(), poll_ok, epoll_ok, kqueue_ok);
//}
