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
