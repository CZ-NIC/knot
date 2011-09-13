#include "os_fdset.h"

#define HAVE_EPOLL

#ifdef HAVE_EPOLL
#include "os_fdset_epoll.c"
#else
#include "os_fdset_poll.c"
#endif
