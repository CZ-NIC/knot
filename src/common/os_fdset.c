#include "os_fdset.h"

#ifdef HAVE_EPOLL
#include "os_fdset_epoll.c"
#else
#include "os_fdset_poll.c"
#endif
