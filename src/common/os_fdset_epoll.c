#include <sys/epoll.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "os_fdset.h"

#define OS_FDS_CHUNKSIZE 8   /*!< Number of pollfd structs in a chunk. */
#define OS_FDS_KEEPCHUNKS 32 /*!< Will attempt to free memory when reached. */

struct os_fdset_t {
	int epfd;
	struct epoll_event *events;
	size_t nfds;
	size_t reserved;
	size_t polled;
};

struct os_fdset_t *os_fdset_new()
{
	struct os_fdset_t *set = malloc(sizeof(struct os_fdset_t));
	if (!set) {
		return 0;
	}

	/* Blank memory. */
	memset(set, 0, sizeof(struct os_fdset_t));

	/* Create epoll fd. */
	set->epfd = epoll_create(OS_FDS_CHUNKSIZE);

	return set;
}

int os_fdset_destroy(struct os_fdset_t * fdset)
{
	if(!fdset) {
		return -1;
	}

	/* Teardown epoll. */
	close(fdset->epfd);

	/* OK if NULL. */
	free(fdset->events);
	free(fdset);
	return 0;
}

int os_fdset_add(struct os_fdset_t *fdset, int fd, int events)
{
	if (!fdset || fd < 0 || events <= 0) {
		return -1;
	}

	/* Realloc needed. */
	if (fdset->nfds == fdset->reserved) {
		const size_t chunk = OS_FDS_CHUNKSIZE;
		const size_t nsize = (fdset->reserved + chunk) *
				     sizeof(struct epoll_event);
		struct epoll_event *events_n = malloc(nsize);
		if (!events_n) {
			return -1;
		}

		/* Clear and copy old fdset data. */
		memset(events_n, 0, nsize);
		memcpy(events_n, fdset->events,
		       fdset->nfds * sizeof(struct epoll_event));
		free(fdset->events);
		fdset->events = events_n;
		fdset->reserved += chunk;
	}

	/* Add to epoll set. */
	struct epoll_event ev;
	ev.events = EPOLLIN; /*! \todo MAP events. */
	ev.data.fd = fd;
	if (epoll_ctl(fdset->epfd, EPOLL_CTL_ADD, fd, &ev) < 0) {
		return -1;
	}

	++fdset->nfds;
	return 0;
}

int os_fdset_remove(struct os_fdset_t *fdset, int fd)
{
	if (!fdset || fd < 0) {
		return -1;
	}

	/* Attempt to remove from set. */
	struct epoll_event ev;
	memset(&ev, 0, sizeof(struct epoll_event));
	if (epoll_ctl(fdset->epfd, EPOLL_CTL_DEL, fd, &ev) < 0) {
		return -1;
	}

	/* Overwrite current item. */
	--fdset->nfds;

	/*! \todo Return memory if overallocated (nfds is far lower than reserved). */
	return 0;
}

int os_fdset_poll(struct os_fdset_t *fdset)
{
	if (!fdset || fdset->nfds < 1 || !fdset->events) {
		return -1;
	}

	/* Poll new events. */
	fdset->polled = 0;
	int nfds = epoll_wait(fdset->epfd, fdset->events, fdset->nfds, -1);

	/* Check. */
	if (nfds < 0) {
		return -1;
	}

	/* Events array is ordered from 0 to nfds. */
	fdset->polled = nfds;
	return nfds;
}

int os_fdset_begin(struct os_fdset_t *fdset, os_fdset_it *it)
{
	if (!fdset || !it) {
		return -1;
	}

	/* Find first. */
	it->pos = 0;
	return os_fdset_next(fdset, it);
}

int os_fdset_end(struct os_fdset_t *fdset, os_fdset_it *it)
{
	if (!fdset || !it || fdset->nfds < 1) {
		return -1;
	}

	/* Check for polled events. */
	if (fdset->polled < 1) {
		it->fd = -1;
		it->pos = 0;
		return -1;
	}

	/* No end found, ends on the beginning. */
	size_t nid = fdset->polled - 1;
	it->fd = fdset->events[nid].data.fd;
	it->pos = nid;
	it->events = 0; /*! \todo Map events. */
	return -1;
}

int os_fdset_next(struct os_fdset_t *fdset, os_fdset_it *it)
{
	if (!fdset || !it || fdset->nfds < 1) {
		return -1;
	}

	/* Check boundaries. */
	if (it->pos >= fdset->polled) {
		return -1;
	}

	/* Select next. */
	size_t nid = it->pos++;
	it->fd = fdset->events[nid].data.fd;
	it->events = 0; /*! \todo Map events. */
	return 0;
}

const char* os_fdset_method()
{
	return "epoll";
}
