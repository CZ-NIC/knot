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

#ifdef HAVE_EPOLL_WAIT

#include <sys/epoll.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "fdset_epoll.h"
#include "skip-list.h"

#define OS_FDS_CHUNKSIZE 8   /*!< Number of pollfd structs in a chunk. */

struct fdset_t {
	fdset_base_t _base;
	int epfd;
	struct epoll_event *events;
	size_t nfds;
	size_t reserved;
	size_t polled;
};

fdset_t *fdset_epoll_new()
{
	fdset_t *set = malloc(sizeof(fdset_t));
	if (set) {
		/* Blank memory. */
		memset(set, 0, sizeof(fdset_t));

		/* Create epoll fd. */
		set->epfd = epoll_create(OS_FDS_CHUNKSIZE);
	}

	return set;
}

int fdset_epoll_destroy(fdset_t * fdset)
{
	if(fdset == NULL) {
		return -1;
	}

	/* Teardown epoll. */
	close(fdset->epfd);

	/* OK if NULL. */
	free(fdset->events);
	free(fdset);
	return 0;
}

int fdset_epoll_add(fdset_t *fdset, int fd, int events)
{
	if (fdset == NULL || fd < 0 || events <= 0) {
		return -1;
	}

	/* Realloc needed. */
	if (mreserve((char **)&fdset->events, sizeof(struct epoll_event),
	             fdset->nfds + 1, OS_FDS_CHUNKSIZE, &fdset->reserved) < 0) {
		return -1;
	}

	/* Add to epoll set. */
	struct epoll_event ev;
	memset(&ev, 0, sizeof(struct epoll_event));
	ev.events = EPOLLIN;
	ev.data.fd = fd;
	if (epoll_ctl(fdset->epfd, EPOLL_CTL_ADD, fd, &ev) < 0) {
		return -1;
	}

	++fdset->nfds;
	return 0;
}

int fdset_epoll_remove(fdset_t *fdset, int fd)
{
	if (fdset == NULL || fd < 0) {
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

	/* Trim excessive memory if possible (retval is not interesting). */
	mreserve((char **)&fdset->events, sizeof(struct epoll_event),
	         fdset->nfds + 1, OS_FDS_CHUNKSIZE, &fdset->reserved);

	return 0;
}

int fdset_epoll_wait(fdset_t *fdset, int timeout)
{
	if (fdset == NULL || fdset->nfds < 1 || fdset->events == NULL) {
		return -1;
	}

	/* Poll new events. */
	fdset->polled = 0;
	int nfds = epoll_wait(fdset->epfd, fdset->events, fdset->nfds, timeout);

	/* Check. */
	if (nfds < 0) {
		return -1;
	}

	/* Events array is ordered from 0 to nfds. */
	fdset->polled = nfds;
	return nfds;
}

int fdset_epoll_begin(fdset_t *fdset, fdset_it_t *it)
{
	if (fdset == NULL || it == NULL) {
		return -1;
	}

	/* Find first. */
	it->pos = 0;
	return fdset_next(fdset, it);
}

int fdset_epoll_end(fdset_t *fdset, fdset_it_t *it)
{
	if (fdset == NULL || it == NULL || fdset->nfds < 1) {
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
	it->events = 0;
	return -1;
}

int fdset_epoll_next(fdset_t *fdset, fdset_it_t *it)
{
	if (fdset == NULL || it == NULL || fdset->nfds < 1) {
		return -1;
	}

	/* Check boundaries. */
	if (it->pos >= fdset->polled || it->pos >= fdset->nfds) {
		return -1;
	}

	/* Select next. */
	size_t nid = it->pos++;
	it->fd = fdset->events[nid].data.fd;
	it->events = 0;
	return 0;
}

const char* fdset_epoll_method()
{
	return "epoll";
}

/* Package APIs. */
struct fdset_backend_t FDSET_EPOLL = {
	.fdset_new = fdset_epoll_new,
	.fdset_destroy = fdset_epoll_destroy,
	.fdset_add = fdset_epoll_add,
	.fdset_remove = fdset_epoll_remove,
	.fdset_wait = fdset_epoll_wait,
	.fdset_begin = fdset_epoll_begin,
	.fdset_end = fdset_epoll_end,
	.fdset_next = fdset_epoll_next,
	.fdset_method = fdset_epoll_method
};

#endif
