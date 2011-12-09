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

#ifdef HAVE_KQUEUE

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/event.h>
#include <sys/time.h>

#include "fdset_kqueue.h"

#define OS_FDS_CHUNKSIZE 8   /*!< Number of pollfd structs in a chunk. */
#define OS_FDS_KEEPCHUNKS 32 /*!< Will attempt to free memory when reached. */

struct fdset_t {
	int kq;
	struct kevent *events;
	struct kevent *revents;
	size_t nfds;
	size_t reserved;
	size_t polled;
};

fdset_t *fdset_kqueue_new()
{
	fdset_t *set = malloc(sizeof(fdset_t));
	if (!set) {
		return 0;
	}

	/* Blank memory. */
	memset(set, 0, sizeof(fdset_t));

	/* Create kqueue fd. */
	set->kq = kqueue();
	if (set->kq < 0) {
		free(set);
		set = 0;
	}

	return set;
}

int fdset_kqueue_destroy(fdset_t * fdset)
{
	if(!fdset) {
		return -1;
	}

	/* Teardown kqueue. */
	close(fdset->kq);

	/* OK if NULL. */
	free(fdset->revents);
	free(fdset->events);
	free(fdset);
	return 0;
}

int fdset_kqueue_realloc(void **old, size_t oldsize, size_t nsize)
{
	void *nmem = malloc(nsize);
	if (!nmem) {
		return -1;
	}

	/* Clear and copy old fdset data. */
	memset(nmem, 0, nsize);
	if (oldsize > 0) {
		memcpy(nmem, *old, oldsize);
		free(*old);
	}
	
	*old = nmem;
	return 0;
}

int fdset_kqueue_add(fdset_t *fdset, int fd, int events)
{
	if (!fdset || fd < 0 || events <= 0) {
		return -1;
	}

	/* Realloc needed. */
	if (fdset->nfds == fdset->reserved) {
		const size_t chunk = OS_FDS_CHUNKSIZE;
		const size_t nsize = (fdset->reserved + chunk) *
				     sizeof(struct kevent);
		const size_t oldsize = fdset->nfds * sizeof(struct kevent);
		
		if (fdset_kqueue_realloc(&fdset->events, oldsize, nsize) < 0) {
			return -1;
		}
		
		if (fdset_kqueue_realloc(&fdset->revents, oldsize, nsize) < 0) {
			return -1;
		}

	}

	/* Add to kqueue set. */
	int evfilt = EVFILT_READ; /*! \todo Map events. */
	EV_SET(&fdset->events[fdset->nfds], fd, evfilt,
	       EV_ADD|EV_ENABLE, 0, 0, 0);

	++fdset->nfds;
	return 0;
}

int fdset_kqueue_remove(fdset_t *fdset, int fd)
{
	if (!fdset || fd < 0) {
		return -1;
	}
	
	/* Find in set. */
	int pos = -1;
	for (int i = 0; i < fdset->nfds; ++i) {
		if (fdset->events[i].ident == fd) {
			pos = i;
			break;
		}
	}
	
	if (pos < 0) {
		return -1;
	}
	
	/* Remove filters. */
	EV_SET(&fdset->events[pos], fd, EVFILT_READ,
	       EV_DISABLE|EV_DELETE, 0, 0, 0);

	/* Attempt to remove from set. */
	size_t remaining = ((fdset->nfds - pos) - 1) * sizeof(struct kevent);
	memmove(fdset->events + pos, fdset->events + (pos + 1), remaining);
	
	/* Overwrite current item. */
	--fdset->nfds;

	/*! \todo Return memory if overallocated (nfds is far lower than reserved). */
	return 0;
}

int fdset_kqueue_wait(fdset_t *fdset)
{
	if (!fdset || fdset->nfds < 1 || !fdset->events) {
		return -1;
	}

	/* Poll new events. */
	fdset->polled = 0;
	int nfds = kevent(fdset->kq, fdset->events, fdset->nfds,
	                  fdset->revents, fdset->nfds, 0);

	/* Check. */
	if (nfds < 0) {
		return -1;
	}

	/* Events array is ordered from 0 to nfds. */
	fdset->polled = nfds;
	return nfds;
}

int fdset_kqueue_begin(fdset_t *fdset, fdset_it_t *it)
{
	if (!fdset || !it) {
		return -1;
	}

	/* Find first. */
	it->pos = 0;
	return fdset_next(fdset, it);
}

int fdset_kqueue_end(fdset_t *fdset, fdset_it_t *it)
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
	it->fd = fdset->revents[nid].ident;
	it->pos = nid;
	it->events = 0; /*! \todo Map events. */
	return -1;
}

int fdset_kqueue_next(fdset_t *fdset, fdset_it_t *it)
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
	it->fd = fdset->revents[nid].ident;
	it->events = 0; /*! \todo Map events. */
	return 0;
}

const char* fdset_kqueue_method()
{
	return "kqueue";
}

/* Package APIs. */
struct fdset_backend_t FDSET_KQUEUE = {
	.fdset_new = fdset_kqueue_new,
	.fdset_destroy = fdset_kqueue_destroy,
	.fdset_add = fdset_kqueue_add,
	.fdset_remove = fdset_kqueue_remove,
	.fdset_wait = fdset_kqueue_wait,
	.fdset_begin = fdset_kqueue_begin,
	.fdset_end = fdset_kqueue_end,
	.fdset_next = fdset_kqueue_next,
	.fdset_method = fdset_kqueue_method
};

#endif
