#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <stddef.h>

#include "os_fdset.h"

#define OS_FDS_CHUNKSIZE 8   /*!< Number of pollfd structs in a chunk. */
#define OS_FDS_KEEPCHUNKS 32 /*!< Will attempt to free memory when reached. */

struct os_fdset_t {
	struct pollfd *fds;
	nfds_t nfds;
	size_t reserved;
	size_t polled;
	size_t begin;
};

struct os_fdset_t *os_fdset_new()
{
	struct os_fdset_t *set = malloc(sizeof(struct os_fdset_t));
	if (!set) {
		return 0;
	}

	/* Blank memory. */
	memset(set, 0, sizeof(struct os_fdset_t));
	return set;
}

int os_fdset_destroy(struct os_fdset_t * fdset)
{
	if(!fdset) {
		return -1;
	}

	/*! \todo No teardown required I guess. */

	/* OK if NULL. */
	free(fdset->fds);
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
		const size_t nsize = sizeof(struct pollfd) * (fdset->reserved + chunk);
		struct pollfd *fds_n = malloc(nsize);
		if (!fds_n) {
			return -1;
		}

		/* Clear and copy old fdset data. */
		memset(fds_n, 0, nsize);
		memcpy(fds_n, fdset->fds, fdset->nfds * sizeof(struct pollfd));
		free(fdset->fds);
		fdset->fds = fds_n;
		fdset->reserved += chunk;
	}

	/* Append. */
	int nid = fdset->nfds++;
	fdset->fds[nid].fd = fd;
	fdset->fds[nid].events = POLLIN; /*! \todo Map events to POLL events. */
	return 0;
}

int os_fdset_remove(struct os_fdset_t *fdset, int fd)
{
	if (!fdset || fd < 0) {
		return -1;
	}

	/* Find file descriptor. */
	unsigned found = 0;
	size_t pos = 0;
	for (size_t i = 0; i < fdset->nfds; ++i) {
		if (fdset->fds[i].fd == fd) {
			found = 1;
			pos = i;
			break;
		}
	}

	/* Check. */
	if (!found) {
		return -1;
	}

	/* Overwrite current item. */
	size_t remaining = ((fdset->nfds - pos) - 1) * sizeof(struct pollfd);
	memmove(fdset->fds + pos, fdset->fds + (pos + 1), remaining);
	--fdset->nfds;

	/*! \todo Return memory if overallocated (nfds is far lower than reserved). */
	/*! \todo Maybe >64 free chunks is excess? */
	return 0;
}

int os_fdset_poll(struct os_fdset_t *fdset)
{
	if (!fdset || fdset->nfds < 1 || !fdset->fds) {
		return -1;
	}

	/* Initialize pointers. */
	fdset->polled = 0;
	fdset->begin = 0;

	/* Poll for events. */
	int ret = poll(fdset->fds, fdset->nfds, -1);
	if (ret < 0) {
		return -1;
	}

	/* Set pointers for iterating. */
	fdset->polled = ret;
	fdset->begin = 0;
	return ret;
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

	/* Trace last matching item from the end. */
	struct pollfd* pfd = fdset->fds + fdset->nfds - 1;
	while (pfd != fdset->fds) {
		if (pfd->events & pfd->revents) {
			it->fd = pfd->fd;
			it->pos = pfd - fdset->fds;
			return 0;
		}
	}

	/* No end found, ends on the beginning. */
	it->fd = -1;
	it->pos = 0;
	return -1;
}

int os_fdset_next(struct os_fdset_t *fdset, os_fdset_it *it)
{
	if (!fdset || !it || fdset->nfds < 1) {
		return -1;
	}

	/* Find next with matching flags. */
	for (; it->pos < fdset->nfds; ++it->pos) {
		struct pollfd* pfd = fdset->fds + it->pos;
		if (pfd->events & pfd->revents) {
			it->fd = pfd->fd;
			it->events = pfd->revents; /*! \todo MAP events. */
			++it->pos; /* Next will start after current. */
			return 0;
		}
	}

	/* No matching event found. */
	it->fd = -1;
	it->pos = 0;
	return -1;
}

const char* os_fdset_method()
{
	return "poll";
}
