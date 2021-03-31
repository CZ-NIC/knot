/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/*!
 * \brief I/O multiplexing with context and timeouts for each fd.
 */

#pragma once

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>

#ifdef HAVE_EPOLL
#include <sys/epoll.h>
#elif HAVE_AIO
#include <poll.h>
#include <linux/aio_abi.h>
#include <sys/syscall.h>
#else
#include <poll.h>
#endif

#define FDSET_RESIZE_STEP	256
#ifdef HAVE_EPOLL
#define FDSET_REMOVE_FLAG	~0U
#elif HAVE_AIO
#define FDSET_REMOVE_FLAG   ~0UL
#endif

/*! \brief Set of filedescriptors with associated context and timeouts. */
typedef struct {
	unsigned n;                   /*!< Active fds. */
	unsigned size;                /*!< Array size (allocated). */
	void **ctx;                   /*!< Context for each fd. */
	time_t *timeout;              /*!< Timeout for each fd (seconds precision). */
#ifdef HAVE_EPOLL
	struct epoll_event *ev;       /*!< Epoll event storage for each fd. */
	struct epoll_event *recv_ev;  /*!< Array for polled events. */
	unsigned recv_size;           /*!< Size of array for polled events. */
	int efd;                      /*!< File descriptor of epoll. */
#elif HAVE_AIO
    struct iocb *ev;              /*!< AIO event storage for each fd */
	struct io_event *recv_ev;     /*!< Array for polled events. */
	unsigned recv_size;           /*!< Size of array for polled events. */
    aio_context_t aioctx;         /*!< File descriptor of aio. */
#else
	struct pollfd *pfd;           /*!< Poll state for each fd. */
#endif
} fdset_t;

/*! \brief State of iterator over received events */
typedef struct {
	fdset_t *fdset;           /*!< Source fdset_t. */
	unsigned idx;             /*!< Event index offset. */
	int unprocessed;          /*!< Unprocessed events left. */
#if defined(HAVE_EPOLL) || defined(HAVE_AIO)
#ifdef HAVE_EPOLL
	struct epoll_event *ptr;  /*!< Pointer on processed event. */
#else
    struct io_event *ptr;     /*!< Pointer on processed event. */
#endif
	unsigned dirty;           /*!< Number of fd to be removed on commit. */
#endif
} fdset_it_t;

typedef enum {
#ifdef HAVE_EPOLL
	FDSET_POLLIN  = EPOLLIN,
	FDSET_POLLOUT = EPOLLOUT,
#else /* UNIX and AIO */
	FDSET_POLLIN  = POLLIN,
	FDSET_POLLOUT = POLLOUT,
#endif
} fdset_event_t;

/*! \brief Mark-and-sweep state. */
typedef enum {
	FDSET_KEEP,
	FDSET_SWEEP
} fdset_sweep_state_t;

/*! \brief Sweep callback (set, index, data) */
typedef fdset_sweep_state_t (*fdset_sweep_cb_t)(fdset_t *, int, void *);

/*!
 * \brief Initialize fdset to given size.
 *
 * \param set Target set.
 * \param size Initial set size.
 *
 * \retval ret == 0 if successful.
 * \retval ret < 0 on error.
 */
int fdset_init(fdset_t *set, const unsigned size);

/*!
 * \brief Clear whole context of FDSET.
 *
 * \param set Target set.
 */
void fdset_clear(fdset_t *set);

/*!
 * \brief Add file descriptor to watched set.
 *
 * \param set Target set.
 * \param fd Added file descriptor.
 * \param events Mask of watched events.
 * \param ctx Context (optional).
 *
 * \retval ret >= 0 is index of the added fd.
 * \retval ret < 0 on errors.
 */
int fdset_add(fdset_t *set, const int fd, const fdset_event_t events, void *ctx);

/*!
 * \brief Remove and close file descriptor from watched set.
 *
 * \param set Target set.
 * \param i Index of the removed fd.
 *
 * \retval 0 if successful.
 * \retval ret < 0 on errors.
 */
int fdset_remove(fdset_t *set, const unsigned idx);

/*!
 * \brief Wait for receive events.
 *
 * Skip events based on offset and set iterator on first event.
 *
 * \param set Target set.
 * \param it Event iterator storage.
 * \param offset Index of first event.
 * \param timeout_ms Timeout of operation in milliseconds (use -1 for unlimited).
 *
 * \retval ret >= 0 represents number of events received.
 * \retval ret < 0 on error.
 */
int fdset_poll(fdset_t *set, fdset_it_t *it, const unsigned offset, const int timeout_ms);

/*!
 * \brief Set file descriptor watchdog interval.
 *
 * Set time (interval from now) after which the associated file descriptor
 * should be sweeped (see fdset_sweep). Good example is setting a grace period
 * of N seconds between socket activity. If socket is not active within
 * <now, now + interval>, it is sweeped and potentially closed.
 *
 * \param set Target set.
 * \param idx Index of the file descriptor.
 * \param interval Allowed interval without activity (seconds).
 *                 -1 disables watchdog timer
 *
 * \retval ret == 0 on success.
 * \retval ret < 0 on errors.
 */
int fdset_set_watchdog(fdset_t *set, const unsigned idx, const int interval);

/*!
 * \brief Sweep file descriptors with exceeding inactivity period.
 *
 * \param set Target set.
 * \param cb Callback for sweeped descriptors.
 * \param data Pointer to extra data.
 */
void fdset_sweep(fdset_t *set, const fdset_sweep_cb_t cb, void *data);

/*!
 * \brief Returns file descriptor based on index.
 *
 * \param set Target set.
 * \param idx Index of the file descriptor.
 *
 * \retval ret >= 0 for file descriptor.
 * \retval ret < 0 on errors.
 */
inline static int fdset_get_fd(const fdset_t *set, const unsigned idx)
{
	assert(set && idx < set->n);

#ifdef HAVE_EPOLL
	return set->ev[idx].data.fd;
#elif HAVE_AIO
    return set->ev[idx].aio_fildes;
#else
	return set->pfd[idx].fd;
#endif
}

/*!
 * \brief Returns number of file descriptors stored in set.
 *
 * \param set Target set.
 *
 * \retval Number of descriptors stored
 */
inline static unsigned fdset_get_length(const fdset_t *set)
{
	assert(set);

	return set->n;
}

/*!
 * \brief Get index of event in set referenced by iterator.
 *
 * \param it Target iterator.
 *
 * \retval Index of event.
 */
inline static unsigned fdset_it_get_idx(const fdset_it_t *it)
{
	assert(it);

#ifdef HAVE_EPOLL
	return it->ptr->data.u64;
#elif HAVE_AIO
    return it->ptr->data;
#else
	return it->idx;
#endif
}

/*!
 * \brief Get file descriptor of event referenced by iterator.
 *
 * \param it Target iterator.
 *
 * \retval ret >= 0 for file descriptor.
 * \retval ret < 0 on errors.
 */
inline static int fdset_it_get_fd(const fdset_it_t *it)
{
	assert(it);

#ifdef HAVE_EPOLL
	return it->fdset->ev[fdset_it_get_idx(it)].data.fd;
#elif HAVE_AIO
    return ((struct iocb *)it->ptr->obj)->aio_fildes;
#else
	return it->fdset->pfd[it->idx].fd;
#endif
}

/*!
 * \brief Move iterator on next received event.
 *
 * \param it Target iterator.
 */
inline static void fdset_it_next(fdset_it_t *it)
{
	assert(it);

#ifdef HAVE_EPOLL
	do {
		it->ptr++;
		it->unprocessed--;
	} while (it->unprocessed > 0 && fdset_it_get_idx(it) < it->idx);
#elif HAVE_AIO
    it->ptr++;
    it->unprocessed--;
#else
	if (--it->unprocessed > 0) {
		while (it->fdset->pfd[++it->idx].revents == 0); /* nop */
	}
#endif
}

/*!
 * \brief Remove file descriptor referenced by iterator from watched set.
 *
 * \param it Target iterator.
 *
 * \retval 0 if successful.
 * \retval ret < 0 on error.
 */
inline static void fdset_it_remove(fdset_it_t *it)
{
	assert(it);

#if defined(HAVE_EPOLL) || defined(HAVE_AIO)
	const int idx = fdset_it_get_idx(it);
	it->dirty++;
#ifdef HAVE_EPOLL
	it->fdset->ev[idx].events = FDSET_REMOVE_FLAG;
#else
	it->fdset->ev[idx].aio_buf = FDSET_REMOVE_FLAG;
#endif
#else
	(void)fdset_remove(it->fdset, fdset_it_get_idx(it));
	/* Iterator should return on last valid already processed element. */
	/* On `next` call (in for-loop) will point on first unprocessed. */
	it->idx--;
#endif
}

/*!
 * \brief Commit changes made in fdset using iterator.
 *
 * \param it Target iterator.
 */
inline static void fdset_it_commit(fdset_it_t *it)
{
#if defined(HAVE_EPOLL) || defined(HAVE_AIO)
	assert(it);
	/* NOTE: reverse iteration to avoid as much "remove last" operations
	 *       as possible. I'm not sure about performance improvement. It
	 *       will skip some syscalls at begin of iteration, but what
	 *       performance increase do we get is a question. It would be good
	 *       test it.
	 */
	fdset_t *set = it->fdset;
	for (int i = set->n - 1; it->dirty > 0 && i >= 0; --i) {
        if (
#ifdef HAVE_EPOLL
		    set->ev[i].events == FDSET_REMOVE_FLAG
#else
		    set->ev[i].aio_buf == FDSET_REMOVE_FLAG
#endif
        ) {
			(void)fdset_remove(set, i);
			it->dirty--;
		}
	}
	assert(it->dirty == 0);
#endif
}

/*!
 * \brief Decide if there is more received events.
 *
 * \param it Target iterator.
 *
 * \retval Logical flag represents 'done' state.
 */
inline static bool fdset_it_is_done(const fdset_it_t *it)
{
	assert(it);

	return it->unprocessed <= 0;
}

/*!
 * \brief Decide if event referenced by iterator is POLLIN event.
 *
 * \param it Target iterator.
 *
 * \retval Logical flag represents 'POLLIN' event received.
 */
inline static bool fdset_it_is_pollin(const fdset_it_t *it)
{
	assert(it);

#ifdef HAVE_EPOLL
	return it->ptr->events & EPOLLIN;
#elif HAVE_AIO
    return ((struct iocb *)it->ptr->obj)->aio_buf & POLLIN;
#else
	return it->fdset->pfd[it->idx].revents & POLLIN;
#endif
}

/*!
 * \brief Decide if event referenced by iterator is error event.
 *
 * \param it Target iterator.
 *
 * \retval Logical flag represents error event received.
 */
inline static bool fdset_it_is_error(const fdset_it_t *it)
{
	assert(it);

#ifdef HAVE_EPOLL
	return it->ptr->events & (EPOLLERR | EPOLLHUP);
#elif HAVE_AIO
    return ((struct iocb *)it->ptr->obj)->aio_buf & (POLLERR | POLLHUP | POLLNVAL);
#else
	return it->fdset->pfd[it->idx].revents & (POLLERR | POLLHUP | POLLNVAL);
#endif
}
