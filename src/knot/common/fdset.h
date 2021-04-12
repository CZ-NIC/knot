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
#elif HAVE_KQUEUE
#include <sys/event.h>
#else
#include <poll.h>
#endif

#include "libknot/errcode.h"

#define FDSET_RESIZE_STEP	256
#ifdef HAVE_EPOLL
#define FDSET_REMOVE_FLAG	~0U
#endif

/*! \brief Set of file descriptors with associated context and timeouts. */
typedef struct {
	unsigned n;                   /*!< Active fds. */
	unsigned size;                /*!< Array size (allocated). */
	void **ctx;                   /*!< Context for each fd. */
	time_t *timeout;              /*!< Timeout for each fd (seconds precision). */
#if defined(HAVE_EPOLL) || defined(HAVE_KQUEUE)
#ifdef HAVE_EPOLL
	struct epoll_event *ev;       /*!< Epoll event storage for each fd. */
	struct epoll_event *recv_ev;  /*!< Array for polled events. */
#elif HAVE_KQUEUE
	struct kevent *ev;            /*!< Kqueue event storage for each fd. */
	struct kevent *recv_ev;       /*!< Array for polled events. */
#endif
	unsigned recv_size;           /*!< Size of array for polled events. */
	int pfd;                      /*!< File descriptor of kernel polling structure (epoll or kqueue). */
#else
	struct pollfd *pfd;           /*!< Poll state for each fd. */
#endif
} fdset_t;

/*! \brief State of iterator over received events */
typedef struct {
	fdset_t *set;             /*!< Source fdset_t. */
	unsigned idx;             /*!< Event index offset. */
	int unprocessed;          /*!< Unprocessed events left. */
#if defined(HAVE_EPOLL) || defined(HAVE_KQUEUE)
#ifdef HAVE_EPOLL
	struct epoll_event *ptr;  /*!< Pointer on processed event. */
#elif HAVE_KQUEUE
	struct kevent *ptr;       /*!< Pointer on processed event. */
#endif
	unsigned dirty;           /*!< Number of fd to be removed on commit. */
#endif
} fdset_it_t;

typedef enum {
#ifdef HAVE_EPOLL
	FDSET_POLLIN  = EPOLLIN,
	FDSET_POLLOUT = EPOLLOUT,
#elif HAVE_KQUEUE
	FDSET_POLLIN  = EVFILT_READ,
	FDSET_POLLOUT = EVFILT_WRITE,
#else
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
 * \param set   Target set.
 * \param size  Initial set size.
 *
 * \return Error code, KNOT_EOK if success.
 */
int fdset_init(fdset_t *set, const unsigned size);

/*!
 * \brief Clear whole context of the fdset.
 *
 * \param set  Target set.
 */
void fdset_clear(fdset_t *set);

/*!
 * \brief Add file descriptor to watched set.
 *
 * \param set     Target set.
 * \param fd      Added file descriptor.
 * \param events  Mask of watched events.
 * \param ctx     Context (optional).
 *
 * \retval ret >= 0 is index of the added fd.
 * \retval ret < 0 on error.
 */
int fdset_add(fdset_t *set, const int fd, const fdset_event_t events, void *ctx);

/*!
 * \brief Remove and close file descriptor from watched set.
 *
 * \param set  Target set.
 * \param idx  Index of the removed fd.
 *
 * \return Error code, KNOT_EOK if success.
 */
int fdset_remove(fdset_t *set, const unsigned idx);

/*!
 * \brief Wait for receive events.
 *
 * Skip events based on offset and set iterator on first event.
 *
 * \param set         Target set.
 * \param it          Event iterator storage.
 * \param offset      Index of first event.
 * \param timeout_ms  Timeout of operation in milliseconds (use -1 for unlimited).
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
 * <now, now + interval>, it is sweeped and closed.
 *
 * \param set       Target set.
 * \param idx       Index of the file descriptor.
 * \param interval  Allowed interval without activity (seconds).
 *                  -1 disables watchdog timer.
 *
 * \return Error code, KNOT_EOK if success.
 */
int fdset_set_watchdog(fdset_t *set, const unsigned idx, const int interval);

/*!
 * \brief Sweep file descriptors with exceeding inactivity period.
 *
 * \param set   Target set.
 * \param cb    Callback for sweeped descriptors.
 * \param data  Pointer to extra data.
 */
void fdset_sweep(fdset_t *set, const fdset_sweep_cb_t cb, void *data);

/*!
 * \brief Returns file descriptor based on index.
 *
 * \param set  Target set.
 * \param idx  Index of the file descriptor.
 *
 * \retval ret >= 0 for file descriptor.
 * \retval ret < 0 on errors.
 */
inline static int fdset_get_fd(const fdset_t *set, const unsigned idx)
{
	assert(set && idx < set->n);

#ifdef HAVE_EPOLL
	return set->ev[idx].data.fd;
#elif HAVE_KQUEUE
	return set->ev[idx].ident;
#else
	return set->pfd[idx].fd;
#endif
}

/*!
 * \brief Returns number of file descriptors stored in set.
 *
 * \param set  Target set.
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
 * \param it  Target iterator.
 *
 * \retval Index of event.
 */
inline static unsigned fdset_it_get_idx(const fdset_it_t *it)
{
	assert(it);

#ifdef HAVE_EPOLL
	return it->ptr->data.u64;
#elif HAVE_KQUEUE
	return (unsigned)(intptr_t)it->ptr->udata;
#else
	return it->idx;
#endif
}

/*!
 * \brief Get file descriptor of event referenced by iterator.
 *
 * \param it  Target iterator.
 *
 * \retval ret >= 0 for file descriptor.
 * \retval ret < 0 on errors.
 */
inline static int fdset_it_get_fd(const fdset_it_t *it)
{
	assert(it);

#ifdef HAVE_EPOLL
	return it->set->ev[fdset_it_get_idx(it)].data.fd;
#elif HAVE_KQUEUE
	return it->ptr->ident;
#else
	return it->set->pfd[it->idx].fd;
#endif
}

/*!
 * \brief Move iterator on next received event.
 *
 * \param it  Target iterator.
 */
inline static void fdset_it_next(fdset_it_t *it)
{
	assert(it);

#if defined(HAVE_EPOLL) || defined(HAVE_KQUEUE)
	do {
		it->ptr++;
		it->unprocessed--;
	} while (it->unprocessed > 0 && fdset_it_get_idx(it) < it->idx);
#else
	if (--it->unprocessed > 0) {
		while (it->set->pfd[++it->idx].revents == 0); /* nop */
	}
#endif
}

/*!
 * \brief Remove file descriptor referenced by iterator from watched set.
 *
 * \param it  Target iterator.
 *
 * \return Error code, KNOT_EOK if success.
 */
inline static void fdset_it_remove(fdset_it_t *it)
{
	assert(it);

#ifdef HAVE_EPOLL
	const int idx = fdset_it_get_idx(it);
	it->set->ev[idx].events = FDSET_REMOVE_FLAG;
	it->dirty++;
#elif HAVE_KQUEUE
	const int idx = fdset_it_get_idx(it);
	/* Bitwise negated filter marks event for delete.  */
	/* Filters become:                                 */
	/*   [FreeBSD]                                     */
	/*       EVFILT_READ  (-1) -> 0                    */
	/*       EVFILT_WRITE (-2) -> 1                    */
	/*   [NetBSD]                                      */
	/*       EVFILT_READ  (0) -> -1                    */
	/*       EVFILT_WRITE (1) -> -2                    */
	/* If not marked for delete then mark for delete.  */
#if defined(__NetBSD__)
	if ((signed short)it->set->ev[idx].filter >= 0) 
#else
	if (it->set->ev[idx].filter < 0) 
#endif
	{
		it->set->ev[idx].filter = ~it->set->ev[idx].filter;
	}
	it->dirty++;
#else
	(void)fdset_remove(it->set, fdset_it_get_idx(it));
	/* Iterator should return on last valid already processed element. */
	/* On `next` call (in for-loop) will point on first unprocessed. */
	it->idx--;
#endif
}

/*!
 * \brief Commit changes made in fdset using iterator.
 *
 * \param it  Target iterator.
 */
void fdset_it_commit(fdset_it_t *it);

/*!
 * \brief Decide if there is more received events.
 *
 * \param it  Target iterator.
 *
 * \retval Logical flag representing 'done' state.
 */
inline static bool fdset_it_is_done(const fdset_it_t *it)
{
	assert(it);

	return it->unprocessed <= 0;
}

/*!
 * \brief Decide if event referenced by iterator is POLLIN event.
 *
 * \param it  Target iterator.
 *
 * \retval Logical flag represents 'POLLIN' event received.
 */
inline static bool fdset_it_is_pollin(const fdset_it_t *it)
{
	assert(it);

#ifdef HAVE_EPOLL
	return it->ptr->events & EPOLLIN;
#elif HAVE_KQUEUE
	return it->ptr->filter == EVFILT_READ;
#else
	return it->set->pfd[it->idx].revents & POLLIN;
#endif
}

/*!
 * \brief Decide if event referenced by iterator is error event.
 *
 * \param it  Target iterator.
 *
 * \retval Logical flag represents error event received.
 */
inline static bool fdset_it_is_error(const fdset_it_t *it)
{
	assert(it);

#ifdef HAVE_EPOLL
	return it->ptr->events & (EPOLLERR | EPOLLHUP);
#elif HAVE_KQUEUE
	return it->ptr->flags & EV_ERROR;
#else
	return it->set->pfd[it->idx].revents & (POLLERR | POLLHUP | POLLNVAL);
#endif
}
