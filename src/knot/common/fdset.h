/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#ifdef ENABLE_POLL

#include <stddef.h>
#include <poll.h>
#include <sys/time.h>
#include <signal.h>

#define FDSET_INIT_SIZE 256 /* Resize step. */

/*! \brief Set of filedescriptors with associated context and timeouts. */
typedef struct fdset {
	unsigned n;          /*!< Active fds. */
	unsigned size;       /*!< Array size (allocated). */
	void* *ctx;          /*!< Context for each fd. */
	struct pollfd *pfd;  /*!< poll state for each fd */
	time_t *timeout;     /*!< Timeout for each fd (seconds precision). */
} fdset_t;

/*! \brief State of iterator over received events */
typedef struct fdset_it {
	fdset_t *ctx;     /*!< Source fdset_t. */
	unsigned idx;     /*!< Index of processed event. */
	int unprocessed;  /*!< Unprocessed events left. */
} fdset_it_t;

/*! \brief Mark-and-sweep state. */
typedef enum fdset_sweep_state {
	FDSET_KEEP,
	FDSET_SWEEP
} fdset_sweep_state_t;

/*! \brief Sweep callback (set, index, data) */
typedef enum fdset_sweep_state (*fdset_sweep_cb_t)(fdset_t*, int, void*);

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
 *
 * \retval ret == 0 if successful.
 * \retval ret < 0 on error.
 */
int fdset_clear(fdset_t* set);

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
int fdset_add(fdset_t *set, const int fd, const unsigned events, void *ctx);

/*!
 * \brief Remove file descriptor from watched set.
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
 * \param timeout Timeout of operation (negative number for unlimited).
 *
 * \retval ret >= 0 represents number of events received.
 * \retval ret < 0 on error.
 */
int fdset_poll(fdset_t *set, fdset_it_t *it, const unsigned offset, const int timeout);

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
 * \brief Returns file descriptor based on index.
 *
 * \param set Target set.
 * \param idx Index of the file descriptor.
 *
 * \retval ret >= 0 for file descriptor.
 * \retval ret < 0 on errors.
 */
int fdset_get_fd(const fdset_t *set, const unsigned idx);

/*!
 * \brief Returns number of file descriptors stored in set.
 *
 * \param set Target set.
 *
 * \retval Number of descriptors stored
 */
unsigned fdset_get_length(const fdset_t *set);

/*!
 * \brief Sweep file descriptors with exceeding inactivity period.
 *
 * \param set Target set.
 * \param cb Callback for sweeped descriptors.
 * \param data Pointer to extra data.
 *
 * \retval number of sweeped descriptors.
 * \retval -1 on errors.
 */
int fdset_sweep(fdset_t* set, const fdset_sweep_cb_t cb, void *data);

/*!
 * \brief Move iterator on next received event.
 *
 * \param it Target iterator.
 */
void fdset_it_next(fdset_it_t *it);

/*!
 * \brief Decide if there is more received events.
 *
 * \param it Target iterator.
 *
 * \retval Logical flag represents 'done' state.
 */
int fdset_it_done(const fdset_it_t *it);

/*!
 * \brief Remove file descriptor referenced by iterator from watched set.
 *
 * \param it Target iterator.
 *
 * \retval 0 if successful.
 * \retval ret < 0 on error.
 */
int fdset_it_remove(fdset_it_t *it);

/*!
 * \brief Get file descriptor of event referenced by iterator.
 *
 * \param it Target iterator.
 *
 * \retval ret >= 0 for file descriptor.
 * \retval ret < 0 on errors.
 */
int fdset_it_get_fd(const fdset_it_t *it);

/*!
 * \brief Get index of event in set referenced by iterator.
 *
 * \param it Target iterator.
 *
 * \retval Index of event.
 */
unsigned fdset_it_get_idx(const fdset_it_t *it);

/*!
 * \brief Decide if event referenced by iterator is POLLIN event.
 *
 * \param it Target iterator.
 *
 * \retval Logical flag represents 'POLLIN' event received.
 */
int fdset_it_ev_is_pollin(const fdset_it_t *it);

/*!
 * \brief Decide if event referenced by iterator is error event.
 *
 * \param it Target iterator.
 *
 * \retval Logical flag represents error event received.
 */
int fdset_it_ev_is_err(const fdset_it_t *it);

#endif