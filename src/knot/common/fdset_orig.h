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

#include <stddef.h>
#include <poll.h>
#include <sys/time.h>
#include <signal.h>

#define FDSET0_INIT_SIZE 256 /* Resize step. */

/*! \brief Set of filedescriptors with associated context and timeouts. */
typedef struct fdset0 {
	unsigned n;          /*!< Active fds. */
	unsigned size;       /*!< Array size (allocated). */
	void* *ctx;          /*!< Context for each fd. */
	struct pollfd *pfd;  /*!< poll state for each fd */
	time_t *timeout;     /*!< Timeout for each fd (seconds precision). */
} fdset0_t;

/*! \brief Mark-and-sweep state. */
enum fdset0_sweep_state {
	FDSET0_KEEP,
	FDSET0_SWEEP
};

/*! \brief Sweep callback (set, index, data) */
typedef enum fdset0_sweep_state (*fdset0_sweep_cb_t)(fdset0_t*, int, void*);

/*!
 * \brief Initialize fdset0 to given size.
 */
int fdset0_init(fdset0_t *set, unsigned size);

/*!
 * \brief Destroy FDSET0.
 *
 * \retval 0 if successful.
 * \retval -1 on error.
 */
int fdset0_clear(fdset0_t* set);

/*!
 * \brief Add file descriptor to watched set.
 *
 * \param set Target set.
 * \param fd Added file descriptor.
 * \param events Mask of watched events.
 * \param ctx Context (optional).
 *
 * \retval index of the added fd if successful.
 * \retval -1 on errors.
 */
int fdset0_add(fdset0_t *set, int fd, unsigned events, void *ctx);

/*!
 * \brief Remove file descriptor from watched set.
 *
 * \param set Target set.
 * \param i Index of the removed fd.
 *
 * \retval 0 if successful.
 * \retval -1 on errors.
 */
int fdset0_remove(fdset0_t *set, unsigned i);

/*!
 * \brief Set file descriptor watchdog interval.
 *
 * Set time (interval from now) after which the associated file descriptor
 * should be sweeped (see fdset0_sweep). Good example is setting a grace period
 * of N seconds between socket activity. If socket is not active within
 * <now, now + interval>, it is sweeped and potentially closed.
 *
 * \param set Target set.
 * \param i Index for the file descriptor.
 * \param interval Allowed interval without activity (seconds).
 *                 -1 disables watchdog timer
 *
 * \retval 0 if successful.
 * \retval -1 on errors.
 */
int fdset0_set_watchdog(fdset0_t* set, int i, int interval);

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
int fdset0_sweep(fdset0_t* set, fdset0_sweep_cb_t cb, void *data);
