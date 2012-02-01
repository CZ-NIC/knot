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
/*!
 * \file fdset_kqueue.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \brief Wrapper for kqueue I/O multiplexing.
 *
 * \addtogroup common_lib
 * @{
 */

#ifndef _KNOTD_FDSET_KQUEUE_H_
#define _KNOTD_FDSET_KQUEUE_H_

#include "fdset.h"

/*!
 * \brief Create new fdset.
 *
 * BSD kqueue() backend.
 *
 * \retval Pointer to initialized FDSET structure if successful.
 * \retval NULL on error.
 */
fdset_t *fdset_kqueue_new();

/*!
 * \brief Destroy FDSET.
 *
 * \retval 0 if successful.
 * \retval -1 on error.
 */
int fdset_kqueue_destroy(fdset_t * fdset);

/*!
 * \brief Add file descriptor to watched set.
 *
 * \param fdset Target set.
 * \param fd Added file descriptor.
 * \param events Mask of watched events.
 *
 * \retval 0 if successful.
 * \retval -1 on errors.
 */
int fdset_kqueue_add(fdset_t *fdset, int fd, int events);

/*!
 * \brief Remove file descriptor from watched set.
 *
 * \param fdset Target set.
 * \param fd File descriptor to be removed.
 *
 * \retval 0 if successful.
 * \retval -1 on errors.
 */
int fdset_kqueue_remove(fdset_t *fdset, int fd);

/*!
 * \brief Poll set for new events.
 *
 * \param fdset Target set.
 * \param timeout Timeout (OS_EV_FOREVER, OS_EV_NOWAIT or value in miliseconds).
 *
 * \retval Number of events if successful.
 * \retval -1 on errors.
 */
int fdset_kqueue_wait(fdset_t *fdset, int timeout);

/*!
 * \brief Set event iterator to the beginning of last polled events.
 *
 * \param fdset Target set.
 * \param it Event iterator.
 *
 * \retval 0 if successful.
 * \retval -1 on errors.
 */
int fdset_kqueue_begin(fdset_t *fdset, fdset_it_t *it);

/*!
 * \brief Set event iterator to the end of last polled events.
 *
 * \param fdset Target set.
 * \param it Event iterator.
 *
 * \retval 0 if successful.
 * \retval -1 on errors.
 */
int fdset_kqueue_end(fdset_t *fdset, fdset_it_t *it);

/*!
 * \brief Set event iterator to the next event.
 *
 * Event iterator fd will be set to -1 if next event doesn't exist.
 *
 * \param fdset Target set.
 * \param it Event iterator.
 *
 * \retval 0 if successful.
 * \retval -1 on errors.
 */
int fdset_kqueue_next(fdset_t *fdset, fdset_it_t *it);

/*!
 * \brief Returned name of kqueue method.
 *
 * \retval Name if successful.
 * \retval NULL if no method was loaded (shouldn't happen).
 */
const char* fdset_kqueue_method();

/*! \brief Exported API. */
extern struct fdset_backend_t FDSET_KQUEUE;

#endif /* _KNOTD_FDSET_KQUEUE_H_ */

/*! @} */
