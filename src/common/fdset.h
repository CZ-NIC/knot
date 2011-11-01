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
 * \file fdset.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \brief Wrapper for native I/O multiplexing.
 *
 * Selects best implementation according to config.
 * - select()
 * - poll() \todo
 * - epoll()
 * - kqueue()
 *
 * \addtogroup common_lib
 * @{
 */

#ifndef _KNOTD_FDSET_H_
#define _KNOTD_FDSET_H_

#include <stddef.h>

/*! \brief Opaque pointer to implementation-specific fdset data. */
typedef struct fdset_t fdset_t;

/*! \brief Unified event types. */
enum fdset_event_t {
	OS_EV_READ  = 1 << 0, /*!< Readable event. */
	OS_EV_WRITE = 1 << 1, /*!< Writeable event. */
	OS_EV_ERROR = 1 << 2  /*!< Error event. */
};

/*! \brief File descriptor set iterator. */
typedef struct fdset_it_t {
	int fd;     /*!< Current file descriptor. */
	int events; /*!< Returned events. */
	size_t pos; /* Internal usage. */
} fdset_it_t;

/*!
 * \brief File descriptor set implementation backend.
 * \notice Functions documentation following.
 * \internal
 */
struct fdset_backend_t
{
	fdset_t* (*fdset_new)();
	int (*fdset_destroy)(fdset_t*);
	int (*fdset_add)(fdset_t*, int, int);
	int (*fdset_remove)(fdset_t*, int);
	int (*fdset_wait)(fdset_t*);
	int (*fdset_begin)(fdset_t*, fdset_it_t*);
	int (*fdset_end)(fdset_t*, fdset_it_t*);
	int (*fdset_next)(fdset_t*, fdset_it_t*);
	const char* (*fdset_method)();
};

/*!
 * \brief Selected backend.
 * \internal
 */
extern struct fdset_backend_t _fdset_backend;

/*!
 * \brief Create new fdset.
 *
 * FDSET implementation depends on system.
 *
 * \retval Pointer to initialized FDSET structure if successful.
 * \retval NULL on error.
 */
static inline fdset_t *fdset_new() {
	return _fdset_backend.fdset_new();
}

/*!
 * \brief Destroy FDSET.
 *
 * \retval 0 if successful.
 * \retval -1 on error.
 */
static inline int fdset_destroy(fdset_t * fdset) {
	return _fdset_backend.fdset_destroy(fdset);
}

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
static inline int fdset_add(fdset_t *fdset, int fd, int events) {
	return _fdset_backend.fdset_add(fdset, fd, events);
}


/*!
 * \brief Remove file descriptor from watched set.
 *
 * \param fdset Target set.
 * \param fd File descriptor to be removed.
 *
 * \retval 0 if successful.
 * \retval -1 on errors.
 */
static inline int fdset_remove(fdset_t *fdset, int fd) {
	return _fdset_backend.fdset_remove(fdset, fd);
}

/*!
 * \brief Poll set for new events.
 *
 * \param fdset Target set.
 *
 * \retval Number of events if successful.
 * \retval -1 on errors.
 *
 * \todo Timeout.
 */
static inline int fdset_wait(fdset_t *fdset) {
	return _fdset_backend.fdset_wait(fdset);
}

/*!
 * \brief Set event iterator to the beginning of last polled events.
 *
 * \param fdset Target set.
 * \param it Event iterator.
 *
 * \retval 0 if successful.
 * \retval -1 on errors.
 */
static inline int fdset_begin(fdset_t *fdset, fdset_it_t *it) {
	return _fdset_backend.fdset_begin(fdset, it);
}

/*!
 * \brief Set event iterator to the end of last polled events.
 *
 * \param fdset Target set.
 * \param it Event iterator.
 *
 * \retval 0 if successful.
 * \retval -1 on errors.
 */
static inline int fdset_end(fdset_t *fdset, fdset_it_t *it) {
	return _fdset_backend.fdset_end(fdset, it);
}

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
static inline int fdset_next(fdset_t *fdset, fdset_it_t *it) {
	return _fdset_backend.fdset_next(fdset, it);
}

/*!
 * \brief Returned name of underlying poll method.
 *
 * \retval Name if successful.
 * \retval NULL if no method was loaded (shouldn't happen).
 */
static inline const char* fdset_method() {
	return _fdset_backend.fdset_method();
}

#endif /* _KNOTD_FDSET_H_ */

/*! @} */
