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
 * \brief Create new fdset.
 *
 * FDSET implementation depends on system.
 *
 * \retval Pointer to initialized FDSET structure if successful.
 * \retval NULL on error.
 */
fdset_t *fdset_new();

/*!
 * \brief Destroy FDSET.
 *
 * \retval 0 if successful.
 * \retval -1 on error.
 */
int fdset_destroy(fdset_t * fdset);

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
int fdset_add(fdset_t *fdset, int fd, int events);

/*!
 * \brief Remove file descriptor from watched set.
 *
 * \param fdset Target set.
 * \param fd File descriptor to be removed.
 *
 * \retval 0 if successful.
 * \retval -1 on errors.
 */
int fdset_remove(fdset_t *fdset, int fd);

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
int fdset_wait(fdset_t *fdset);

/*!
 * \brief Set event iterator to the beginning of last polled events.
 *
 * \param fdset Target set.
 * \param it Event iterator.
 *
 * \retval 0 if successful.
 * \retval -1 on errors.
 */
int fdset_begin(fdset_t *fdset, fdset_it_t *it);

/*!
 * \brief Set event iterator to the end of last polled events.
 *
 * \param fdset Target set.
 * \param it Event iterator.
 *
 * \retval 0 if successful.
 * \retval -1 on errors.
 */
int fdset_end(fdset_t *fdset, fdset_it_t *it);

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
int fdset_next(fdset_t *fdset, fdset_it_t *it);

/*!
 * \brief Returned name of underlying poll method.
 *
 * \retval Name if successful.
 * \retval NULL if no method was loaded (shouldn't happen).
 */
const char* fdset_method();

#endif /* _KNOTD_FDSET_H_ */

/*! @} */
