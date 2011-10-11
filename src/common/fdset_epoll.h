/*!
 * \file fdset_epoll.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \brief Wrapper for epoll I/O multiplexing.
 *
 * \addtogroup common_lib
 * @{
 */

#ifndef _KNOTD_FDSET_EPOLL_H_
#define _KNOTD_FDSET_EPOLL_H_

#include "fdset.h"

/*!
 * \brief Create new fdset.
 *
 * Linux epoll() backend.
 *
 * \retval Pointer to initialized FDSET structure if successful.
 * \retval NULL on error.
 */
fdset_t *fdset_epoll_new();

/*!
 * \brief Destroy FDSET.
 *
 * \retval 0 if successful.
 * \retval -1 on error.
 */
int fdset_epoll_destroy(fdset_t * fdset);

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
int fdset_epoll_add(fdset_t *fdset, int fd, int events);

/*!
 * \brief Remove file descriptor from watched set.
 *
 * \param fdset Target set.
 * \param fd File descriptor to be removed.
 *
 * \retval 0 if successful.
 * \retval -1 on errors.
 */
int fdset_epoll_remove(fdset_t *fdset, int fd);

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
int fdset_epoll_wait(fdset_t *fdset);

/*!
 * \brief Set event iterator to the beginning of last polled events.
 *
 * \param fdset Target set.
 * \param it Event iterator.
 *
 * \retval 0 if successful.
 * \retval -1 on errors.
 */
int fdset_epoll_begin(fdset_t *fdset, fdset_it_t *it);

/*!
 * \brief Set event iterator to the end of last polled events.
 *
 * \param fdset Target set.
 * \param it Event iterator.
 *
 * \retval 0 if successful.
 * \retval -1 on errors.
 */
int fdset_epoll_end(fdset_t *fdset, fdset_it_t *it);

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
int fdset_epoll_next(fdset_t *fdset, fdset_it_t *it);

/*!
 * \brief Returned name of epoll method.
 *
 * \retval Name if successful.
 * \retval NULL if no method was loaded (shouldn't happen).
 */
const char* fdset_epoll_method();

/*! \brief Exported API. */
extern struct fdset_backend_t FDSET_EPOLL;

#endif /* _KNOTD_FDSET_EPOLL_H_ */

/*! @} */
