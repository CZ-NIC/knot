/*!
 * \file os_fdset.h
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

#ifndef _KNOTD_OS_FDSET_H_
#define _KNOTD_OS_FDSET_H_

#include <stddef.h>

/*! \brief Opaque pointer to implementation-specific fdset data. */
struct os_fdset_t;

/*! \brief Single event descriptor. */
typedef struct os_fd_t {
    int fd;
    int events;
    size_t pos;
} os_fd_t;

/*! \brief Unified event types. */
enum os_ev_t {
    OS_EV_READ  = 1 << 0,
    OS_EV_WRITE = 1 << 1,
    OS_EV_ERROR = 1 << 2
};

/*!
 * \brief Create new fdset.
 *
 * FDSET implementation depends on system.
 *
 * \retval Pointer to initialized FDSET structure if successful.
 * \retval NULL on error.
 */
struct os_fdset_t *os_fdset_new();

/*!
 * \brief Destroy FDSET.
 *
 * \retval 0 if successful.
 * \retval -1 on error.
 */
int os_fdset_destroy(struct os_fdset_t * fdset);

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
int os_fdset_add(struct os_fdset_t *fdset, int fd, int events);

/*!
 * \brief Remove file descriptor from watched set.
 *
 * \param fdset Target set.
 * \param fd File descriptor to be removed.
 *
 * \retval 0 if successful.
 * \retval -1 on errors.
 */
int os_fdset_remove(struct os_fdset_t *fdset, int fd);

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
int os_fdset_poll(struct os_fdset_t *fdset);

/*!
 * \brief Set event iterator to the beginning of last polled events.
 *
 * \param fdset Target set.
 * \param it Event iterator.
 *
 * \retval 0 if successful.
 * \retval -1 on errors.
 */
int os_fdset_begin(struct os_fdset_t *fdset, os_fd_t *it);

/*!
 * \brief Set event iterator to the end of last polled events.
 *
 * \param fdset Target set.
 * \param it Event iterator.
 *
 * \retval 0 if successful.
 * \retval -1 on errors.
 */
int os_fdset_end(struct os_fdset_t *fdset, os_fd_t *it);

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
int os_fdset_next(struct os_fdset_t *fdset, os_fd_t *it);


/*!
 * \brief Returned name of underlying poll method.
 *
 * \retval Name if successful.
 * \retval NULL if no method was loaded (shouldn't happen).
 */
const char* os_fdset_method();

#endif /* _KNOTD_OS_FDSET_H_ */

/*! @} */
