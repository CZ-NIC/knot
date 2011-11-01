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
 * \file evqueue.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \brief Event queue.
 *
 * \addtogroup common_lib
 * @{
 */

#ifndef _KNOTD_COMMON_EVQUEUE_H_
#define _KNOTD_COMMON_EVQUEUE_H_

#include <pthread.h>
#include <signal.h> // sigset_t
#include <time.h>
#include <sys/time.h>

//#include "knot/common.h"
#include "common/lists.h"

struct event_t;

/*!
 * \brief Event callback.
 *
 * Pointer to whole event structure is passed to the callback.
 * Callback should return 0 on success and negative integer on error.
 *
 * Example callback:
 * \code
 * int print_callback(event_t *t) {
 *    return printf("Callback: %s\n", t->data);
 * }
 * \endcode
 */
typedef int (*event_cb_t)(struct event_t *);

/*!
 * \brief Event structure.
 */
typedef struct event_t {
	node n;            /*!< Node for event queue. */
	int type;          /*!< Event type. */
	struct timeval tv; /*!< Event scheduled time. */
	void *data;        /*!< Usable data ptr. */
	event_cb_t cb;     /*!< Event callback. */
	void *parent;      /*!< Pointer to parent (evqueue, scheduler...) */
} event_t;

/*!
 * \brief Event queue constants.
 */
enum {
	EVQUEUE_READFD  = 0,
	EVQUEUE_WRITEFD = 1
};

/*!
 * \brief Event queue structure.
 */
typedef struct {
	int fds[2]; /*!< Read and Write fds. */
} evqueue_t;

/*!
 * \brief Create new event queue.
 *
 * Event queue is thread-safe and POSIX signal-safe.
 * It uses piped fds for queueing and pselect(2) to
 * wait for events.
 *
 * \retval New instance on success.
 * \retval NULL on error.
 */
evqueue_t *evqueue_new();

/*!
 * \brief Deinitialize and free event queue.
 *
 * \param q Pointer to queue instance.
 * \note *q is set to 0.
 */
void evqueue_free(evqueue_t **q);

/*!
 * \brief Poll for new events.
 *
 * Unblocked signals during polling are specified
 * in a sigmask.
 *
 * \param q Event queue.
 * \param ts Timeout (or NULL for infinite).
 * \param sigmask Bitmask of signals to receive (or NULL).
 *
 * \retval Number of polled events on success.
 * \retval -1 On error or signal interrupt.
 */
int evqueue_poll(evqueue_t *q, const struct timespec *ts, const sigset_t *sigmask);

/*!
 * \brief Return evqueue pollable fd.
 *
 * \param q Event queue.
 *
 * \retval File descriptor available for polling.
 * \retval -1 On error.
 */
static inline int evqueue_pollfd(evqueue_t *q) {
	return q->fds[EVQUEUE_READFD];
}

/*!
 * \brief Read data from event queue.
 *
 * This function is useful for sending custom
 * events or other data types through the event queue.
 *
 * \param q Event queue.
 * \param dst Destination buffer.
 * \param len Number of bytes to read.
 *
 * \retval Number of read bytes on success.
 * \retval -1 on error, \see read(2).
 */
int evqueue_read(evqueue_t *q, void *dst, size_t len);

/*!
 * \brief Write data to event queue.
 *
 * This function is useful for sending custom
 * events or other data types through the event queue.
 *
 * \param q Event queue.
 * \param src Source buffer.
 * \param len Number of bytes to write.
 *
 * \retval Number of written bytes on success.
 * \retval -1 on error, \see write(2).
 */
int evqueue_write(evqueue_t *q, const void *src, size_t len);

/*!
 * \brief Read event from event queue.
 *
 * \param q Event queue.
 * \param ev Event structure for writing.
 *
 * \retval 0 on success.
 * \retval -1 on error.
 */
int evqueue_get(evqueue_t *q, event_t *ev);

/*!
 * \brief Add event to queue.
 *
 * \param q Event queue.
 * \param ev Event structure to read.
 *
 * \retval 0 on success.
 * \retval -1 on error.
 */
int evqueue_add(evqueue_t *q, const event_t *ev);

/* Singleton event queue pointer. */
extern evqueue_t *s_evqueue;

/*!
 * \brief Event queue singleton.
 */
static inline evqueue_t *evqueue() {
	return s_evqueue;
}

/*!
 * \brief Set event queue singleton.
 */
static inline void evqueue_set(evqueue_t *q) {
	s_evqueue = q;
}

#endif /* _KNOTD_COMMON_EVQUEUE_H_ */

/*! @} */
