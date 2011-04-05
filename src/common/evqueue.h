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

#ifndef _KNOT_COMMON_EVQUEUE_H_
#define _KNOT_COMMON_EVQUEUE_H_

#include <pthread.h>
#include <signal.h> // sigset_t

//#include "knot/common.h"
#include "common/lists.h"

struct event_t;

/*!
 * \brief Event callback.
 */
typedef int (*eventcb_t)(struct event_t *);

/*!
 * \brief Event structure.
 */
typedef struct event_t {
	int code;     /*!< Event code. */
	void *data;   /*!< Usable data ptr. */
	eventcb_t cb; /*!< Event callback. */
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
 * \param timeout Specified timeout. Use NULL for infinite.
 * \param sigmask Bitmask of signals to receive.
 *
 * \retval Number of polled events on success.
 * \retval <0 On error or signal interrupt (EINTR, EINVAL, ENOMEM).
 */
int evqueue_poll(evqueue_t *q, const sigset_t *sigmask);

/*!
 * \brief Read event from event queue.
 *
 * \param q Event queue.
 * \param ev Event structure for writing.
 *
 * \retval 0 on success (EOK).
 * \retval <0 on error (EINVAL, EINTR, EAGAIN).
 */
int evqueue_get(evqueue_t *q, event_t *ev);

/*!
 * \brief Add event to queue.
 *
 * \param q Event queue.
 * \param ev Event structure to read.
 *
 * \retval 0 on success (EOK).
 * \retval <0 on error (EINVAL, EINTR, EAGAIN).
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

#endif /* _KNOT_COMMON_EVQUEUE_H_ */

/*! @} */
