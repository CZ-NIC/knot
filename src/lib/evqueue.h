/*!
 * \file evqueue.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \brief Event queue.
 *
 * \addtogroup data_structures
 * @{
 */
#ifndef _CUTEDNS_EVQUEUE_H_
#define _CUTEDNS_EVQUEUE_H_

#include <pthread.h>

#include "common.h"
#include "lib/lists.h"

/*!
 * \brief Event structure.
 */
typedef struct {
	void *data; /*!< Usable data ptr. */
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
 * \retval -1 On error or signal interrupt.
 */
int evqueue_poll(evqueue_t *q, const sigset_t *sigmask);

/*!
 * \brief Read event from event queue.
 *
 * \param q Event queue.
 * \retval Event data on success.
 * \retval NULL on error.
 */
void *evqueue_get(evqueue_t *q);

/*!
 * \brief Add event to queue.
 *
 * \param q Event queue.
 * \param item Pointer to event-related data.
 * \retval 0 on success.
 * \retval <0 on error.
 */
int evqueue_add(evqueue_t *q, void *item);

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

#endif /* _CUTEDNS_EVQUEUE_H_ */

/*! @} */
