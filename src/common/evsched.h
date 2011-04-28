/*!
 * \file evsched.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \brief Event scheduler.
 *
 * Scheduler works with the same event_t type as event queue.
 * It is also thread-safe so the scheduler can run in a separate thread
 * while events can be enqueued from different threads.
 *
 * Guideline is, that the scheduler run loop should exit with
 * a special event type EVSCHED_TERM.
 *
 * Example usage:
 * \code
 * evsched_t *s = evsched_new();
 *
 * // Schedule myfunc() after 1000ms
 * evsched_schedule_cb(s, myfunc, data, 1000)
 *
 * // Schedule termination event after 1500ms
 * evsched_schedule_term(s, 1500);
 *
 * // Event scheduler main loop
 * while (1) {
 *    // Wait for next scheduled event
 *    event_t *ev = evsched_next();
 *
 *    // Break on termination event
 *    if (ev->type == EVSCHED_TERM) {
 *       evsched_event_free(s, ev);
 *       break;
 *    }
 *
 *    // Execute and discard event
 *    if (ev->cb) {
 *       ev->cb(ev);
 *    }
 *    evsched_event_free(s, ev); // Free executed event
 * }
 *
 * // Delete event scheduler
 * evsched_delete(s);
 * \endcode
 *
 * \addtogroup common_lib
 * @{
 */

#ifndef _KNOT_COMMON_EVSCHED_H_
#define _KNOT_COMMON_EVSCHED_H_

#include <pthread.h>
#include "common/slab/slab.h"
#include "common/lists.h"
#include "common/evqueue.h"

/*!
 * \brief Scheduler event types.
 */
typedef enum evsched_ev_t {
	EVSCHED_NOOP = 0,   /*!< No-op action, skip. */
	EVSCHED_CB,         /*!< Callback action. */
	EVSCHED_TERM        /*!< Terminal action, stop event scheduler. */
} evsched_ev_t;

/*!
 * \brief Event scheduler structure.
 *
 * Keeps list of scheduled events. Events are executed in their scheduled
 * time and kept in an ordered list (queue).
 * Scheduler is terminated with a special EVSCHED_TERM event type.
 */
typedef struct {
	pthread_mutex_t mx;      /*!< Event queue locking. */
	pthread_cond_t notify;   /*!< Event queue notification. */
	list calendar;           /*!< Event calendar. */
	struct {
		slab_cache_t alloc;      /*!< Events SLAB cache. */
		pthread_spinlock_t lock; /*!< Events cache spin lock. */
	} cache;
} evsched_t;

/*!
 * \brief Create new event scheduler instance.
 *
 * \retval New instance on success.
 * \retval NULL on error.
 */
evsched_t *evsched_new();

/*!
 * \brief Deinitialize and free event scheduler instance.
 *
 * \param s Pointer to event scheduler instance.
 * \note *sched is set to 0.
 */
void evsched_delete(evsched_t **s);

/*!
 * \brief Create an empty event.
 *
 * \param s Pointer to event scheduler instance.
 * \param type Event type.
 * \retval New instance on success.
 * \retval NULL on error.
 */
event_t *evsched_event_new(evsched_t *s, int type);

/*!
 * \brief Dispose event instance.
 *
 * \param s Pointer to event scheduler instance.
 * \param ev Event instance.
 */
void evsched_event_free(evsched_t *s, event_t *ev);

/*!
 * \brief Fetch next-event.
 *
 * Scheduler may block until a next event is available.
 * Send scheduler an EVSCHED_NOOP or EVSCHED_TERM event to unblock it.
 *
 * \param s Event scheduler.
 *
 * \retval Scheduled event.
 * \retval NULL on error.
 */
event_t* evsched_next(evsched_t *s);

/*!
 * \brief Schedule an event.
 *
 * \param s Event scheduler.
 * \param ev Prepared event.
 *
 * \retval 0 on success.
 * \retval <0 on error.
 */
int evsched_schedule(evsched_t *s, event_t *ev);

/*!
 * \brief Schedule callback event.
 *
 * Execute callback after dt miliseconds has passed.
 *
 * \param s Event scheduler.
 * \param cb Callback handler.
 * \param data Data for callback.
 * \param dt Time difference in milliseconds from now (dt is relative).
 *
 * \retval Event instance on success.
 * \retval NULL on error.
 */
event_t* evsched_schedule_cb(evsched_t *s, event_cb_t cb, void *data, int dt);

/*!
 * \brief Schedule termination event.
 *
 * Special action for scheduler termination.
 *
 * \param s Event scheduler.
 * \param dt Time difference in milliseconds from now (dt is relative).
 *
 * \retval Event instance on success.
 * \retval NULL on error.
 */
event_t* evsched_schedule_term(evsched_t *s, int dt);

/*!
 * \brief Cancel a scheduled event.
 *
 * \param s Event scheduler.
 * \param ev Scheduled event.
 *
 * \retval 0 on success.
 * \retval <0 on error.
 */
int evsched_cancel(evsched_t *s, event_t *ev);


#endif /* _KNOT_COMMON_EVSCHED_H_ */

/*! @} */
