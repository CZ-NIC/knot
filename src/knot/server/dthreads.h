/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
 * \brief Threading API.
 *
 * Dynamic threads provide:
 * - coherent and incoherent threading capabilities
 * - thread repurposing
 * - thread prioritization
 * - on-the-fly changing of threading unit size
 *
 * Coherent threading unit is when all threads execute
 * the same runnable function.
 *
 * Incoherent function is when at least one thread executes
 * a different runnable than the others.
 */

#pragma once

#include <pthread.h>

#define DEFAULT_THR_COUNT 2  /*!< Default thread count. */

/* Forward decls */
struct dthread;
struct dt_unit;

/*!
 * \brief Thread state enumeration.
 */
typedef enum {
	ThreadJoined    = 1 << 0, /*!< Thread is finished and joined. */
	ThreadJoinable  = 1 << 1, /*!< Thread is waiting to be reclaimed. */
	ThreadCancelled = 1 << 2, /*!< Thread is cancelled, finishing task. */
	ThreadDead      = 1 << 3, /*!< Thread is finished, exiting. */
	ThreadIdle      = 1 << 4, /*!< Thread is idle, waiting for purpose. */
	ThreadActive    = 1 << 5  /*!< Thread is active, working on a task. */
} dt_state_t;

/*!
 * \brief Thread runnable prototype.
 *
 * Runnable is basically a pointer to function which is called on active
 * thread runtime.
 *
 * \note When implementing a runnable, keep in mind to check thread state as
 *       it may change, and implement a cooperative cancellation point.
 *
 *       Implement this by checking dt_is_cancelled() and return
 *       as soon as possible.
 */
typedef int (*runnable_t)(struct dthread *);

/*!
 * \brief Single thread descriptor public API.
 */
typedef struct dthread {
	volatile unsigned  state; /*!< Bitfield of dt_flag flags. */
	runnable_t           run; /*!< Runnable function or 0. */
	runnable_t      destruct; /*!< Destructor function or 0. */
	void               *data; /*!< Currently active data */
	struct dt_unit     *unit; /*!< Reference to assigned unit. */
	void             *_adata; /*!< Thread-specific data. */
	pthread_t           _thr; /*!< Thread */
	pthread_attr_t     _attr; /*!< Thread attributes */
	pthread_mutex_t      _mx; /*!< Thread state change lock. */
} dthread_t;

/*!
 * \brief Thread unit descriptor API.
 *
 * Thread unit consists of 1..N threads.
 * Unit is coherent if all threads execute
 * the same runnable.
 */
typedef struct dt_unit {
	int                   size; /*!< Unit width (number of threads) */
	struct dthread   **threads; /*!< Array of threads */
	pthread_cond_t     _notify; /*!< Notify thread */
	pthread_mutex_t _notify_mx; /*!< Condition mutex */
	pthread_cond_t     _report; /*!< Report thread state */
	pthread_mutex_t _report_mx; /*!< Condition mutex */
	pthread_mutex_t        _mx; /*!< Unit lock */
} dt_unit_t;

/*!
 * \brief Create a set of coherent threads.
 *
 * Coherent means, that the threads will share a common runnable and the data.
 *
 * \param count Requested thread count.
 * \param runnable Runnable function for all threads.
 * \param destructor Destructor for all threads.
 * \param data Any data passed onto threads.
 *
 * \retval New instance if successful
 * \retval NULL on error
 */
dt_unit_t *dt_create(int count, runnable_t runnable, runnable_t destructor, void *data);

/*!
 * \brief Free unit.
 *
 * \warning Behavior is undefined if threads are still active, make sure
 *          to call dt_join() first.
 *
 * \param unit Unit to be deleted.
 */
void dt_delete(dt_unit_t **unit);

/*!
 * \brief Start all threads in selected unit.
 *
 * \param unit Unit to be started.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL on invalid parameters (unit is null).
 */
int dt_start(dt_unit_t *unit);

/*!
 * \brief Send given signal to thread.
 *
 * \note This is useful to interrupt some blocking I/O as well, for example
 *       with SIGALRM, which is handled by default.
 * \note Signal handler may be overriden in runnable.
 *
 * \param thread Target thread instance.
 * \param signum Signal code.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL on invalid parameters.
 * \retval KNOT_ERROR unspecified error.
 */
int dt_signalize(dthread_t *thread, int signum);

/*!
 * \brief Wait for all thread in unit to finish.
 *
 * \param unit Unit to be joined.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL on invalid parameters.
 */
int dt_join(dt_unit_t *unit);

/*!
 * \brief Stop all threads in unit.
 *
 * Thread is interrupted at the nearest runnable cancellation point.
 *
 * \param unit Unit to be stopped.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL on invalid parameters.
 */
int dt_stop(dt_unit_t *unit);

/*!
 * \brief Set thread affinity to masked CPU's.
 *
 * \param thread Target thread instance.
 * \param cpu_id Array of CPU IDs to set affinity to.
 * \param cpu_count Number of CPUs in the array, set to 0 for no CPU.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL on invalid parameters.
 */
int dt_setaffinity(dthread_t *thread, unsigned* cpu_id, size_t cpu_count);

/*!
 * \brief Wake up thread from idle state.
 *
 * Thread is awoken from idle state and reenters runnable.
 * This function only affects idle threads.
 *
 * \note Unit needs to be started with dt_start() first, as the function
 *       doesn't affect dead threads.
 *
 * \param thread Target thread instance.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL on invalid parameters.
 * \retval KNOT_ENOTSUP operation not supported.
 */
int dt_activate(dthread_t *thread);

/*!
 * \brief Put thread to idle state, cancells current runnable function.
 *
 * Thread is flagged with Cancel flag and returns from runnable at the nearest
 * cancellation point, which requires complying runnable function.
 *
 * \note Thread isn't disposed, but put to idle state until it's requested
 *       again or collected by dt_compact().
 *
 * \param thread Target thread instance.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL on invalid parameters.
 */
int dt_cancel(dthread_t *thread);

/*!
 * \brief Collect and dispose idle threads.
 *
 * \param unit Target unit instance.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL on invalid parameters.
 */
int dt_compact(dt_unit_t *unit);

/*!
 * \brief Return number of online processors.
 *
 * \retval Number of online CPU's if success.
 * \retval <0 on failure.
 */
int dt_online_cpus(void);

/*!
 * \brief Return optimal number of threads for instance.
 *
 * It is estimated as NUM_CPUs + CONSTANT.
 * Fallback is DEFAULT_THR_COUNT  (\see common.h).
 *
 * \return Number of threads.
 */
int dt_optimal_size(void);

/*!
 * \brief Return true if thread is cancelled.
 *
 * Synchronously check for ThreadCancelled flag.
 *
 * \param thread Target thread instance.
 *
 * \retval 1 if cancelled.
 * \retval 0 if not cancelled.
 */
int dt_is_cancelled(dthread_t *thread);

/*!
 * \brief Return thread index in threading unit.
 *
 * \note Returns 0 when thread doesn't have a unit.
 *
 * \param thread Target thread instance.
 *
 * \return Thread index.
 */
unsigned dt_get_id(dthread_t *thread);

/*!
 * \brief Lock unit to prevent parallel operations which could alter unit
 *        at the same time.
 *
 * \param unit Target unit instance.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL on invalid parameters.
 * \retval KNOT_EAGAIN lack of resources to lock unit, try again.
 * \retval KNOT_ERROR unspecified error.
 */
int dt_unit_lock(dt_unit_t *unit);

/*!
 * \brief Unlock unit.
 *
 * \see dt_unit_lock()
 *
 * \param unit Target unit instance.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL on invalid parameters.
 * \retval KNOT_EAGAIN lack of resources to unlock unit, try again.
 * \retval KNOT_ERROR unspecified error.
 */
int dt_unit_unlock(dt_unit_t *unit);
