/*!
 * \file dthreads.h
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
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
 *
 * \addtogroup threading
 * @{
 */

#ifndef CUTE_DTHREADS_H
#define CUTE_DTHREADS_H

#include <pthread.h>

/* Forward decls */
struct dthread_t;
struct dt_unit_t;

/*!
 * \brief Thread state enumeration.
 *
 * \note State values are ordered by state level
 *       and such should not be changed.
 *       The reason is, you can compare like: "state > Dead" etc.
 */
enum {
    ThreadJoined    = 1 << 0, /*!< Thread is finished and joined. */
    ThreadCancelled = 1 << 1, /*!< Thread is cancelled, finishing task. */
    ThreadDead      = 1 << 2, /*!< Thread is finished, waiting to be freed. */
    ThreadIdle      = 1 << 3, /*!< Thread is idle, waiting for purpose. */
    ThreadActive    = 1 << 4  /*!< Thread is active, working on a task. */

} dt_state_t;

/*!
 * \brief Thread runnable prototype.
 *
 * Runnable is basically a pointer to function
 * which is called on active thread runtime.
 *
 * \note When implementing runnable, keep in mind
 *       to check thread state, as it changes and
 *       implement cooperative cancellation point.
 *       If state contains Cancelled flag, return
 *       as soon as possible.
 */
typedef int (*runnable_t)(struct dthread_t*);

/*!
 * \brief Single thread descriptor public API.
 * \todo Find a good way to hide implementation data
 *       in an overlapped out-of-line structure,
 *       while not breaking an array of dthread_t.
 */
typedef struct dthread_t {
    volatile unsigned  state; /*!< Bitfield of dt_flag flags. */
    runnable_t           run; /*!< Runnable function or 0. */
    void               *data; /*!< Currently active data */
    struct dt_unit_t   *unit; /*!< Reference to assigned unit. */
    void             *_adata; /* Thread-specific data. */
    pthread_t           _thr; /* Implementation specific thread */
    pthread_attr_t     _attr; /* Implementation specific thread attributes */
    pthread_mutex_t      _mx; /* Thread state change lock. */
} dthread_t;

/*!
 * \brief Thread unit descriptor API.
 *
 * Thread unit consists of 1..N threads.
 * Unit is coherent if all threads execute
 * the same runnable.
 */
typedef struct dt_unit_t {
    int                   size; /*!< Unit width (number of allocated threads) */
    struct dthread_t **threads; /*!< Array of threads */
    pthread_cond_t     _notify; /* Notify thread */
    pthread_mutex_t _notify_mx; /* Condition mutex */
    pthread_cond_t     _report; /* Report thread state */
    pthread_mutex_t _report_mx; /* Condition mutex */
    pthread_mutex_t        _mx; /* Unit lock */
} dt_unit_t;

/*!
 * \brief Create a set of threads with no initial runnable.
 *
 * \param count Requested thread count.
 * \return On success: new instance, else 0
 */
dt_unit_t *dt_create (int count);

/*!
 * \brief Create a set of coherent threads.
 *
 * \param count Requested thread count.
 * \param runnable Runnable function for all threads.
 * \param data Any data passed onto threads.
 * \return On success: new instance, else 0
 */
dt_unit_t *dt_create_coherent (int count, runnable_t runnable, void *data);

/*!
 * \brief Free unit.
 *
 * \warning Behavior is undefined if threads are still running,
 *          make sure to dt_join() first.
 */
void dt_delete (dt_unit_t **unit);

/*!
 * \brief Resize unit to given number.
 *
 * \note Newly created dthreads will have
 *       no runnable or data, their state
 *       will be ThreadJoined (that means
 *       no thread will be physically created until
 *       next dt_start()).
 *
 * \warning Be careful when shrinking unit,
 *          joined and idle threads are reclaimed first,
 *          but it may kill your active threads as a last resort.
 *          However, threads will stop at their cancellation point,
 *          so this is potentially an expensive operation.
 *
 * \param size New unit size.
 * \return On success: 0, else <0
 */
int dt_resize(dt_unit_t *unit, int size);

/*!
 * \brief Start all threads in selected unit.
 *
 * \return On success: 0, else <0
 */
int dt_start (dt_unit_t *unit);

/*!
 * \brief Send given signal to thread.
 *
 * \note This is useful to interrupt some blocking I/O as well,
 *       for example with SIGALRM, which is handled by default.
 * \note Signal handler may be overriden in runnable.
 *
 * \param signum Signal code.
 * \return On success: 0, else <0
 */
int dt_signalize (dthread_t *thread, int signum);

/*!
 *  \brief Wait for all thread in unit to finish.
 *
 *  \return Negative integer on failure.
 */
int dt_join (dt_unit_t *unit);

/*!
 *  \brief Stop thread from running.
 *
 *  Active thread is interrupted at the nearest
 *  runnable cancellation point.
 *
 * \return On success: 0, else <0
 */
int dt_stop_id (dthread_t* thread);

/*!
 *  \brief Stop all threads in unit.
 *
 *  Active threads are interrupted at the nearest
 *  runnable cancellation point.
 *
 * \return On success: 0, else <0
 */
int dt_stop (dt_unit_t *unit);

/*!
 * \brief Modify thread priority.
 *
 * \param thread_id Identifier in unit, -1 means all threads.
 * \param prio Requested priority (positive integer, default is 0).
 * \return On success: 0, else <0
 */
int dt_setprio (dthread_t* thread, int prio);

/*!
 * \brief Set thread to execute another runnable.
 *
 * \param thread    Thread reference.
 * \param runnable  Runnable function for target thread.
 * \param data      Data passed to target thread.
 * \return On success: 0, else <0
 */
int dt_repurpose (dthread_t* thread, runnable_t runnable, void *data);

/*!
 * \brief Wake up thread from idle state.
 *
 * Thread is awoken from idle state and enters runnable.
 * This function has no effect on running threads.
 */
int dt_activate (dthread_t *thread);

/*!
 * \brief Put thread to idle state, cancells current runnable function.
 *
 * Thread is flagged with Cancel flag and returns from runnable at the nearest
 * cancellation point, which requires complying runnable function.
 *
 * \note Thread isn't disposed, but put to idle state
 *       until it's requested again or collected by dt_compact().
 *
 * \param thread Cancelled thread.
 * \return On success: 0, else <0
 */
int dt_cancel (dthread_t *thread);

/*!
 * \brief Collect and dispose idle threads.
 *
 * \param unit Target unit.
 * \return On success: 0, else <0
 */
int dt_compact (dt_unit_t *unit);

/*!
 * \brief Return optimal number of threads for instance.
 *
 * It is estimated as NUM_CPUs + 1.
 * Fallback is DEFAULT_THR_COUNT  (\see common.h).
 *
 * \return number of threads
 */
int dt_optimal_size ();

/*!
 * \brief Return true if thread is cancelled.
 *
 * Synchronously check for ThreadCancelled flag.
 */
int dt_is_cancelled (dthread_t *thread);

#endif // DTHREADS_H

/** @} */
