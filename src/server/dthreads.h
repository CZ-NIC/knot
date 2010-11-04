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
    ThreadDead      = 1 << 1, /*!< Thread is finished, waiting to be freed. */
    ThreadIdle      = 1 << 2, /*!< Thread is idle, waiting for purpose. */
    ThreadActive    = 1 << 3, /*!< Thread is active, working on a task. */
    ThreadCancelled = 1 << 4  /*!< Thread is cancelled, finishing task. */

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
    unsigned           state; /*!< Bitfield of dt_flag flags. */
    runnable_t           run; /*!< Runnable function or 0. */
    void               *data; /*!< Thread-specific data. */
    struct dt_unit_t   *unit; /*!< Reference to assigned unit. */
    void             *_adata; /* Currently active data */
    pthread_t           _thr; /* Implementation specific thread */
    pthread_attr_t     _attr; /* Implementation specific thread attributes */
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
    struct dthread_t  *threads; /*!< Array of threads */
    pthread_cond_t     _isidle; /* Threads notification condition */
    pthread_mutex_t _isidle_mx; /* Condition mutex */
    pthread_cond_t     _isdead; /* Dead thread notification */
    pthread_mutex_t _isdead_mx; /* Condition mutex */
} dt_unit_t;

/*! \brief Accessor to threads in unit. */
#define dt_get(p_unit, id) (p_unit->threads + (id))

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
 * \brief Start all threads in selected unit.
 *
 * \return On success: 0, else <0
 */
int dt_start (dt_unit_t *unit);

/*!
 * \brief Send given signal to threads.
 *
 * \note This is useful to interrupt some blocking I/O as well,
 *       for example with SIGALRM and a properly set handler.
 *
 * \param signum Signal code.
 * \return On success: 0, else <0
 */
int dt_signalize (dt_unit_t *unit, int signum);

/*!
 *  \brief Wait for all thread in unit to finish.
 *
 *  \return Negative integer on failure.
 */
int dt_join (dt_unit_t *unit);

/*!
 *  \brief Stop all threads from running.
 *
 *  Active threads are interrupted at the nearest
 *  runnable cancellation point.
 *
 *  \return Number of affected threads.
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


#endif // DTHREADS_H

/** @} */
