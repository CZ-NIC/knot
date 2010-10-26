/*!
 * @file dispatcher.h
 *
 * API for dispatching given number of POSIX threads on specified routine,
 * blocking and state-keeping.
 *
 */
#ifndef DISPATCHER_H
#define DISPATCHER_H

#include <pthread.h>

/*----------------------------------------------------------------------------*/

/** Thread routine prototype.
  */
typedef void *(*thr_routine)(void *);

/** Dispatcher structure is used for tracking and altering state of
  * running threads and given routine.
  */
typedef struct dpt_dispatcher {
    int thread_count;
    thr_routine routine;
    void **routine_obj;
    pthread_t *threads;
    pthread_attr_t* attrs;
} dpt_dispatcher;

/*----------------------------------------------------------------------------*/

/** Creates a set of sleeping threads with routine_obj as an entrypoint.
  * \param thread_count Number of requested threads.
  * \param thr_routine Pointer to given thread routine.
  * \param routine_obj Pointer to data given to each thread.
  * \return New instance or NULL on failure.
  */
dpt_dispatcher *dpt_create( int thread_count, thr_routine routine,
                            void *routine_obj );

/** Runs the created threads (non-blocking).
  * \return Negative integer on failure.
  */
int dpt_start( dpt_dispatcher *dispatcher );

/** Notify the created threads and interrupt blocking operations.
  * \return Negative integer on failure.
  */
int dpt_notify( dpt_dispatcher *dispatcher, int sig );

/** Waits for the created threads to finish (blocking).
  * \return Negative integer on failure.
  */
int dpt_wait( dpt_dispatcher *dispatcher );

/** Destroys the dispatcher instance.
  * \warning Make sure all threads are finished.
  */
void dpt_destroy( dpt_dispatcher **dispatcher );

/** Set dispatcher thread priority.
  * \param thread_id Thread id relative to dispatcher set, -1 == all threads.
  * \param prio Requested priority (positive integer, default is 0).
  * \return Negative integer on failure.
  */
int dpt_setprio_id( dpt_dispatcher* dispatcher, int thread_id, int prio );

/** Set dispatcher threads priority.
  * \param prio Requested priority (positive integer, default is 0).
  * \return Negative integer on failure.
  */
static inline int dpt_setprio( dpt_dispatcher* dispatcher, int prio ) {
   return dpt_setprio_id(dispatcher, -1, prio);
}

/*----------------------------------------------------------------------------*/

#endif  // DISPATCHER_H
