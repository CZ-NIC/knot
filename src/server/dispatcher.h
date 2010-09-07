/*!
 * @file dispatcher.h
 *
 * API for dispatching given number of POSIX threads on specified routine,
 * blocking and state-keeping.
 *
 */
#ifndef DISPATCHER
#define DISPATCHER

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
  */
int dpt_start( dpt_dispatcher *dispatcher );

/** Waits for the created threads to finish (blocking).
  */
int dpt_wait( dpt_dispatcher *dispatcher );

/** Destroys the dispatcher instance.
  * \warning Make sure all threads are finished.
  */
void dpt_destroy( dpt_dispatcher **dispatcher );

/*----------------------------------------------------------------------------*/

#endif  // DISPATCHER
