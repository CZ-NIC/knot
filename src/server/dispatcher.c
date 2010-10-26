#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include "dispatcher.h"
#include "common.h"

/*----------------------------------------------------------------------------*/

dpt_dispatcher *dpt_create( int thread_count, thr_routine routine,
                            void *routine_obj )
{
    dpt_dispatcher *dispatcher = malloc(sizeof(dpt_dispatcher));
    dispatcher->thread_count = thread_count;
    dispatcher->routine = routine;
    dispatcher->routine_obj = malloc(dispatcher->thread_count * sizeof(void*));
    dispatcher->attrs = malloc(dispatcher->thread_count * sizeof(pthread_attr_t));
    dispatcher->threads = malloc(dispatcher->thread_count * sizeof(pthread_t));
    for(int i = 0; i < thread_count; ++i) {
        dispatcher->routine_obj[i] = routine_obj;
        pthread_attr_init(&dispatcher->attrs[i]);
        pthread_attr_setinheritsched(&dispatcher->attrs[i], PTHREAD_INHERIT_SCHED);
        pthread_attr_setschedpolicy(&dispatcher->attrs[i], SCHED_OTHER);
    }
    return dispatcher;
}

/*----------------------------------------------------------------------------*/

int dpt_start( dpt_dispatcher *dispatcher )
{
    for (int i = 0; i < dispatcher->thread_count; ++i)
    {
        if (pthread_create(&dispatcher->threads[i], &dispatcher->attrs[i],
                           dispatcher->routine, dispatcher->routine_obj[i])) {
            log_error("%s: failed to create thread %d", __func__, i);
            return -1;
        }
    }

    return 0;
}

int dpt_notify( dpt_dispatcher* dispatcher,  int sig )
{
   for(int i = 0; i < dispatcher->thread_count; ++i) {
      pthread_kill(dispatcher->threads[i], sig);
   }

   return 0;
}

/*----------------------------------------------------------------------------*/

int dpt_wait( dpt_dispatcher *dispatcher )
{
    for (int i = 0; i < dispatcher->thread_count; ++i)
    {
        if ( pthread_join( dispatcher->threads[i], NULL ) ) {
            log_error("%s: failed to join thread %d", __func__, i);
            return -1;
        }
    }

    return 0;
}

/*----------------------------------------------------------------------------*/

void dpt_destroy( dpt_dispatcher **dispatcher )
{
    // some cleaning stuff
    // shouldn't we check if the threads have terminated?
    if(dispatcher == NULL || *dispatcher == NULL)
        return;

    // Free thread attrs
    for(int i = 0; i < (*dispatcher)->thread_count; ++i) {
       pthread_attr_destroy(&(*dispatcher)->attrs[i]);
    }

    free((*dispatcher)->attrs);
    free((*dispatcher)->threads);
    free((*dispatcher)->routine_obj);
    free(*dispatcher);
    *dispatcher = NULL;
}

int dpt_setprio_id( dpt_dispatcher* dispatcher, int thread_id, int prio )
{
   // Single thread
   int ret = 0;
   if(thread_id != -1) {
      if(thread_id < dispatcher->thread_count) {

         int policy = SCHED_FIFO;
         prio = MIN(MAX(sched_get_priority_min(policy), prio), sched_get_priority_max(policy));
         ret = pthread_attr_setschedpolicy(&dispatcher->attrs[thread_id], policy);
         if(ret < 0) {
            debug_server("dpt_setprio_id(%p, %d, %d) failed: %s",
                         dispatcher, thread_id, prio, strerror(errno));
         }

         struct sched_param sp;
         sp.sched_priority = prio;
         ret = pthread_attr_setschedparam(&dispatcher->attrs[thread_id], &sp);
         if(ret < 0) {
            debug_server("dpt_setprio_id(%p, %d, %d) failed: %s",
                         dispatcher, thread_id, prio, strerror(errno));
         }

         return ret;
      }
      else {
         // Invalid thread id
         debug_server("dpt_setprio_id(%p, %d, %d) failed: invalid thread id (thread_count is %d)",
                      dispatcher, thread_id, prio, dispatcher->thread_count);
         return -1;
      }
   }

   // Multiple threads
   for(thread_id = 0; thread_id < dispatcher->thread_count; ++thread_id) {
      ret = dpt_setprio_id(dispatcher, thread_id, prio);
   }

   return ret;
}
