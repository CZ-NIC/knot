#include <stdlib.h>
#include <pthread.h>
#include <stdio.h>

#include "dispatcher.h"
#include "common.h"

/*----------------------------------------------------------------------------*/

dpt_dispatcher *dpt_create( int thread_count, thr_routine routine,
                            void *routine_obj )
{
    dpt_dispatcher *dispatcher = malloc(sizeof(dpt_dispatcher));
    dispatcher->thread_count = thread_count;
    dispatcher->routine = routine;
    dispatcher->routine_obj = routine_obj;
    dispatcher->threads = malloc(dispatcher->thread_count * sizeof(pthread_t));
    return dispatcher;
}

/*----------------------------------------------------------------------------*/

int dpt_start( dpt_dispatcher *dispatcher )
{
    for (int i = 0; i < dispatcher->thread_count; ++i)
    {
        if (pthread_create(&dispatcher->threads[i], NULL,
                           dispatcher->routine, dispatcher->routine_obj)) {
            log_error("%s: failed to create thread %d", __func__, i);
            return -1;
        }
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

    free((*dispatcher)->threads);
    free(*dispatcher);
    *dispatcher = NULL;
}
