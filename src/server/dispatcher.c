#include "dispatcher.h"

#include <stdlib.h>
#include <pthread.h>
#include <stdio.h>

/*----------------------------------------------------------------------------*/

dpt_dispatcher *dpt_create( int thread_count, void *(*thr_routine)(void *),
                            void *routine_obj )
{
    dpt_dispatcher *dispatcher = malloc(sizeof(dispatcher));
    dispatcher->thread_count = thread_count;
    dispatcher->routine = thr_routine;
    dispatcher->routine_obj = routine_obj;
    dispatcher->threads = malloc(dispatcher->thread_count * sizeof(pthread_t));
    return dispatcher;
}

/*----------------------------------------------------------------------------*/

int dpt_start( dpt_dispatcher *dispatcher )
{
    int i;

    for (i = 0; i < dispatcher->thread_count; ++i)
    {
        if (pthread_create(&dispatcher->threads[i], NULL,
                           dispatcher->routine, dispatcher->routine_obj)) {
            printf("ERROR CREATING THREAD %d", i );
            return -1;
        }
    }
    for (i = 0; i < dispatcher->thread_count; ++i)
    {
        if ( pthread_join( dispatcher->threads[i], NULL ) ) {
            printf( "ERROR JOINING THREAD %d", i );
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

    free(*dispatcher);
    *dispatcher = NULL;
}
