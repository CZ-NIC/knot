#ifndef DISPATCHER
#define DISPATCHER

#include <pthread.h>

/*----------------------------------------------------------------------------*/

typedef struct dpt_dispatcher {
    int thread_count;
    void *(*routine)(void *);
    void *routine_obj;
    pthread_t *threads;
} dpt_dispatcher;

/*----------------------------------------------------------------------------*/

dpt_dispatcher *dpt_create( int thread_count, void *(*thr_routine)(void *),
                            void *routine_obj );

int dpt_start( dpt_dispatcher *dispatcher );

void dpt_destroy( dpt_dispatcher **dispatcher );

/*----------------------------------------------------------------------------*/

#endif  // DISPATCHER
