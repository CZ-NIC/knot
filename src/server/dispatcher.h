#ifndef DISPATCHER
#define DISPATCHER

#include <pthread.h>

/*----------------------------------------------------------------------------*/
typedef void *(*thr_routine)(void *);

typedef struct dpt_dispatcher {
    int thread_count;
    thr_routine routine;
    void *routine_obj;
    pthread_t *threads;
} dpt_dispatcher;

/*----------------------------------------------------------------------------*/

dpt_dispatcher *dpt_create( int thread_count, thr_routine routine,
                            void *routine_obj );

int dpt_start( dpt_dispatcher *dispatcher );
int dpt_wait( dpt_dispatcher *dispatcher );

void dpt_destroy( dpt_dispatcher **dispatcher );

/*----------------------------------------------------------------------------*/

#endif  // DISPATCHER
