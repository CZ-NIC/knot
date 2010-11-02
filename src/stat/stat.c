/*
 * File:     stat.c
 * Date:     01.11.2010 17:36
 * Author:   jan
 * Project:  
 * Description:   
 */

#include <malloc.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <stdbool.h>

#include "common.h"
#include "stat.h"

void stat_print_qps( stat_t *stat )
{
    printf("%f\n", stat->qps);
}

void stat_sleep_compute( void *stat )
{
    stat_t *stat2 = (stat_t *) stat;
    while (1)
    {
        sleep(1);
        pthread_mutex_lock(&(stat2->mutex));
//        stat2->qps=(stat2->qps+(stat2->queries/1.0));
        stat2->qps=stat2->queries;
        stat2->queries=0;
        pthread_mutex_unlock(&(stat2->mutex));
        stat_print_qps(stat2);
    }
}

stat_t *stat_new( )
{
    stat_t *ret;
    if ((ret=malloc(sizeof(stat_t)))==NULL) {
                
        return NULL;
    }
    ret->first = false;
//    ret->data=null;
//    ret->mutex=PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_init(&ret->mutex, NULL);
    return ret;
}

void stat_start( stat_t *stat )
{
    printf("starting sleeper thread\n");
    pthread_t sleeper;
    pthread_create(&sleeper, NULL, (void *) &stat_sleep_compute, stat);
}

/* void stat_set_protocol( stat_t *stat, uint protocol )
{
    stat->protocol = protocol;
}*/

int stat_get_time( stat_t *stat )
{
    if (!stat->first) {
        clock_gettime(CLOCK_REALTIME, &stat->t1);
        stat->first = true;
    }
    else {
        clock_gettime(CLOCK_REALTIME, &stat->t2);
        stat->first = false;
        stat->queries++;
    }
}

uint stat_last_query_time( stat_t *stat ) 
{
    return (stat->t2).tv_nsec-(stat->t2).tv_nsec;
}

/* end of file stat.c */
