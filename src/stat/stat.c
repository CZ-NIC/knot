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
        sleep(SLEEP_TIME);
        pthread_mutex_lock(&(stat2->mutex));
        stat2->qps=stat2->queries/(double)SLEEP_TIME;
        stat2->queries=0;
        pthread_mutex_unlock(&(stat2->mutex));
        stat_print_qps(stat2);
        printf("mean_latency: %f\n", (stat2->latency/(double)stat2->queries2)/1000);
        if (stat2->queries2 > MAX_QUERIES) {
            stat2->latency = 0;
            stat2->queries2 = 0;
        }
    }
}

stat_t *stat_new( )
{
    stat_t *ret;
    if ((ret=malloc(sizeof(stat_t)))==NULL) {
                
        return NULL;
    }
    ret->first = false;
    pthread_mutex_init(&ret->mutex, NULL);
    ret->queries=0;
    ret->qps=0.0;
    ret->mean_latency=0.0;
    ret->len=0;
    ret->latency=0;
    ret->queries2=0;
    return ret;
}

void stat_start( stat_t *stat )
{
    pthread_t sleeper;
    pthread_create(&sleeper, NULL, (void *) &stat_sleep_compute, stat);
}

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
        stat->queries2++;
        stat->latency+=stat_last_query_time(stat);
        //stat_add_data(stat, stat_last_query_time(stat));
    }
}

uint stat_last_query_time( stat_t *stat ) 
{
    return (stat->t2).tv_nsec-(stat->t1).tv_nsec;
}

void stat_add_data( stat_t *stat, uint query_time )
{
    if (stat->len!=100) {
        (stat->data[stat->len]).nano_secs=query_time;
        stat->len++;
    }
    else {
        stat->mean_latency=0;
        for (int i = 0; i < 100; i++) {
            stat->mean_latency+=(stat->data[i]).nano_secs;
        }
        stat->mean_latency/=1000000.0; //ms
        stat->len=0;
    }
}

/* end of file stat.c */
