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

/*----------------------------------------------------------------------------*/

void stat_sleep_compute( void *gatherer )
{ //TODO have a look at locking
    stat_gatherer_t *gath = (stat_gatherer_t *) gatherer;
    while (1) {
        sleep(SLEEP_TIME);

        pthread_mutex_lock(&(gath->mutex_read)); //qps, mean_latency ???
        pthread_mutex_lock(&(gath->mutex_queries));
        
        gath->qps=gath->queries/(double)SLEEP_TIME;

        pthread_mutex_lock(&(gath->mutex_latency));
        //latency can overflow TODO fix
        gath->mean_latency=(gath->latency/ (double) gath->queries); //TODO only applies for sleep time
        pthread_mutex_unlock(&(gath->mutex_latency));

        gath->queries=0;

        pthread_mutex_unlock(&(gath->mutex_queries));
        pthread_mutex_unlock(&(gath->mutex_read));

        printf("qps: %f\n", gath->qps);
        printf("mean_lat: %f\n", gath->mean_latency); //nano seconds
    }
}

/*----------------------------------------------------------------------------*/

stat_gatherer_t *stat_new_gatherer( )
{
    stat_gatherer_t *ret;

    if ((ret=malloc(sizeof(stat_gatherer_t)))==NULL) {
               //err memry 
        return NULL;
    }

    pthread_mutex_init(&ret->mutex_read, NULL);
    pthread_mutex_init(&ret->mutex_queries, NULL);
    pthread_mutex_init(&ret->mutex_latency, NULL);

    ret->qps = 0.0;
    ret->mean_latency = 0.0;

    ret->latency = 0;
    ret->queries = 0;

    return ret;
}

/*----------------------------------------------------------------------------*/

stat_t *stat_new_stat( )
{
    stat_t *ret;

    if ((ret=malloc(sizeof(stat_t)))==NULL) {
               //err memry 
        return NULL;
    }

    ret->first=false;

    ret->gatherer=NULL;

    return ret;
}

/*----------------------------------------------------------------------------*/

void stat_stat_free( stat_t *stat ) 
{
    free(stat);
}

/*----------------------------------------------------------------------------*/

void stat_gatherer_free( stat_gatherer_t *gatherer )
{
    free(gatherer);
}


/*----------------------------------------------------------------------------*/

void stat_set_gatherer( stat_t *stat, stat_gatherer_t *gatherer)
{
    stat->gatherer=gatherer;
}

/*----------------------------------------------------------------------------*/

void stat_start( stat_gatherer_t *gatherer )
{
    pthread_t sleeper;
    pthread_create(&sleeper, NULL, (void *) &stat_sleep_compute, gatherer);
}

/*----------------------------------------------------------------------------*/

void stat_inc_query(stat_gatherer_t *gath)
{
    pthread_mutex_lock(&(gath->mutex_queries));
    gath->queries++;
    pthread_mutex_unlock(&(gath->mutex_queries));
}

/*----------------------------------------------------------------------------*/

void stat_inc_latency(stat_gatherer_t *gath, uint increment)
{
    pthread_mutex_lock(&(gath->mutex_latency));
    gath->latency+=increment;
    pthread_mutex_unlock(&(gath->mutex_latency));
}

/*----------------------------------------------------------------------------*/

void stat_get_time( stat_t *stat )
{
    if (!stat->first) {
        clock_gettime(CLOCK_REALTIME, &stat->t1);
        stat->first = true;
    }
    else {
        clock_gettime(CLOCK_REALTIME, &stat->t2);
        stat->first = false;
        stat_inc_query(stat->gatherer);
        stat_inc_latency(stat->gatherer, stat_last_query_time(stat));
    }
}

/*----------------------------------------------------------------------------*/

uint stat_last_query_time( stat_t *stat ) 
{
    return (stat->t2).tv_nsec-(stat->t1).tv_nsec;
}

/*----------------------------------------------------------------------------*/

/*void stat_add_data( stat_t *stat, uint query_time )
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
*/
/* end of file stat.c */
