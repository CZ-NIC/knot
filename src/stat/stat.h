/*
 * File:     stat.h
 * Date:     01.11.2010 16:57
 * Author:   jan
 * Project:  
 * Description:   
 */

#ifndef __STAT_H__
#define __STAT_H__

#include <time.h>
#include <stdbool.h>
#include <pthread.h>

//static uint const BUFFER_SIZE=100; //this does not work...

static uint const SLEEP_TIME=1;

#define BUFFER_SIZE 100

typedef enum {
    stat_UDP,
    stat_TCP
} protocol_e;

typedef struct stat_data_t {
    uint query_type;
    uint nano_secs;
    protocol_e protocol;
} stat_data_t;

typedef struct stat_gatherer_t {
    //these mutexes (or mutices? :) might be used wrong...I have to think about it some more
    pthread_mutex_t mutex_read, mutex_queries, mutex_latency;
    double qps;
    double mean_latency;
    uint latency;
    uint queries; 
} stat_gatherer_t;

typedef struct stat_t {
    bool first;
    struct timespec t1, t2;
    stat_gatherer_t *gatherer;
} stat_t;

/* PRIVATES */
/*---------------------------------------------------------------------------*/

uint stat_last_query_time ( stat_t *stat );

void stat_add_data( stat_t *stat, uint query_time );

void stat_set_protocol( stat_t *stat ,uint protocol );

/*---------------------------------------------------------------------------*/

stat_gatherer_t *stat_new_gatherer( );

stat_t *stat_new_stat( );

void stat_set_gatherer( stat_t *stat, stat_gatherer_t *gatherer);

void stat_get_time( stat_t *stat );

void stat_start( stat_gatherer_t *gatherer );

void stat_gatherer_free( stat_gatherer_t *gatherer );

void stat_stat_free( stat_t *stat );

#endif

/* end of file stat.h */
