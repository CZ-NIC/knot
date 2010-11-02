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

//static uint const BUFFER_SIZE=100;

static uint const MAX_QUERIES=10000000;

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

typedef struct stat_t {
         pthread_mutex_t mutex;
         bool first;
         struct timespec t1, t2;
         double qps;
         double mean_latency;
         uint queries;
         uint queries2;
         uint len;
         uint latency;
         stat_data_t data[BUFFER_SIZE]; //XXX
} stat_t;

/* PRIVATES */
/*---------------------------------------------------------------------------*/

uint stat_last_query_time ( stat_t *stat );

void stat_add_data( stat_t *stat, uint query_time );

void stat_set_protocol( stat_t *stat ,uint protocol );

/*---------------------------------------------------------------------------*/

stat_t *stat_new( );

int stat_get_time( stat_t *stat );

void stat_start( stat_t *stat );

#endif

/* end of file stat.h */
