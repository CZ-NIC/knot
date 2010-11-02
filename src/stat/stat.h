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

static uint const BUFFER_SIZE=1000;

/*typedef enum {
        UDP,
        TCP
} protocol_e;*/

typedef struct stat_data_t {
        uint query_type;
        uint nano_secs;
        char *interface;
//        protocol_e protocol;
} stat_data_t;

typedef struct stat_t {
         pthread_mutex_t mutex;
         bool first;
         struct timespec t1, t2;
         double qps;
         uint queries;
//         stat_data_t data[BUFFER_SIZE];
} stat_t;

/* PRIVATES */
/*---------------------------------------------------------------------------*/

uint stat_last_query_time ( stat_t *stat );

/*---------------------------------------------------------------------------*/

stat_t *stat_new( );

void stat_set_protocol( uint protocol );

int stat_get_time( stat_t *stat );

#endif

/* end of file stat.h */
