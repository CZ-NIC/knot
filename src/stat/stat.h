/*
 * File:     stat.h
 * Date:     01.11.2010 16:57
 * Author:   jan
 * Project:  
 * Description:   
 */

#include <time.h>
#include <stdbool.h>

static uint const BUFFER_SIZE=1000;

#ifndef __STAT_H__
#define __STAT_H__

enum {
        udp;
        tcp;
} protocol_e;

typedef struct stat_data_t {
        uint query_type;
        uint nano_secs;
        char *interface;
        protocol_e protocol;
} stat_data_t;

typedef struct stat_t {
         bool first;
         struct timespec t1, t2;
         stat_data_t data[BUFFER_SIZE];
} stat_t;

/* PRIVATES */
/*---------------------------------------------------------------------------*/

uint stat_last_query_time ( stat_t *stat );

/*---------------------------------------------------------------------------*/

stat_t *stat_new( );

void stat_set_protocol( uint protocol );

int 

int stat_get_time( stat_t *stat, timespec *t );

#endif

/* end of file stat.h */
