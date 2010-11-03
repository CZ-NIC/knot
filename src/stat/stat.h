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
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

static uint const SLEEP_TIME=4;

#define FREQ_BUFFER_SIZE 10000

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
    uint freq_array[FREQ_BUFFER_SIZE]; /* this should be much bigger, but sparse array, ideally 2**32 */
} stat_gatherer_t;

typedef struct stat_t {
    bool first;
    struct timespec t1, t2;
    protocol_e protocol;
    struct sockaddr_in *s_addr;
//  pthread_t incrementor_thread;
    stat_gatherer_t *gatherer;
} stat_t;

/* PRIVATES */
/*---------------------------------------------------------------------------*/

uint stat_last_query_time ( stat_t *stat );

void stat_add_data( stat_t *stat, uint query_time );

/*---------------------------------------------------------------------------*/

/**
\brief 

\return */
stat_gatherer_t *stat_new_gatherer( );

/**
\brief 

\return */
stat_t *stat_new_stat( );

/**
\brief 

\param stat  
\param gatherer  

\return */
void stat_set_gatherer( stat_t *stat, stat_gatherer_t *gatherer);

/**
\brief 

\param stat  
\param protocol  

\return */
void stat_set_protocol( stat_t *stat, int protocol);

/**
\brief 

\return */
void stat_get_time( stat_t *stat );

/**
\brief 

\return */
void stat_start( stat_gatherer_t *gatherer );

/**
\brief 

\return */
void stat_gatherer_free( stat_gatherer_t *gatherer );

/**
\brief 

\return */
void stat_stat_free( stat_t *stat );

#endif

/* end of file stat.h */
