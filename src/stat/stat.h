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

#include "gatherer.h"

static uint const SLEEP_TIME=15;

typedef struct stat_data_t {
    uint query_type;
    uint nano_secs;
    protocol_e protocol;
} stat_data_t;

typedef struct stat_t {
    bool first;
    struct timespec t1, t2;
    protocol_e protocol;
    struct sockaddr_in *s_addr;
//  pthread_t incrementor_thread;
    gatherer_t *gatherer;
} stat_t;

/* PRIVATES */
/*---------------------------------------------------------------------------*/

uint stat_last_query_time ( stat_t *stat );

void stat_add_data( stat_t *stat, uint query_time );

/*---------------------------------------------------------------------------*/

/**
\brief 

\return */
stat_t *stat_new_stat( );

/**
\brief 

\param stat  
\param gatherer  

\return */
void stat_set_gatherer( stat_t *stat, gatherer_t *gatherer);

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
void stat_start();

/**
\brief 

\return */


/**
\brief 

\return */
void stat_stat_free( stat_t *stat );

void stat_get_first( stat_t *stat , struct sockaddr_in *s_addr );

void stat_get_second( stat_t *stat );


#endif

/* end of file stat.h */
