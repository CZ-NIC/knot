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

/* determines how long until the sleeper thread wakes up and does compuations */
static uint const SLEEP_TIME=15;

/**
\brief 
Statistics structure, unique for each UDP/TCP thread.
*/
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
Creates a new stat_t instance.
\return new instance, NULL otherwise*/
stat_t *stat_new_stat( );

/**
\brief 
Assignes a gatherer to stat_t structure.
\param stat  stat_t (usually newly created)
\param gatherer  "parental" gatherer structure

\return */
void stat_set_gatherer( stat_t *stat, gatherer_t *gatherer);

/**
\brief 
Sets a protocol for stat_t structure. Options are stat_UDP, stat_TCP.
\param stat  stat_t (usually newly created)
\param protocol  protocol to be assigned to stat structure
\return */

void stat_set_protocol( stat_t *stat, int protocol);

/**
\brief 
Frees a stat_t structure.
\parem stat stat_t to be freed
\return */
void stat_stat_free( stat_t *stat );

/**
\brief 
Gets the time from processing function.
\param stat  current instance of stat_t
\param s_addr  sockaddr structure to be used later for statistics

\return */
void stat_get_first( stat_t *stat, struct sockaddr_in *s_addr );

/**
\brief 
Gets the the from processing fuction and changes the corresponding variables.
\param stat current stat_t instance
\return */
void stat_get_second( stat_t *stat );


#endif

/* end of file stat.h */
