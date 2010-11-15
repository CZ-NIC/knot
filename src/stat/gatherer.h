/*
 * File:     gath.h
 * Date:     08.11.2010 10:10
 * Author:   jan
 * Project:  
 * Description:   
 */

#ifndef __GATH_H__
#define __GATH_H__

#include <stdint.h>

#include "common.h"

enum fbs { FREQ_BUFFER_SIZE = 100000 };

typedef enum {
    stat_UDP,
    stat_TCP
} protocol_e;

/**
\brief 
 Structure used for backward mapping from simple hash to string representation.
*/
typedef struct flow_data_t {
    char *addr;
    uint16_t port;
    protocol_e protocol;
} flow_data_t;

/**
\brief 
Gatherer structure, used for gathering statistics from multiple threads.
*/
typedef struct gatherer_t {
    pthread_mutex_t mutex_read;
    double qps;
    double udp_qps;
    double tcp_qps;
    double mean_latency;
    double udp_mean_latency;
    double tcp_mean_latency;
    uint udp_latency;
    uint tcp_latency;
    uint udp_queries;
    uint tcp_queries;
    uint freq_array[FREQ_BUFFER_SIZE]; /* this should be much bigger, 
    but sparse array, ideally 2**32 */
    flow_data_t *flow_array[FREQ_BUFFER_SIZE];
} gatherer_t;

/**
\brief Creates a new gatherer instance

\return pointer to creted structure, NULL otherwise*/
gatherer_t *new_gatherer();

/**
\brief Frees a gatherer instance

\param gatherer gatherer instance to be freed

\return */
void gatherer_free( gatherer_t *gatherer );

#endif

/* end of file gath.h */
