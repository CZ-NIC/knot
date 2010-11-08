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

#define FREQ_BUFFER_SIZE 100000

typedef enum {
    stat_UDP,
    stat_TCP
} protocol_e;

typedef struct flow_data_t {
    char *addr;
    uint16_t port;
    protocol_e protocol;
} flow_data_t;

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
    uint freq_array[FREQ_BUFFER_SIZE]; /* this should be much bigger, but sparse array, ideally 2**32 */
    flow_data_t *flow_array[FREQ_BUFFER_SIZE];
} gatherer_t;

gatherer_t *new_gatherer();

void gatherer_free( gatherer_t *gatherer );

#endif

/* end of file gath.h */
