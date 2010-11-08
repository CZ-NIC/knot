/*
 * File:     gath.c
 * Date:     08.11.2010 10:18
 * Author:   jan
 * Project:  
 * Description:   
 */

#include <malloc.h>
#include <pthread.h>

#include "gatherer.h"
#include "common.h"

/*----------------------------------------------------------------------------*/

gatherer_t *new_gatherer( )
{
    gatherer_t *ret;

    if ((ret=malloc(sizeof(gatherer_t)))==NULL) {
               //err memry 
        return NULL;
    }

    pthread_mutex_init(&ret->mutex_read, NULL);

    for (int i = 0; i < FREQ_BUFFER_SIZE; i++) {
        ret->freq_array[i]=0;
    }

    ret->qps = 0.0;
    ret->udp_qps = 0.0;
    ret->tcp_qps = 0.0;

    ret->mean_latency = 0.0;
    ret->udp_mean_latency = 0.0;
    ret->tcp_mean_latency = 0.0;

    ret->udp_latency = 0;
    ret->tcp_latency = 0;

    ret->udp_queries = 0;
    ret->tcp_queries = 0;

    return ret;
}

/*----------------------------------------------------------------------------*/

void gatherer_free( gatherer_t *gath )
{
    for (int i = 0; i < FREQ_BUFFER_SIZE; i++) {
        free(gath->flow_array[i]->addr);
    }
    free(gath);
}

/*----------------------------------------------------------------------------*/

/* end of file gath.c */
