/*
 * File:     stat.c
 * Date:     01.11.2010 17:36
 * Author:   jan
 * Project:  
 * Description:   
 */

#include <malloc.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>

#include "common.h"
#include "stat.h"
#include "gatherer.h"


/*----------------------------------------------------------------------------*/

void stat_reset_gatherer_array( gatherer_t *gatherer )
{
    for (int i = 0; i < FREQ_BUFFER_SIZE; i++) {
        gatherer->freq_array[i]=0;
    }
}

/*----------------------------------------------------------------------------*/

void stat_sleep_compute( void *gatherer )
{ //TODO have a look at locking
    gatherer_t *gath = (gatherer_t *) gatherer;
    while (1) {
        sleep(SLEEP_TIME);

        for (int i = 0; i < FREQ_BUFFER_SIZE; i++) {
            if (gath->freq_array[i]>1) {
                printf("too much activity at index %d: %d queries adress:
                       %s port %d protocol %d\n", i, gath->freq_array[i], 
                       gath->flow_array[i]->addr, gath->flow_array[i]->port,
                       gath->flow_array[i]->protocol);
            }
        }

        pthread_mutex_lock(&(gath->mutex_read)); // when reading, we have
        //to lock

        gath->udp_qps=gath->udp_queries/(double)SLEEP_TIME;

        gath->tcp_qps=gath->tcp_queries/(double)SLEEP_TIME;

        gath->qps = gath->udp_qps + gath->tcp_qps;

        gath->udp_mean_latency=(gath->udp_latency/(double)gath->udp_queries); 

        gath->tcp_mean_latency=(gath->tcp_latency/(double)gath->tcp_queries); 

        gath->mean_latency = (gath->udp_mean_latency+gath->tcp_mean_latency)/2;

        //TODO only applies for sleep time, which might not be bad, at least
        //there's no need to hold more variables
        gath->udp_queries=0;

        gath->tcp_queries=0;

        pthread_mutex_unlock(&(gath->mutex_read));

        stat_reset_gatherer_array(gath);

        printf("qps_udp: %f\n", gath->udp_qps);
        printf("mean_lat_udp: %f\n", gath->udp_mean_latency); //nano seconds

        printf("qps_tcp: %f\n", gath->tcp_qps);
        printf("mean_lat_tcp: %f\n", gath->tcp_mean_latency); //nano seconds

        printf("UDP/TCP ratio %f\n", gath->udp_qps/gath->tcp_qps);

    }
}

/*----------------------------------------------------------------------------*/

stat_t *stat_new_stat( )
{
    stat_t *ret;

    if ((ret=malloc(sizeof(stat_t)))==NULL) {
               //err memry 
        return NULL;
    }

    ret->first=false;

    ret->gatherer=NULL;

    return ret;
}

/*----------------------------------------------------------------------------*/

void stat_stat_free( stat_t *stat ) 
{
    free(stat);
}

/*----------------------------------------------------------------------------*/

uint return_index ( struct sockaddr_in *s_addr , protocol_e protocol )
{
    /* this is the first "hash" I could think of quickly */
    uint ret=0;

    char str[24];
    inet_ntop(AF_INET, &s_addr->sin_addr, str, 24);

    for (int i = 0; i < strlen(str); i++) {
        if (str[i]!='.') { 
            ret+=str[i];
            ret*=(i+1);
        }
    }

    ret+=s_addr->sin_port * 7;
    if (protocol == stat_UDP) {
        ret*=3;
    } else {
        ret*=7;
    }
    ret%=FREQ_BUFFER_SIZE; /* effectively uses only end of the hash, maybe
    hash the resulting number once again to get 0 <= n < 10000 */
    return ret;
}

/*----------------------------------------------------------------------------*/

void stat_gatherer_add_data( stat_t *stat )
{   
    uint index = return_index(stat->s_addr, stat->protocol);
    if (!stat->gatherer->freq_array[index]) {
        char addr[24];
        inet_ntop(AF_INET, &stat->s_addr->sin_addr, addr, 24);
        flow_data_t *tmp;
        tmp=malloc(sizeof(flow_data_t));
        tmp->addr=malloc(sizeof(char)*24);
        strcpy(tmp->addr, addr);
        tmp->port=stat->s_addr->sin_port;
        tmp->protocol=stat->protocol;
        stat->gatherer->flow_array[index]=tmp;
    }
  
    //TODO add a check here, whether hashing fction performs well enough

    stat->gatherer->freq_array[index]+=1;
}

/*----------------------------------------------------------------------------*/

void stat_set_gatherer( stat_t *stat, gatherer_t *gatherer )
{
    stat->gatherer=gatherer;
}

/*----------------------------------------------------------------------------*/

void stat_set_protocol( stat_t *stat, int protocol)
{
    stat->protocol=protocol;
}

/*----------------------------------------------------------------------------*/

void stat_start( gatherer_t *gatherer ) //TODO this starts gatherer, not stat
{
    pthread_t sleeper;
    pthread_create(&sleeper, NULL, (void *) &stat_sleep_compute,
                   gatherer);
}

/*----------------------------------------------------------------------------*/

void stat_inc_query( stat_t *stat )
{
//  pthread_mutex_lock(&(gath->mutex_queries));
    if (stat->protocol==stat_UDP) {
        stat->gatherer->udp_queries++;
    } else {
        stat->gatherer->tcp_queries++;
    }
//  pthread_mutex_unlock(&(gath->mutex_queries));
}

/*----------------------------------------------------------------------------*/

void stat_inc_latency( stat_t *stat, uint increment )
{
//  pthread_mutex_lock(&(gath->mutex_latency));
    if (stat->protocol==stat_UDP) {
        stat->gatherer->udp_latency+=increment;
    } else {
        stat->gatherer->tcp_latency+=increment;
    }
//  pthread_mutex_unlock(&(gath->mutex_latency));
}

/*----------------------------------------------------------------------------*/

void stat_get_first( stat_t *stat , struct sockaddr_in *s_addr )
{
    clock_gettime(CLOCK_REALTIME, &stat->t1);
    stat->s_addr = s_addr;
    //TODO handle s_addr, it's gonna get deleted pretty soon
}

/*----------------------------------------------------------------------------*/

void stat_get_second( stat_t *stat )
{
    clock_gettime(CLOCK_REALTIME, &stat->t2);

    stat_inc_query(stat);
    stat_inc_latency(stat, stat_last_query_time(stat));

    stat_gatherer_add_data(stat);
}

/*----------------------------------------------------------------------------*/

uint stat_last_query_time( stat_t *stat ) 
{
    return (stat->t2).tv_nsec-(stat->t1).tv_nsec;
}

/*----------------------------------------------------------------------------*/

/* end of file stat.c */
