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

void stat_reset_gatherer_array( stat_gatherer_t *gatherer )
{
    for (int i = 0; i < FREQ_BUFFER_SIZE; i++) {
        gatherer->freq_array[i]=0;
    }
}

/*----------------------------------------------------------------------------*/

void stat_sleep_compute( void *gatherer )
{ //TODO have a look at locking
    stat_gatherer_t *gath = (stat_gatherer_t *) gatherer;
    while (1) {
        sleep(SLEEP_TIME);

        for (int i = 0; i < FREQ_BUFFER_SIZE; i++) {
            if (gath->freq_array[i]>50) {
                printf("too much activity at index %d: %d queries\n", 
                       i, gath->freq_array[i]);
            }
        }

        pthread_mutex_lock(&(gath->mutex_read)); //qps, mean_latency ???
//      pthread_mutex_lock(&(gath->mutex_queries));
        
        gath->qps=gath->queries/(double)SLEEP_TIME;

//      pthread_mutex_lock(&(gath->mutex_latency));
        //latency can overflow TODO fix
        gath->mean_latency=(gath->latency/ (double) gath->queries); //TODO only applies for sleep time
//      pthread_mutex_unlock(&(gath->mutex_latency));

        gath->queries=0;

//      pthread_mutex_unlock(&(gath->mutex_queries));
        pthread_mutex_unlock(&(gath->mutex_read));

        stat_reset_gatherer_array(gath);

        printf("qps: %f\n", gath->qps);
        printf("mean_lat: %f\n", gath->mean_latency); //nano seconds
    }
}

/*----------------------------------------------------------------------------*/

stat_gatherer_t *stat_new_gatherer( )
{
    stat_gatherer_t *ret;

    if ((ret=malloc(sizeof(stat_gatherer_t)))==NULL) {
               //err memry 
        return NULL;
    }

    pthread_mutex_init(&ret->mutex_read, NULL);
//  pthread_mutex_init(&ret->mutex_queries, NULL);
//  pthread_mutex_init(&ret->mutex_latency, NULL);

    for (int i = 0; i < FREQ_BUFFER_SIZE; i++) {
        ret->freq_array[i]=0;
    }

    ret->qps = 0.0;
    ret->mean_latency = 0.0;

    ret->latency = 0;
    ret->queries = 0;

    return ret;
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

void stat_gatherer_free( stat_gatherer_t *gatherer )
{
    free(gatherer);
}

uint return_index ( struct sockaddr_in *s_addr )
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
    ret%=FREQ_BUFFER_SIZE; /* effectively uses only end of the hash, maybe
    hash the resulting number once again to get 0 <= n < 10000 */
    return ret;
}

/*----------------------------------------------------------------------------*/

void stat_gatherer_add_data( stat_gatherer_t *gatherer , stat_t *stat,
                             struct sockaddr_in *s_addr )
{
    gatherer->freq_array[return_index(s_addr)]+=1;
}

/*----------------------------------------------------------------------------*/

void stat_set_gatherer( stat_t *stat, stat_gatherer_t *gatherer )
{
    stat->gatherer=gatherer;
}

/*----------------------------------------------------------------------------*/

void stat_set_protocol( stat_t *stat, int protocol)
{
    stat->protocol=protocol;
}

/*----------------------------------------------------------------------------*/

void stat_start( stat_gatherer_t *gatherer )
{
    pthread_t sleeper;
    pthread_create(&sleeper, NULL, (void *) &stat_sleep_compute, gatherer);
}

/*----------------------------------------------------------------------------*/

void stat_inc_query(stat_gatherer_t *gath)
{
//  pthread_mutex_lock(&(gath->mutex_queries));
    gath->queries++;
//  pthread_mutex_unlock(&(gath->mutex_queries));
}

/*----------------------------------------------------------------------------*/

void stat_inc_latency(stat_gatherer_t *gath, uint increment)
{
//  pthread_mutex_lock(&(gath->mutex_latency));
    gath->latency+=increment;
//  pthread_mutex_unlock(&(gath->mutex_latency));
}

/*----------------------------------------------------------------------------*/

void stat_get_first( stat_t *stat , struct sockaddr_in *s_addr )
{
    clock_gettime(CLOCK_REALTIME, &stat->t1);
    stat->s_addr = s_addr;
    //TODO handle s_addr;
}

/*----------------------------------------------------------------------------*/

void stat_get_second( stat_t *stat )
{
    clock_gettime(CLOCK_REALTIME, &stat->t2);

    stat_inc_query(stat->gatherer);
    stat_inc_latency(stat->gatherer, stat_last_query_time(stat));

    stat_gatherer_add_data(stat->gatherer, stat, stat->s_addr);
}

/*----------------------------------------------------------------------------*/

uint stat_last_query_time( stat_t *stat ) 
{
    return (stat->t2).tv_nsec-(stat->t1).tv_nsec;
}

/*----------------------------------------------------------------------------*/

/* end of file stat.c */
