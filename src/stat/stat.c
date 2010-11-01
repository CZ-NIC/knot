/*
 * File:     stat.c
 * Date:     01.11.2010 17:36
 * Author:   jan
 * Project:  
 * Description:   
 */

#include <malloc.h>
#include <time.h>

#include "common.h"
#include "stat.h"

stat_t *stat_new( )
{
    stat_t *ret;
    if ((ret=malloc(sizeof(stat_t)))==NULL) {
                
        return NULL;
    }
    first = false;
    data=null;
}

void stat_set_protocol( stat_t *stat, uint protocol )
{
    stat->protocol = protocol;
}

int stat_get_time( stat_t *stat, timespec *t )
{
    if (!first) {
        clock_gettime(CLOCK_REALTIME, &t1);
        first = true;
    }
    else {
        clock_gettime(CLOCK_REALTIME, &t2);
        first = false;
    }
}

uint stat_last_query_time( stat_t *stat ) 
{
    return (stat->t2)->tv_nsec-(stat->t2)->tv_nsec;
}

/* end of file stat.c */
