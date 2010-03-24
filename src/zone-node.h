#ifndef ZONE_NODE
#define ZONE_NODE

#include "common.h"
#include "dns-simple.h"

/*----------------------------------------------------------------------------*/

typedef struct zn_node {
    dnss_rr **records;
    uint count;
    uint max_count;
} zn_node;

/*----------------------------------------------------------------------------*/

zn_node *zn_create( uint count );

int zn_add_rr( zn_node *node, dnss_rr *rr );

const dnss_rr *zn_find_rr( zn_node *node, uint16_t type );

void zn_destroy( zn_node **node );

void zn_destructor( void *item );

/*----------------------------------------------------------------------------*/

#endif
