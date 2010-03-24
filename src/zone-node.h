#ifndef ZONE_NODE
#define ZONE_NODE

/*----------------------------------------------------------------------------*/

typedef struct zn_node {

} zn_node;

/*----------------------------------------------------------------------------*/

zn_node *zn_create();

//void zn_destroy( zn_node **node );

void zn_destructor( void *item );

/*----------------------------------------------------------------------------*/

#endif
