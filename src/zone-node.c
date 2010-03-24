#include "zone-node.h"

#include <stdlib.h>

/*----------------------------------------------------------------------------*/

zn_node *zn_create()
{
    zn_node *node = malloc(sizeof(zn_node));
    return node;
}

/*----------------------------------------------------------------------------*/

void zn_destroy( zn_node **node )
{
    free(*node);
    node = NULL;
}

/*----------------------------------------------------------------------------*/

void zn_destructor( void *item )
{
    zn_node *node = (zn_node *)item;
    zn_destroy(&node);
}
