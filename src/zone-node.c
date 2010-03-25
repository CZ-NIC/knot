#include "zone-node.h"

#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include "common.h"
#include "dns-simple.h"

/*----------------------------------------------------------------------------*/

zn_node *zn_create( uint count )
{
    zn_node *node = malloc(sizeof(zn_node));

    if (node != NULL) {
        if (count > 0) {
            node->records = malloc(count * sizeof(dnss_rr *));
            if (node->records == NULL) {
                fprintf(stderr, "zn_create(): Allocation failed!\n");
                free(node);
                return NULL;
            }
            node->max_count = count;
            memset(node->records, 0, count * sizeof(dnss_rr *));
        } else {
            node->records = NULL;
        }
        node->count = 0;
    }

    return node;
}

/*----------------------------------------------------------------------------*/

int zn_add_rr( zn_node *node, dnss_rr *rr )
{
    assert(node->count <= node->max_count);
    if (node->count == node->max_count) {
        // no place
        return -1;
    }

    node->records[node->count++] = rr;
    return 0;
}

/*----------------------------------------------------------------------------*/

const dnss_rr *zn_find_rr( const zn_node *node, uint16_t type )
{
    uint i = 0;
    while (i < node->count && node->records[i]->rrtype != type) {
        assert(node->records[i] != NULL);
        ++i;
    }

    if (i == node->count) {
        return NULL;
    }

    assert(node->records[i]->rrtype == type);
    return node->records[i];
}

/*----------------------------------------------------------------------------*/

void zn_destroy( zn_node **node )
{
    for (uint i = 0; i < (*node)->count; ++i) {
        dnss_destroy_rr(&(*node)->records[i]);
    }
    free((*node)->records);
    free(*node);
    *node = NULL;
}

/*----------------------------------------------------------------------------*/

void zn_destructor( void *item )
{
    zn_node *node = (zn_node *)item;
    zn_destroy(&node);
}
