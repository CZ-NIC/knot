/*
 * File     node.c
 * Date     11.11.2010 15:38
 * Author:  jan.kadlec@nic.cz
 * Project: CuteDNS
 * Description:   
 */

#include <malloc.h>

#include "common.h"
#include "node.h"
#include "rrset.h"

int compare_rrset_types( void *rrset_1, void *rrset_2 )
{
    return (((dnslib_rrset_t *)rrset_1)->type == 
            ((dnslib_rrset_t *)rrset_2)->type ? 0 : 
            ((dnslib_rrset_t *)rrset_1)->type < 
            ((dnslib_rrset_t *)rrset_2)->type ? -1 : 1);
}

dnslib_node_t *dnslib_node_new( dnslib_dname_t *owner, dnslib_node_t *parent )
{
    dnslib_node_t *ret = malloc(sizeof(dnslib_node_t));
    if (ret == NULL) {
        ERR_ALLOC_FAILED;
        return NULL;
    }

    ret->owner = owner;
    ret->parent = parent;

    ret->rrsets = skip_create_list(compare_rrset_types);
    return ret;
}

int dnslib_node_add_rrset( dnslib_node_t *node, dnslib_rrset_t *rrset )
{
    if ((skip_insert(node->rrsets, &rrset->type, &rrset, NULL)) != 0) {
        return -2;
    }
    return 0;
}

const dnslib_rrset_t *dnslib_node_get_rrset( const dnslib_node_t *node,
											 uint16_t type )
{
    return (dnslib_rrset_t*)skip_find(node->rrsets, &type);
}

const dnslib_node_t *dnslib_node_get_parent( const dnslib_node_t *node )
{
    return node->parent;
}

void dnslib_node_free( dnslib_node_t **node )
{
    skip_destroy_list(&(*node)->rrsets, NULL, NULL);
    free(*node);
    *node = NULL;
}

/* end of file node.c */
