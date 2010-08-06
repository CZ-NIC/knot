#include "zone-node.h"

#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include "common.h"
#include "skip-list.h"
#include <ldns/rr.h>
#include <ldns/dname.h>
#include <ldns/rdata.h>

/*----------------------------------------------------------------------------*/

static const uint RRSETS_COUNT = 10;

/*----------------------------------------------------------------------------*/

int zn_compare_keys( void *key1, void *key2 )
{
	// in our case, key is of type ldns_rr_type, but as casting to enum may
	// result in undefined behaviour, we use regular unsigned int.
	return ((uint)key1 < (uint)key2) ? -1 : (((uint)key1 > (uint)key2) ? 1 : 0);
}

/*----------------------------------------------------------------------------*/

int zn_merge_values( void **value1, void **value2 )
{
	if (ldns_rr_list_cat((ldns_rr_list *)(*value1),
						 (ldns_rr_list *)(*value2))) {
		return 0;
	} else {
		return -1;
	}
}

/*----------------------------------------------------------------------------*/

void zn_destroy_value( void *value )
{
	ldns_rr_list_deep_free((ldns_rr_list *)value);
}

/*----------------------------------------------------------------------------*/

zn_node *zn_create()
{
    zn_node *node = malloc(sizeof(zn_node));
	if (node == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	node->rrsets = skip_create_list(zn_compare_keys);
	if (node->rrsets == NULL) {
		free(node);
		return NULL;
	}

	node->next = NULL;
	node->prev = NULL;
	node->owner = NULL;

    return node;
}

/*----------------------------------------------------------------------------*/

ldns_rdf *zn_owner( zn_node *node )
{
	return node->owner;
}

/*----------------------------------------------------------------------------*/

int zn_add_rr( zn_node *node, ldns_rr *rr )
{
	/*
	 * This whole function can be written with less code if we first create new
	 * rr_list, insert the RR into it and then call skip_insert and provide
	 * the merging function.
	 *
	 * However, in that case the allocation will occur always, what may be
	 * time-consuming, so we retain this version for now.
	 */
	if (rr == NULL) {
		return -7;
	}

	// accept only RR with the same owner
	if (node->owner
		&& ldns_dname_compare(node->owner, ldns_rr_owner(rr)) != 0) {
		return -6;
	}

	// find an appropriate RRSet for the RR
	ldns_rr_list *rrset = (ldns_rr_list *)skip_find(
							node->rrsets, (void *)ldns_rr_get_type(rr));

	// found proper RRSet, insert into it
	if (rrset != NULL) {
		assert(ldns_rr_list_type(rrset) == ldns_rr_get_type(rr));
		if (ldns_rr_list_push_rr(rrset, rr) != true) {
			return -3;
		}
	} else {
		rrset = ldns_rr_list_new();
		if (rrset == NULL) {
			ERR_ALLOC_FAILED;
			return -4;
		}
		// add the RR to the RRSet
		if (ldns_rr_list_push_rr(rrset, rr) != true) {
			return -5;
		}
		// insert the rrset into the node
		int res = skip_insert(node->rrsets, (void *)ldns_rr_get_type(rr),
							  (void *)rrset, NULL);
		assert(res != 2 && res != -2);
		// if no owner yet and successfuly inserted
		if (node->owner == NULL && res == 0) {
			// set the owner
			node->owner = ldns_rdf_clone(ldns_rr_owner(rr));
		}
		return res;
	}

	return 0;
}

/*----------------------------------------------------------------------------*/

int zn_add_rrset( zn_node *node, ldns_rr_list *rrset )
{
	assert(ldns_is_rrset(rrset));
	// here we do not have to allocate anything even if the RRSet is not in
	// the list, so can use the shortcut (see comment in zn_add_rr()).
	int res = skip_insert(node->rrsets, (void *)ldns_rr_list_type(rrset),
					   (void *)rrset, zn_merge_values);

	// if the node did not have any owner and insert successful, set the owner
	if (node->owner == NULL && res == 0) {
		node->owner = ldns_rdf_clone(ldns_rr_list_owner(rrset));
	}

	return res;
}

/*----------------------------------------------------------------------------*/

const ldns_rr_list *zn_find_rrset( const zn_node *node, ldns_rr_type type )
{
	ldns_rr_list *rrset = skip_find(node->rrsets, (void *)type);

	assert(rrset == NULL || ldns_is_rrset(rrset));
	assert(rrset == NULL || ldns_rr_list_type(rrset) == type);

	return rrset;
}

/*----------------------------------------------------------------------------*/

void zn_destroy( zn_node **node )
{
	skip_destroy_list((*node)->rrsets, NULL, zn_destroy_value);
	ldns_rdf_deep_free((*node)->owner);
    free(*node);
    *node = NULL;
}

/*----------------------------------------------------------------------------*/

void zn_destructor( void *item )
{
    zn_node *node = (zn_node *)item;
    zn_destroy(&node);
}
