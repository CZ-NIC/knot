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
static const uint8_t FLAGS_DELEG = 0x1;
static const uint8_t FLAGS_NONAUTH = 0x2;

/*----------------------------------------------------------------------------*/
/* Private functions          					                              */
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

static inline void zn_flags_set_delegation_point( uint8_t *flags )
{
	(*flags) |= FLAGS_DELEG;
}

/*----------------------------------------------------------------------------*/

static inline int zn_flags_is_delegation_point( uint8_t flags )
{
	return (flags & FLAGS_DELEG);
}

/*----------------------------------------------------------------------------*/

static inline void zn_flags_set_nonauth( uint8_t *flags )
{
	(*flags) |= FLAGS_NONAUTH;
}

/*----------------------------------------------------------------------------*/

static inline int zn_flags_is_nonauth( uint8_t flags )
{
	return (flags & FLAGS_NONAUTH);
}

/*----------------------------------------------------------------------------*/
/* Public functions          					                              */
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
	// not a CNAME
	node->ref.cname = NULL;
	// not a delegation point
	node->flags = 0;

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

ldns_rr_list *zn_find_rrset( const zn_node *node, ldns_rr_type type )
{
	ldns_rr_list *rrset = skip_find(node->rrsets, (void *)type);

	assert(rrset == NULL || ldns_is_rrset(rrset));
	assert(rrset == NULL || ldns_rr_list_type(rrset) == type);

	return rrset;
}

/*----------------------------------------------------------------------------*/

void zn_set_non_authoritative( zn_node *node )
{
	zn_flags_set_nonauth(&node->flags);
}

/*----------------------------------------------------------------------------*/

int zn_is_non_authoritative( const zn_node *node )
{
	return zn_flags_is_nonauth(node->flags);
}

/*----------------------------------------------------------------------------*/

void zn_set_delegation_point( zn_node *node )
{
	assert(node->ref.glues == NULL);
	node->ref.glues = ldns_rr_list_new();
	zn_flags_set_delegation_point(&node->flags);
}

/*----------------------------------------------------------------------------*/

int zn_is_delegation_point( const zn_node *node )
{
	assert((zn_flags_is_delegation_point(node->flags) == 0
			&& node->ref.glues == NULL)
		   || (zn_flags_is_delegation_point(node->flags) == 1
			   && node->ref.glues != NULL));
	return zn_flags_is_delegation_point(node->flags);
}

/*----------------------------------------------------------------------------*/

int zn_is_cname( const zn_node *node )
{
	return (zn_flags_is_delegation_point(node->flags) == 0
			 && node->ref.cname != NULL);
}

/*----------------------------------------------------------------------------*/

zn_node *zn_get_cname( const zn_node *node )
{
	assert(zn_flags_is_delegation_point(node->flags) == 0);
	return node->ref.cname;
}

/*----------------------------------------------------------------------------*/

int zn_push_glue( zn_node *node, ldns_rr_list *glue )
{
	assert((zn_flags_is_delegation_point(node->flags) == 1
			&& node->ref.glues != NULL));

	if (glue == NULL) {
		return 0;
	}

	int res = ldns_rr_list_push_rr_list(node->ref.glues, glue) - 1;
	if (res == 0) {
		// sort the glue RRs
		ldns_rr_list_sort(node->ref.glues);
	}
	return res;
}

/*----------------------------------------------------------------------------*/

ldns_rr_list *zn_get_glues( const zn_node *node )
{
	if (!zn_is_delegation_point(node)) {
		return NULL;
	}
	return node->ref.glues;
}

/*----------------------------------------------------------------------------*/

ldns_rr_list *zn_get_glue( const zn_node *node, ldns_rdf *owner,
						   ldns_rr_type type )
{
	assert(type == LDNS_RR_TYPE_A || type == LDNS_RR_TYPE_AAAA);

	if (!zn_is_delegation_point(node)) {
		return NULL;
	}

	ldns_rr_list *glue = ldns_rr_list_new();

	ldns_rr *rr;
	int i = -1;
	int cmp;
	do {
		++i;
		rr = ldns_rr_list_rr(node->ref.glues, i);
	} while ((cmp = ldns_dname_compare(ldns_rr_owner(rr), owner)) < 0);

	// found owner
	while (cmp == 0 && ldns_rr_get_type(rr) != type) {
		++i;
		rr = ldns_rr_list_rr(node->ref.glues, i);
		cmp = ldns_dname_compare(ldns_rr_owner(rr), owner);
	}

	// found owner & type
	while (cmp == 0 && ldns_rr_get_type(rr) == type) {
		ldns_rr_list_push_rr(glue, rr);
		++i;
		rr = ldns_rr_list_rr(node->ref.glues, i);
		cmp = ldns_dname_compare(ldns_rr_owner(rr), owner);
	}

	return glue;
}

/*----------------------------------------------------------------------------*/

void zn_destroy( zn_node **node )
{
	skip_destroy_list((*node)->rrsets, NULL, zn_destroy_value);
	ldns_rdf_deep_free((*node)->owner);
	if (zn_is_delegation_point(*node)) {
		ldns_rr_list_free((*node)->ref.glues);
	}
    free(*node);
    *node = NULL;
}

/*----------------------------------------------------------------------------*/

void zn_destructor( void *item )
{
    zn_node *node = (zn_node *)item;
    zn_destroy(&node);
}
