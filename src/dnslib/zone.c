#include <stdlib.h>
#include <assert.h>

#include "zone.h"
#include "common.h"
#include "node.h"
#include "dname.h"
#include "tree.h"
#include "consts.h"
#include "descriptor.h"

/*----------------------------------------------------------------------------*/
/* Non-API functions                                                          */
/*----------------------------------------------------------------------------*/

// AVL tree functions
TREE_DEFINE(dnslib_node, avl);

/*----------------------------------------------------------------------------*/

int dnslib_zone_check_node(const dnslib_zone_t *zone, const dnslib_node_t *node)
{
	if (zone == NULL || node == NULL) {
		return -1;
	}

	// assert or just check??
	assert(zone->apex != NULL);

	if (!dnslib_dname_is_subdomain(node->owner, zone->apex->owner)) {
		char *node_owner = dnslib_dname_to_str(node->owner);
		char *apex_owner = dnslib_dname_to_str(zone->apex->owner);
		log_error("Trying to insert foreign node to a zone. "
			  "Node owner: %s, zone apex: %s\n",
			  node_owner, apex_owner);
		free(node_owner);
		free(apex_owner);
		return -2;
	}
	return 0;
}

/*----------------------------------------------------------------------------*/

void dnslib_zone_destroy_node_rrsets_from_tree(dnslib_node_t *node, void *data)
{
	UNUSED(data);
	dnslib_node_free_rrsets(node);
}

/*----------------------------------------------------------------------------*/

void dnslib_zone_destroy_node_owner_from_tree(dnslib_node_t *node, void *data)
{
	UNUSED(data);
	dnslib_node_free(&node, 1);
}

/*----------------------------------------------------------------------------*/

void dnslib_zone_adjust_rdata_item(dnslib_rdata_t *rdata, dnslib_zone_t *zone,
                                   int pos)
{
	const dnslib_rdata_item_t *dname_item
		= dnslib_rdata_item(rdata, pos);

	if (dname_item != NULL) {
		dnslib_dname_t *dname = dname_item->dname;
		const dnslib_node_t *n = NULL;
		const dnslib_node_t *closest_encloser = NULL;

//		int exact = dnslib_zone_find_dname(zone, dname, &n,
//		                                   &closest_encloser);
		n = dnslib_zone_find_node(zone, dname);

		if (n == NULL) {
			return;
		}

//		assert(!exact || n == closest_encloser);

//		if (exact) {
			// just doble-check if the domain name is not already
			// adjusted
			if (n->owner == dname_item->dname) {
				return;
			}
			debug_dnslib_zone("Replacing dname %s by reference to "
			  "dname %s in zone.\n", dname->name, n->owner->name);

			dnslib_rdata_item_set_dname(rdata, pos, n->owner);
			dnslib_dname_free(&dname);
//		} else if (closest_encloser != NULL) {
//			debug_dnslib_zone("Saving closest encloser to RDATA.\n");
			// save pointer to the closest encloser
//			dnslib_rdata_item_t *item =
//				dnslib_rdata_get_item(rdata, pos);
//			assert(item->dname != NULL);
//			item->dname->node = (dnslib_node_t *)closest_encloser;
//		}
	}
}

/*----------------------------------------------------------------------------*/

void dnslib_zone_adjust_node(dnslib_node_t *node, dnslib_rr_type_t type,
                             dnslib_zone_t *zone)
{
	dnslib_rrset_t *rrset = dnslib_node_get_rrset(node, type);
	if (!rrset) {
		return;
	}

	dnslib_rrtype_descriptor_t *desc =
		dnslib_rrtype_descriptor_by_type(type);
	dnslib_rdata_t *rdata_first = dnslib_rrset_get_rdata(rrset);
	dnslib_rdata_t *rdata = rdata_first;

	if (rdata == NULL) {
		return;
	}

	while (rdata->next != rdata_first) {
		for (int i = 0; i < rdata->count; ++i) {
			if (desc->wireformat[i]
			    == DNSLIB_RDATA_WF_COMPRESSED_DNAME
			    || desc->wireformat[i]
			       == DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME
			    || desc->wireformat[i]
			       == DNSLIB_RDATA_WF_LITERAL_DNAME) {
				debug_dnslib_zone("Adjusting domain name at "
				  "position %d of RDATA of record with owner "
				  "%s and type %s.\n",
				  i, rrset->owner->name,
				  dnslib_rrtype_to_string(type));

				dnslib_zone_adjust_rdata_item(rdata, zone, i);
			}
		}
		rdata = rdata->next;
	}

	for (int i = 0; i < rdata->count; ++i) {
		if (desc->wireformat[i]
		    == DNSLIB_RDATA_WF_COMPRESSED_DNAME
		    || desc->wireformat[i]
		       == DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME
		    || desc->wireformat[i]
		       == DNSLIB_RDATA_WF_LITERAL_DNAME) {
			debug_dnslib_zone("Adjusting domain name at "
			  "position %d of RDATA of record with owner "
			  "%s and type %s.\n",
			  i, rrset->owner->name,
			  dnslib_rrtype_to_string(type));

			dnslib_zone_adjust_rdata_item(rdata, zone, i);
		}
	}

	// delegation point / non-authoritative node
	if (node->parent
	    && (dnslib_node_is_deleg_point(node->parent)
	        || dnslib_node_is_non_auth(node->parent))) {
		dnslib_node_set_non_auth(node);
	} else if (dnslib_node_rrset(node, DNSLIB_RRTYPE_NS) != NULL
		   && node != zone->apex) {
		dnslib_node_set_deleg_point(node);
	}
}

/*----------------------------------------------------------------------------*/

void dnslib_zone_adjust_node_in_tree(dnslib_node_t *node, void *data)
{
	assert(data != NULL);
	dnslib_zone_t *zone = (dnslib_zone_t *)data;

	for (int i = 0; i < DNSLIB_COMPRESSIBLE_TYPES; ++i) {
		dnslib_zone_adjust_node(node, dnslib_compressible_types[i],
		                        zone);
	}
}

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

dnslib_zone_t *dnslib_zone_new(dnslib_node_t *apex)
{
	if (apex == NULL) {
		return NULL;
	}

	dnslib_zone_t *zone = (dnslib_zone_t *)malloc(sizeof(dnslib_zone_t));
	if (zone == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	zone->apex = apex;
	zone->tree = malloc(sizeof(avl_tree_t));
	if (zone->tree == NULL) {
		ERR_ALLOC_FAILED;
		free(zone);
		return NULL;
	}
	zone->nsec3_nodes = malloc(sizeof(avl_tree_t));
	if (zone->nsec3_nodes == NULL) {
		ERR_ALLOC_FAILED;
		free(zone->tree);
		free(zone);
		return NULL;
	}

	TREE_INIT(zone->tree, dnslib_node_compare);
	TREE_INIT(zone->nsec3_nodes, dnslib_node_compare);

	// how to know if this is successfull??
	TREE_INSERT(zone->tree, dnslib_node, avl, apex);

	return zone;
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_add_node(dnslib_zone_t *zone, dnslib_node_t *node)
{
	int ret = 0;
	if ((ret = dnslib_zone_check_node(zone, node)) != 0) {
		return ret;
	}

	// add the node to the tree
	// how to know if this is successfull??
	TREE_INSERT(zone->tree, dnslib_node, avl, node);

	return 0;
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_add_nsec3_node(dnslib_zone_t *zone, dnslib_node_t *node)
{
	int ret = 0;
	if ((ret = dnslib_zone_check_node(zone, node)) != 0) {
		return ret;
	}

	// how to know if this is successfull??
	TREE_INSERT(zone->nsec3_nodes, dnslib_node, avl, node);

	return 0;
}

/*----------------------------------------------------------------------------*/

dnslib_node_t *dnslib_zone_get_node(const dnslib_zone_t *zone,
                                    const dnslib_dname_t *name)
{
	if (zone == NULL || name == NULL) {
		return NULL;
	}

	// create dummy node to use for lookup
	dnslib_node_t *tmp = dnslib_node_new((dnslib_dname_t *)name, NULL);
	dnslib_node_t *n = TREE_FIND(zone->tree, dnslib_node, avl, tmp);
	dnslib_node_free(&tmp, 0);

	return n;
}

/*----------------------------------------------------------------------------*/

dnslib_node_t *dnslib_zone_get_nsec3_node(const dnslib_zone_t *zone,
                                          const dnslib_dname_t *name)
{
	if (zone == NULL || name == NULL) {
		return NULL;
	}

	// create dummy node to use for lookup
	dnslib_node_t *tmp = dnslib_node_new((dnslib_dname_t *)name, NULL);
	dnslib_node_t *n = TREE_FIND(zone->nsec3_nodes, dnslib_node, avl, tmp);
	dnslib_node_free(&tmp, 0);

	return n;
}

/*----------------------------------------------------------------------------*/

const dnslib_node_t *dnslib_zone_find_node(const dnslib_zone_t *zone,
                                           const dnslib_dname_t *name)
{
	return dnslib_zone_get_node(zone, name);
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_find_dname(const dnslib_zone_t *zone,
                           const dnslib_dname_t *name,
                           const dnslib_node_t **node,
                           const dnslib_node_t **closest_encloser)
{
	assert(zone);
	assert(name);
	assert(node);
	assert(closest_encloser);

	dnslib_node_t *found = NULL;

DEBUG_DNSLIB_ZONE(
	char *name_str = dnslib_dname_to_str(name);
	char *zone_str = dnslib_dname_to_str(zone->apex->owner);
	debug_dnslib_zone("Searching for name %s in zone %s...\n",
			  name_str, zone_str);
	free(name_str);
	free(zone_str);
);

	if (!dnslib_dname_is_subdomain(name, zone->apex->owner)) {
		*node = NULL;
		*closest_encloser = NULL;
		return 0;
	}

	// create dummy node to use for lookup
	dnslib_node_t *tmp = dnslib_node_new((dnslib_dname_t *)name, NULL);
	int exact_match = TREE_FIND_LESS_EQUAL(
	                      zone->tree, dnslib_node, avl, tmp, &found);
	dnslib_node_free(&tmp, 0);

	*node = found;
	*closest_encloser = found;

DEBUG_DNSLIB_ZONE(
	char *name_str = (found) ? dnslib_dname_to_str(found->owner) : "(nil)";
	debug_dnslib_zone("Search function returned %d and node %s\n",
	                  exact_match, name_str);

	if (found) {
		free(name_str);
	}
);

	// there must be at least one node with domain name less or equal to
	// the searched name if the name belongs to the zone (the root)
	if (*node == NULL) {
		return -2;
	}

	if (!exact_match) {
		int matched_labels = dnslib_dname_matched_labels(
				(*closest_encloser)->owner, name);
		while (matched_labels
		       < dnslib_dname_label_count((*closest_encloser)->owner)) {
			(*closest_encloser) = (*closest_encloser)->parent;
			assert(*closest_encloser);
		}
	}

	return exact_match;
}

/*----------------------------------------------------------------------------*/

const dnslib_node_t *dnslib_zone_find_nsec3_node(const dnslib_zone_t *zone,
                                                 const dnslib_dname_t *name)
{
	return dnslib_zone_get_nsec3_node(zone, name);
}

/*----------------------------------------------------------------------------*/

const dnslib_node_t *dnslib_zone_apex(const dnslib_zone_t *zone)
{
	return zone->apex;
}

/*----------------------------------------------------------------------------*/

void dnslib_zone_adjust_dnames(dnslib_zone_t *zone)
{
	TREE_FORWARD_APPLY(zone->tree, dnslib_node, avl,
	                   dnslib_zone_adjust_node_in_tree, zone);
}

/*----------------------------------------------------------------------------*/

void dnslib_zone_tree_apply_postorder(dnslib_zone_t *zone,
                              void (*function)(dnslib_node_t *node, void *data),
                              void *data)
{
	if (zone == NULL) {
		return;
	}

	TREE_POST_ORDER_APPLY(zone->tree, dnslib_node, avl, function, data);
}

/*----------------------------------------------------------------------------*/

void dnslib_zone_tree_apply_inorder(dnslib_zone_t *zone,
                              void (*function)(dnslib_node_t *node, void *data),
                              void *data)
{
	if (zone == NULL) {
		return;
	}

	TREE_FORWARD_APPLY(zone->tree, dnslib_node, avl, function, data);
}

/*----------------------------------------------------------------------------*/

void dnslib_zone_tree_apply_inorder_reverse(dnslib_zone_t *zone,
                              void (*function)(dnslib_node_t *node, void *data),
                              void *data)
{
	if (zone == NULL) {
		return;
	}

	TREE_REVERSE_APPLY(zone->tree, dnslib_node, avl, function, data);
}

/*----------------------------------------------------------------------------*/

void dnslib_zone_nsec3_apply_postorder(dnslib_zone_t *zone,
                              void (*function)(dnslib_node_t *node, void *data),
                              void *data)
{
	if (zone == NULL) {
		return;
	}

	TREE_POST_ORDER_APPLY(zone->nsec3_nodes, dnslib_node, avl, function,
	                      data);
}

/*----------------------------------------------------------------------------*/

void dnslib_zone_nsec3_apply_inorder(dnslib_zone_t *zone,
                              void (*function)(dnslib_node_t *node, void *data),
                              void *data)
{
	if (zone == NULL) {
		return;
	}

	TREE_FORWARD_APPLY(zone->nsec3_nodes, dnslib_node, avl, function, data);
}

/*----------------------------------------------------------------------------*/

void dnslib_zone_nsec3_apply_inorder_reverse(dnslib_zone_t *zone,
                              void (*function)(dnslib_node_t *node, void *data),
                              void *data)
{
	if (zone == NULL) {
		return;
	}

	TREE_REVERSE_APPLY(zone->nsec3_nodes, dnslib_node, avl, function, data);
}

/*----------------------------------------------------------------------------*/

void dnslib_zone_free(dnslib_zone_t **zone)
{
	if (zone == NULL || *zone == NULL) {
		return;
	}

	free((*zone)->tree);
	free((*zone)->nsec3_nodes);

	free(*zone);
	*zone = NULL;
}

/*----------------------------------------------------------------------------*/

void dnslib_zone_deep_free(dnslib_zone_t **zone)
{
	if (zone == NULL || *zone == NULL) {
		return;
	}

	/* has to go through zone twice, rdata may contain references to node
	   owners earlier in the zone which may be already freed */

	TREE_POST_ORDER_APPLY((*zone)->tree, dnslib_node, avl,
	                      dnslib_zone_destroy_node_rrsets_from_tree, NULL);

 	TREE_POST_ORDER_APPLY((*zone)->tree, dnslib_node, avl,
	                      dnslib_zone_destroy_node_owner_from_tree, NULL);

	TREE_POST_ORDER_APPLY((*zone)->nsec3_nodes, dnslib_node, avl,
	                      dnslib_zone_destroy_node_rrsets_from_tree, NULL);

	TREE_POST_ORDER_APPLY((*zone)->nsec3_nodes, dnslib_node, avl,
	                      dnslib_zone_destroy_node_owner_from_tree, NULL);

	free((*zone)->tree);
	free((*zone)->nsec3_nodes);

	free(*zone);
	*zone = NULL;
}
