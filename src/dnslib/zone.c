#include <stdlib.h>
#include <assert.h>

#include "zone.h"
#include "common.h"
#include "node.h"
#include "dname.h"
#include "tree.h"
#include "consts.h"
#include "descriptor.h"
#include "cuckoo-hash-table.h"
#include "nsec3.h"
#include "base32.h"

/*----------------------------------------------------------------------------*/
/* Non-API functions                                                          */
/*----------------------------------------------------------------------------*/

// AVL tree functions
TREE_DEFINE(dnslib_node, avl);

/*----------------------------------------------------------------------------*/

static int dnslib_zone_check_node(const dnslib_zone_t *zone,
                                  const dnslib_node_t *node)
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

static void dnslib_zone_destroy_node_rrsets_from_tree(dnslib_node_t *node,
                                                      void *data)
{
	UNUSED(data);
	dnslib_node_free_rrsets(node);
}

/*----------------------------------------------------------------------------*/

static void dnslib_zone_destroy_node_owner_from_tree(dnslib_node_t *node,
                                                     void *data)
{
	UNUSED(data);
	dnslib_node_free(&node, 1);
}

/*----------------------------------------------------------------------------*/

static void dnslib_zone_adjust_rdata_item(dnslib_rdata_t *rdata,
                                          dnslib_zone_t *zone, int pos)
{
	const dnslib_rdata_item_t *dname_item
		= dnslib_rdata_item(rdata, pos);

	if (dname_item != NULL) {
		dnslib_dname_t *dname = dname_item->dname;
		const dnslib_node_t *n = NULL;
//		const dnslib_node_t *closest_encloser = NULL;

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

static void dnslib_zone_adjust_type(dnslib_node_t *node, dnslib_zone_t *zone,
                                    dnslib_rr_type_t type)
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
}

/*----------------------------------------------------------------------------*/

static void dnslib_zone_adjust_node(dnslib_node_t *node, dnslib_zone_t *zone)
{

DEBUG_DNSLIB_ZONE(
	char *name = dnslib_dname_to_str(node->owner);
	debug_dnslib_zone("----- Adjusting node %s -----\n", name);
	free(name);
);

	// adjust domain names
	for (int i = 0; i < DNSLIB_COMPRESSIBLE_TYPES; ++i) {
		dnslib_zone_adjust_type(node, zone,
		                        dnslib_compressible_types[i]);
	}
DEBUG_DNSLIB_ZONE(
	if (node->parent) {
		char *name = dnslib_dname_to_str(node->parent->owner);
		debug_dnslib_zone("Parent: %s\n", name);
		debug_dnslib_zone("Parent is delegation point: %s\n",
		       dnslib_node_is_deleg_point(node->parent) ? "yes" : "no");
		debug_dnslib_zone("Parent is non-authoritative: %s\n",
		       dnslib_node_is_non_auth(node->parent) ? "yes" : "no");
		free(name);
	} else {
		debug_dnslib_zone("No parent!\n");
	}
);
	// delegation point / non-authoritative node
	if (node->parent
	    && (dnslib_node_is_deleg_point(node->parent)
	        || dnslib_node_is_non_auth(node->parent))) {
		dnslib_node_set_non_auth(node);
	} else if (dnslib_node_rrset(node, DNSLIB_RRTYPE_NS) != NULL
		   && node != zone->apex) {
		dnslib_node_set_deleg_point(node);
	}

	// NSEC3 node
	assert(node->owner);
	const dnslib_node_t *prev;
	node->nsec3_node = NULL;
	(void)dnslib_zone_find_nsec3_for_name(zone, node->owner,
	                                      &node->nsec3_node, &prev);

	debug_dnslib_zone("Set flags to the node: \n");
	debug_dnslib_zone("Delegation point: %s\n",
	       dnslib_node_is_deleg_point(node) ? "yes" : "no");
	debug_dnslib_zone("Non-authoritative: %s\n",
	       dnslib_node_is_non_auth(node) ? "yes" : "no");
}

/*----------------------------------------------------------------------------*/

static void dnslib_zone_adjust_node_in_tree(dnslib_node_t *node, void *data)
{
	assert(data != NULL);
	dnslib_zone_t *zone = (dnslib_zone_t *)data;

	dnslib_zone_adjust_node(node, zone);
}

/*----------------------------------------------------------------------------*/

static dnslib_dname_t *dnslib_zone_nsec3_name(const dnslib_zone_t *zone,
                                              const dnslib_dname_t *name)
{
	const dnslib_nsec3_params_t *nsec3_params =
		dnslib_zone_nsec3params(zone);

	if (nsec3_params == NULL) {
DEBUG_DNSLIB_ZONE(
		char *n = dnslib_dname_to_str(zone->apex->owner);
		debug_dnslib_zone("No NSEC3PARAMS for zone %s.\n", n);
		free(n);
);
		return NULL;
	}

	uint8_t *hashed_name = NULL;
	size_t hash_size = 0;

DEBUG_DNSLIB_ZONE(
	char *n = dnslib_dname_to_str(name);
	debug_dnslib_zone("Hashing name %s.\n", n);
	free(n);
);

	int res = dnslib_nsec3_sha1(nsec3_params, dnslib_dname_name(name),
	                            dnslib_dname_size(name), &hashed_name,
	                            &hash_size);

	if (res != 0) {
		char *n = dnslib_dname_to_str(name);
		log_warning("Error while hashing name %s.\n", n);
		free(n);
		return NULL;
	}

	debug_dnslib_zone("Hash: %.*s\n", hash_size, hashed_name);

	char *name_b32 = NULL;
	size_t size = base32_encode_alloc((char *)hashed_name, hash_size,
	                                  &name_b32);

	if (size == 0) {
		char *n = dnslib_dname_to_str(name);
		log_warning("Error while encoding hashed name %s to base32.\n",
			    n);
		free(n);
		return NULL;
	}

	assert(name_b32 != NULL);

	debug_dnslib_zone("Base32-encoded hash: %s\n", name_b32);

	dnslib_dname_t *nsec3_name =
		dnslib_dname_new_from_wire((uint8_t *)name_b32, size + 1, NULL);

	free(name_b32);

	if (nsec3_name == NULL) {
		log_warning("Error while creating domain name for hashed name"
		            "%.*s\n", (size_t)hash_size, hashed_name);
		return NULL;
	}

	assert(zone->apex->owner != NULL);
	dnslib_dname_t *ret = dnslib_dname_cat(nsec3_name, zone->apex->owner);

	if (ret == NULL) {
		log_warning("Error while creating NSEC3 domain name for hashed "
		            "name %.*s\n", (size_t)hash_size, hashed_name);
		return NULL;
	}

	assert(ret == nsec3_name);

	return nsec3_name;
}

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

dnslib_zone_t *dnslib_zone_new(dnslib_node_t *apex, uint node_count)
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

	zone->node_count = node_count;

	TREE_INIT(zone->tree, dnslib_node_compare);
	TREE_INIT(zone->nsec3_nodes, dnslib_node_compare);

	// how to know if this is successfull??
	TREE_INSERT(zone->tree, dnslib_node, avl, apex);

#ifdef USE_HASH_TABLE
	if (zone->node_count > 0) {
		zone->table = ck_create_table(zone->node_count);
		if (zone->table == NULL) {
			free(zone->tree);
			free(zone->nsec3_nodes);
			free(zone);
			return NULL;
		}

		// insert the apex into the hash table
		if (ck_insert_item(zone->table, (const char *)apex->owner->name,
		                   apex->owner->size, (void *)apex) != 0) {
			ck_destroy_table(&zone->table, NULL, 0);
			free(zone->tree);
			free(zone->nsec3_nodes);
			free(zone);
			return NULL;
		}
	} else {
		zone->table = NULL;
	}
#endif
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

#ifdef USE_HASH_TABLE
	// add the node also to the hash table if authoritative, or deleg. point
	if (zone->table != NULL
	    && ck_insert_item(zone->table, (const char *)node->owner->name,
	                   node->owner->size, (void *)node) != 0) {
		log_error("Error inserting node into hash table!\n");
		return -3;
	}
#endif

	debug_dnslib_zone("Inserted node %p with owner: %s (labels: %d), "
	                  "pointer: %p\n", node,
	                  dnslib_dname_to_str(node->owner),
	                  dnslib_dname_label_count(node->owner), node->owner);

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
                           const dnslib_node_t **closest_encloser,
                           const dnslib_node_t **previous)
{
	if (zone == NULL || name == NULL || node == NULL
	    || closest_encloser == NULL || previous == NULL) {
		return DNSLIB_ZONE_NAME_ERROR;
	}

	dnslib_node_t *found = NULL;
	dnslib_node_t *prev = NULL;

DEBUG_DNSLIB_ZONE(
	char *name_str = dnslib_dname_to_str(name);
	char *zone_str = dnslib_dname_to_str(zone->apex->owner);
	debug_dnslib_zone("Searching for name %s in zone %s...\n",
			  name_str, zone_str);
	free(name_str);
	free(zone_str);
);

	if (dnslib_dname_compare(name, zone->apex->owner) == 0) {
		*node = zone->apex;
		*closest_encloser = *node;
		return DNSLIB_ZONE_NAME_FOUND;
	}

	if (!dnslib_dname_is_subdomain(name, zone->apex->owner)) {
		*node = NULL;
		*closest_encloser = NULL;
		return DNSLIB_ZONE_NAME_NOT_IN_ZONE;
	}

	// create dummy node to use for lookup
	dnslib_node_t *tmp = dnslib_node_new((dnslib_dname_t *)name, NULL);
	int exact_match = TREE_FIND_LESS_EQUAL(
	                   zone->tree, dnslib_node, avl, tmp, &found, &prev);
	dnslib_node_free(&tmp, 0);

	*node = found;
	*closest_encloser = found;

	if (prev == NULL) {
		// either the returned node is the root of the tree, or it is
		// the leftmost node in the tree; in both cases node was found
		// set the previous node of the found node
		assert(exact_match);
		assert(found != NULL);
		*previous = dnslib_node_previous(found);
	} else {
		// otherwise check if the previous node is not an empty
		// non-terminal
		*previous = (dnslib_node_rrset_count(prev) == 0)
		            ? dnslib_node_previous(prev)
		            : prev;
	}

DEBUG_DNSLIB_ZONE(
	char *name_str = (found) ? dnslib_dname_to_str(found->owner) : "(nil)";
	char *name_str2 = (prev != NULL) ? dnslib_dname_to_str(prev->owner)
	                                 : "(nil)";
	debug_dnslib_zone("Search function returned %d, node %s and prev: %s\n",
	                  exact_match, name_str, name_str2);

	if (found) {
		free(name_str);
	}
	if (prev != NULL) {
		free(name_str2);
	}
);

	// there must be at least one node with domain name less or equal to
	// the searched name if the name belongs to the zone (the root)
	if (*node == NULL) {
		return DNSLIB_ZONE_NAME_NOT_IN_ZONE;
	}

	// TODO: this could be replaced by saving pointer to closest encloser
	//       in node

	if (!exact_match) {
		int matched_labels = dnslib_dname_matched_labels(
				(*closest_encloser)->owner, name);
		while (matched_labels
		       < dnslib_dname_label_count((*closest_encloser)->owner)) {
			(*closest_encloser) = (*closest_encloser)->parent;
			assert(*closest_encloser);
		}
	}

//	if (dnslib_node_is_non_auth(*closest_encloser)) {
//		while (dnslib_node_is_non_auth(*closest_encloser)) {
//			(*closest_encloser) = (*closest_encloser)->parent;
//			assert(*closest_encloser);
//		}
//	}

	debug_dnslib_zone("find_dname() returning %d\n", exact_match);

	return (exact_match)
	       ? DNSLIB_ZONE_NAME_FOUND
	       : DNSLIB_ZONE_NAME_NOT_FOUND;
}

/*----------------------------------------------------------------------------*/
#ifdef USE_HASH_TABLE
int dnslib_zone_find_dname_hash(const dnslib_zone_t *zone,
                                const dnslib_dname_t *name,
                                const dnslib_node_t **node,
                                const dnslib_node_t **closest_encloser)
{
	assert(zone);
	assert(name);
	assert(node);
	assert(closest_encloser);

DEBUG_DNSLIB_ZONE(
	char *name_str = dnslib_dname_to_str(name);
	char *zone_str = dnslib_dname_to_str(zone->apex->owner);
	debug_dnslib_zone("Searching for name %s in zone %s...\n",
			  name_str, zone_str);
	free(name_str);
	free(zone_str);
);

	if (dnslib_dname_compare(name, zone->apex->owner) == 0) {
		*node = zone->apex;
		*closest_encloser = *node;
		return DNSLIB_ZONE_NAME_FOUND;
	}

	if (!dnslib_dname_is_subdomain(name, zone->apex->owner)) {
		*node = NULL;
		*closest_encloser = NULL;
		return DNSLIB_ZONE_NAME_NOT_IN_ZONE;
	}

	const ck_hash_table_item_t *item = ck_find_item(zone->table,
	                                               (const char *)name->name,
	                                               name->size);

	if (item != NULL) {
		*node = (const dnslib_node_t *)item->value;
		*closest_encloser = *node;

		debug_dnslib_zone("Found node in hash table: %p (owner %p, "
		                  "labels: %d)\n", *node, (*node)->owner,
		                  dnslib_dname_label_count((*node)->owner));
		assert(*node != NULL);
		assert(*closest_encloser != NULL);
		return DNSLIB_ZONE_NAME_FOUND;
	}

	*node = NULL;

	// chop leftmost labels until some node is found
	// copy the name for chopping
	dnslib_dname_t *name_copy = dnslib_dname_copy(name);

	while (item == NULL) {
		dnslib_dname_left_chop_no_copy(name_copy);
		assert(name_copy->label_count > 0);  // not satisfied in root zone!!

		item = ck_find_item(zone->table, (const char *)name_copy->name,
		                    name_copy->size);
	}

	dnslib_dname_free(&name_copy);

	assert(item != NULL);

	*closest_encloser = (const dnslib_node_t *)item->value;

	return DNSLIB_ZONE_NAME_NOT_FOUND;
}
#endif
/*----------------------------------------------------------------------------*/

const dnslib_node_t *dnslib_zone_find_nsec3_node(const dnslib_zone_t *zone,
                                                 const dnslib_dname_t *name)
{
	return dnslib_zone_get_nsec3_node(zone, name);
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_find_nsec3_for_name(const dnslib_zone_t *zone,
                                    const dnslib_dname_t *name,
                                    const dnslib_node_t **nsec3_node,
                                    const dnslib_node_t **nsec3_previous)
{
	if (zone == NULL || name == NULL
	    || nsec3_node == NULL || nsec3_previous == NULL) {
		return DNSLIB_ZONE_NAME_ERROR;
	}

	dnslib_dname_t *nsec3_name = dnslib_zone_nsec3_name(zone, name);

DEBUG_DNSLIB_ZONE(
	char *n = dnslib_dname_to_str(nsec3_name);
	debug_dnslib_zone("NSEC3 node name: %s.\n", n);
	free(n);
);

	dnslib_node_t *found, *prev;

	// create dummy node to use for lookup
	dnslib_node_t *tmp = dnslib_node_new(nsec3_name, NULL);
	int exact_match = TREE_FIND_LESS_EQUAL(zone->nsec3_nodes, dnslib_node, \
	                   avl, tmp, &found, &prev);
	dnslib_node_free(&tmp, 0);

DEBUG_DNSLIB_ZONE(
	if (found) {
		char *n = dnslib_dname_to_str(found->owner);
		debug_dnslib_zone("Found NSEC3 node: %s.\n", n);
		free(n);
	} else {
		debug_dnslib_zone("Found no NSEC3 node.\n");
	}

	if (prev) {
		char *n = dnslib_dname_to_str(prev>owner);
		debug_dnslib_zone("Found previous NSEC3 node: %s.\n", n);
		free(n);
	} else {
		debug_dnslib_zone("Found no previous NSEC3 node.\n");
	}
);
	*nsec3_node = found;

	if (prev == NULL) {
		// either the returned node is the root of the tree, or it is
		// the leftmost node in the tree; in both cases node was found
		// set the previous node of the found node
		assert(exact_match);
		assert(*nsec3_node != NULL);
		*nsec3_previous = dnslib_node_previous(*nsec3_previous);
	} else {
		*nsec3_previous = prev;
	}

	debug_dnslib_zone("find_nsec3_for_name() returning %d\n", exact_match);

	return (exact_match)
	       ? DNSLIB_ZONE_NAME_FOUND
	       : DNSLIB_ZONE_NAME_NOT_FOUND;
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

void dnslib_zone_load_nsec3param(dnslib_zone_t *zone)
{
	assert(zone);
	assert(zone->apex);
	const dnslib_rrset_t *rrset = dnslib_node_rrset(zone->apex,
	                                              DNSLIB_RRTYPE_NSEC3PARAM);

	if (rrset != NULL) {
		dnslib_nsec3_params_from_wire(&zone->nsec3_params, rrset);
	} else {
		memset(&zone->nsec3_params, 0, sizeof(dnslib_nsec3_params_t));
	}
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_nsec3_enabled(const dnslib_zone_t *zone)
{
	return (zone->nsec3_params.algorithm != 0);
}

/*----------------------------------------------------------------------------*/

const dnslib_nsec3_params_t *dnslib_zone_nsec3params(const dnslib_zone_t *zone)
{
	if (dnslib_zone_nsec3_enabled(zone)) {
		return &zone->nsec3_params;
	} else {
		return NULL;
	}
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

#ifdef USE_HASH_TABLE
	if ((*zone)->table != NULL) {
		ck_destroy_table(&(*zone)->table, NULL, 0);
	}
#endif

	free(*zone);
	*zone = NULL;
}

/*----------------------------------------------------------------------------*/

void dnslib_zone_deep_free(dnslib_zone_t **zone)
{
	if (zone == NULL || *zone == NULL) {
		return;
	}
#ifdef USE_HASH_TABLE
	if ((*zone)->table != NULL) {
		ck_destroy_table(&(*zone)->table, NULL, 0);
	}
#endif
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
