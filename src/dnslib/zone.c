#include <config.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include <urcu.h>

#include "dnslib/dnslib-common.h"
#include "dnslib/zone.h"
#include "dnslib/node.h"
#include "dnslib/dname.h"
#include "dnslib/consts.h"
#include "dnslib/descriptor.h"
#include "dnslib/nsec3.h"
#include "dnslib/error.h"
#include "dnslib/debug.h"
#include "dnslib/utils.h"
#include "common/tree.h"
#include "common/base32hex.h"
#include "dnslib/hash/cuckoo-hash-table.h"
#include "dnslib/zone-contents.h"

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

dnslib_zone_t *dnslib_zone_new(dnslib_node_t *apex, uint node_count,
                               int use_domain_table)
{
	debug_dnslib_zone("Creating new zone!\n");
	if (apex == NULL) {
		return NULL;
	}

	dnslib_zone_t *zone = (dnslib_zone_t *)calloc(1, sizeof(dnslib_zone_t));
	if (zone == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	// save the zone name
	debug_dnslib_zone("Copying zone name.\n");
	zone->name = dnslib_dname_copy(dnslib_node_owner(apex));
	if (zone->name == NULL) {
		ERR_ALLOC_FAILED;
		free(zone);
		return NULL;
	}

	debug_dnslib_zone("Creating zone contents.\n");
	zone->contents = dnslib_zone_contents_new(apex, node_count,
	                                          use_domain_table);
	if (zone->contents == NULL) {
		dnslib_dname_free(&zone->name);
		free(zone);
		return NULL;
	}

	debug_dnslib_zone("Initializing zone data.\n");
	/* Initialize data. */
	zone->data = 0;
	zone->dtor = 0;

	return zone;
//	dnslib_zone_contents_t *contents = (dnslib_zone_contents_t *)
//	                              calloc(1, sizeof(dnslib_zone_contents_t));
//	if (contents == NULL) {
//		ERR_ALLOC_FAILED;
//		free(zone);
//		dnslib_dname_free(&zone->name);
//		return NULL;
//	}

//	contents->apex = apex;
////	zone->tree = malloc(sizeof(avl_tree_t));
////	if (zone->tree == NULL) {
////		ERR_ALLOC_FAILED;
////		goto cleanup;
////	}
////	zone->nsec3_nodes = malloc(sizeof(avl_tree_t));
////	if (zone->nsec3_nodes == NULL) {
////		ERR_ALLOC_FAILED;
////		goto cleanup;
////	}

//	debug_dnslib_zone("Creating tree for normal nodes.\n");
//	contents->nodes = malloc(sizeof(dnslib_zone_tree_t));
//	if (contents->nodes == NULL) {
//		ERR_ALLOC_FAILED;
//		goto cleanup;
//	}

//	debug_dnslib_zone("Creating tree for NSEC3 nodes.\n");
//	contents->nsec3_nodes = malloc(sizeof(dnslib_zone_tree_t));
//	if (contents->nsec3_nodes == NULL) {
//		ERR_ALLOC_FAILED;
//		goto cleanup;
//	}

//	if (use_domain_table) {
//		debug_dnslib_zone("Creating domain name table.\n");
//		contents->dname_table = dnslib_dname_table_new();
//		if (contents->dname_table == NULL) {
//			ERR_ALLOC_FAILED;
//			goto cleanup;
//		}
//	} else {
//		contents->dname_table = NULL;
//	}

//	debug_dnslib_zone("Initializing zone data.\n");
//	/* Initialize data. */
//	zone->data = 0;
//	zone->dtor = 0;

//	contents->node_count = node_count;

//	/* Initialize NSEC3 params */
//	debug_dnslib_zone("Initializing NSEC3 parameters.\n");
//	contents->nsec3_params.algorithm = 0;
//	contents->nsec3_params.flags = 0;
//	contents->nsec3_params.iterations = 0;
//	contents->nsec3_params.salt_length = 0;
//	contents->nsec3_params.salt = NULL;

////	TREE_INIT(zone->tree, dnslib_node_compare);
////	TREE_INIT(zone->nsec3_nodes, dnslib_node_compare);

//	debug_dnslib_zone("Initializing zone trees.\n");
//	if (dnslib_zone_tree_init(contents->nodes) != DNSLIB_EOK
//	    || dnslib_zone_tree_init(contents->nsec3_nodes) != DNSLIB_EOK) {
//		goto cleanup;
//	}

//	// how to know if this is successfull??
////	TREE_INSERT(zone->tree, dnslib_node, avl, apex);

//	debug_dnslib_zone("Inserting apex into the zone tree.\n");
//	if (dnslib_zone_tree_insert(contents->nodes, apex) != DNSLIB_EOK) {
//		debug_dnslib_zone("Failed to insert apex to the zone tree.\n");
//		goto cleanup;
//	}

//#ifdef USE_HASH_TABLE
//	if (contents->node_count > 0) {
//		debug_dnslib_zone("Creating hash table.\n");
//		contents->table = ck_create_table(contents->node_count);
//		if (contents->table == NULL) {
//			goto cleanup;
//		}

//		// insert the apex into the hash table
//		debug_dnslib_zone("Inserting apex into the hash table.\n");
//		if (ck_insert_item(contents->table,
//		                   (const char *)dnslib_dname_name(
//		                                       dnslib_node_owner(apex)),
//		                   dnslib_dname_size(dnslib_node_owner(apex)),
//		                   (void *)apex) != 0) {
//			ck_destroy_table(&contents->table, NULL, 0);
//			goto cleanup;
//		}
//	} else {
//		contents->table = NULL;
//	}
//#endif

//	// insert names from the apex to the domain table
//	if (use_domain_table) {
//		debug_dnslib_zone("Inserting names from apex to table.\n");
//		int rc = dnslib_zone_dnames_from_node_to_table(
//		             contents->dname_table, apex);
//		if (rc != DNSLIB_EOK) {
//			ck_destroy_table(&contents->table, NULL, 0);
//			goto cleanup;
//		}
//	}

//	debug_dnslib_zone("Saving zone contents.\n");
//	zone->contents = contents;

//	return zone;

//cleanup:
//	debug_dnslib_zone("Cleaning up.\n");
//	free(contents->dname_table);
//	free(contents->nodes);
//	free(contents->nsec3_nodes);
//	free(contents);
//	dnslib_dname_free(&zone->name);
//	free(zone);
//	return NULL;
}

/*----------------------------------------------------------------------------*/

dnslib_zone_contents_t *dnslib_zone_get_contents(
	const dnslib_zone_t *zone)
{
	if (zone == NULL) {
		return NULL;
	}

	return rcu_dereference(zone->contents);
}

/*----------------------------------------------------------------------------*/

const dnslib_zone_contents_t *dnslib_zone_contents(
	const dnslib_zone_t *zone)
{
	if (zone == NULL) {
		return NULL;
	}

	return rcu_dereference(zone->contents);
}

/*----------------------------------------------------------------------------*/

time_t dnslib_zone_version(const dnslib_zone_t *zone)
{
	if (zone == NULL) {
		return DNSLIB_EBADARG;
	}

	return dnslib_zone_contents_version(zone->contents);
//	return zone->contents->version;
}

/*----------------------------------------------------------------------------*/

void dnslib_zone_set_version(dnslib_zone_t *zone, time_t version)
{
	if (zone == NULL) {
		return;
	}

	dnslib_zone_contents_set_version(zone->contents, version);
//	zone->contents->version = version;
}

/*----------------------------------------------------------------------------*/

short dnslib_zone_generation(const dnslib_zone_t *zone)
{
	if (zone == NULL) {
		return DNSLIB_EBADARG;
	}

	return dnslib_zone_contents_generation(zone->contents);
//	return zone->contents->generation;
}

/*----------------------------------------------------------------------------*/

void dnslib_zone_switch_generation(dnslib_zone_t *zone)
{
	if (zone == NULL) {
		return;
	}

	dnslib_zone_contents_switch_generation(zone->contents);
//	zone->contents->generation = 1 - zone->contents->generation;
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_add_node(dnslib_zone_t *zone, dnslib_node_t *node,
                         int create_parents, int use_domain_table)
{
	if (zone == NULL) {
		return DNSLIB_EBADARG;
	}

	dnslib_node_set_zone(node, zone);

	return dnslib_zone_contents_add_node(zone->contents, node,
	                                     create_parents, 0,
	                                     use_domain_table);
//	if (zone == NULL || node == NULL || zone->contents == NULL) {
//		return DNSLIB_EBADARG;
//	}

//	int ret = 0;
//	if ((ret = dnslib_zone_check_node(zone->contents, node)) != 0) {
//		return ret;
//	}

//	ret = dnslib_zone_tree_insert(zone->contents->nodes, node);
//	if (ret != DNSLIB_EOK) {
//		debug_dnslib_zone("Failed to insert node into zone tree.\n");
//		return ret;
//	}

//#ifdef USE_HASH_TABLE
//DEBUG_DNSLIB_ZONE(
//	char *name = dnslib_dname_to_str(node->owner);
//	debug_dnslib_zone("Adding node with owner %s to hash table.\n", name);
//	free(name);
//);
//	//assert(zone->table != NULL);
//	// add the node also to the hash table if authoritative, or deleg. point
//	if (zone->contents->table != NULL
//	    && ck_insert_item(zone->contents->table,
//	                      (const char *)node->owner->name,
//	                      node->owner->size, (void *)node) != 0) {
//		debug_dnslib_zone("Error inserting node into hash table!\n");
//		/*! \todo Remove the node from the tree. */
//		return DNSLIB_EHASH;
//	}
//#endif
//	assert(dnslib_zone_find_node(zone, node->owner));

//	if (use_domain_table) {
//		ret = dnslib_zone_dnames_from_node_to_table(
//		          zone->contents->dname_table, node);
//		if (ret != DNSLIB_EOK) {
//			/*! \todo Remove the node from the tree and hash table. */
//			debug_dnslib_zone("Failed to add dnames into table.\n");
//			return ret;
//		}
//	}

//	if (!create_parents) {
//		return DNSLIB_EOK;
//	}

//	debug_dnslib_zone("Creating parents of the node.\n");

//	dnslib_dname_t *chopped =
//		dnslib_dname_left_chop(node->owner);
//	if (dnslib_dname_compare(zone->contents->apex->owner, chopped) == 0) {
//		debug_dnslib_zone("Zone apex is the parent.\n");
//		node->parent = zone->contents->apex;
//	} else {
//		dnslib_node_t *next_node;
//		while ((next_node
//		      = dnslib_zone_get_node(zone, chopped)) == NULL) {
//			/* Adding new dname to zone + add to table. */
//			debug_dnslib_zone("Creating new node.\n");
//			next_node = dnslib_node_new(chopped, NULL);
//			if (next_node == NULL) {
//				dnslib_dname_free(&chopped);
//				return DNSLIB_ENOMEM;
//			}
//			if (use_domain_table) {
//				ret = dnslib_zone_dnames_from_node_to_table(
//					zone->contents->dname_table, next_node);
//				if (ret != DNSLIB_EOK) {
//					return ret;
//				}
//			}
//			node->parent = next_node;

//			if (next_node->owner != chopped) {
//				assert(0);
//				/* Node owner was in RDATA */
//				chopped = next_node->owner;
//			}

//			assert(dnslib_zone_find_node(zone, chopped) == NULL);
//			assert(next_node->owner == chopped);

//			debug_dnslib_zone("Inserting new node to zone tree.\n");
////			TREE_INSERT(zone->tree, dnslib_node, avl, next_node);

//			ret = dnslib_zone_tree_insert(zone->contents->nodes,
//			                              next_node);
//			if (ret != DNSLIB_EOK) {
//				debug_dnslib_zone("Failed to insert new node "
//				                  "to zone tree.\n");
//				dnslib_dname_free(&chopped);
//				return ret;
//			}

//#ifdef USE_HASH_TABLE
//DEBUG_DNSLIB_ZONE(
//			char *name = dnslib_dname_to_str(next_node->owner);
//			debug_dnslib_zone("Adding new node with owner %s to "
//			                  "hash table.\n", name);
//			free(name);
//);

//			if (zone->contents->table != NULL
//			    && ck_insert_item(zone->contents->table,
//			      (const char *)next_node->owner->name,
//			      next_node->owner->size, (void *)next_node) != 0) {
//				debug_dnslib_zone("Error inserting node into "
//				                  "hash table!\n");
//				dnslib_dname_free(&chopped);
//				return DNSLIB_EHASH;
//			}
//#endif
//			debug_dnslib_zone("Next parent.\n");
//			node =  next_node;
//			chopped = dnslib_dname_left_chop(chopped);
//		}
//		debug_dnslib_zone("Created all parents.\n");
//	}
//	dnslib_dname_free(&chopped);

//	return DNSLIB_EOK;
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_add_rrset(dnslib_zone_t *zone, dnslib_rrset_t *rrset,
                          dnslib_node_t **node,
                          dnslib_rrset_dupl_handling_t dupl,
                          int use_domain_table)
{
	if (zone == NULL) {
		return DNSLIB_EBADARG;
	}

	return dnslib_zone_contents_add_rrset(zone->contents, rrset, node, dupl,
	                                      use_domain_table);

//	if (zone == NULL || rrset == NULL || zone->contents->apex == NULL
//	    || zone->contents == NULL || zone->contents->apex->owner == NULL
//	    || node == NULL) {
//		return DNSLIB_EBADARG;
//	}

//	// check if the RRSet belongs to the zone
//	if (dnslib_dname_compare(dnslib_rrset_owner(rrset),
//	                         zone->contents->apex->owner) != 0
//	    && !dnslib_dname_is_subdomain(dnslib_rrset_owner(rrset),
//	                                  zone->contents->apex->owner)) {
//		return DNSLIB_EBADZONE;
//	}

//	if ((*node) == NULL
//	    && (*node = dnslib_zone_get_node(zone, dnslib_rrset_owner(rrset)))
//	        == NULL) {
//		return DNSLIB_ENONODE;
//	}

//	assert(*node != NULL);

//	// add all domain names from the RRSet to domain name table
//	int rc;

//	/*! \todo REMOVE RRSET */
//	rc = dnslib_node_add_rrset(*node, rrset,
//	                           dupl == DNSLIB_RRSET_DUPL_MERGE);
//	if (rc < 0) {
//		debug_dnslib_zone("Failed to add RRSet to node.\n");
//		return rc;
//	}

//	int ret = rc;

//	if (use_domain_table) {
//		debug_dnslib_zone("Saving RRSet to table.\n");
//		rc = dnslib_zone_dnames_from_rrset_to_table(
//		         zone->contents->dname_table, rrset, 0, (*node)->owner);
//		if (rc != DNSLIB_EOK) {
//			debug_dnslib_zone("Error saving domain names from "
//					  "RRSIGs to the domain name table.\n "
//					  "The zone may be in an inconsistent "
//					  "state.\n");
//			// WARNING: the zone is not in consistent state now -
//			// there may be domain names in it that are not inserted
//			// into the domain table
//			return rc;
//		}
//	}

//	// replace RRSet's owner with the node's owner (that is already in the
//	// table)
//	/*! \todo Do even if domain table is not used?? */
//	if (ret == DNSLIB_EOK && rrset->owner != (*node)->owner) {
//		dnslib_dname_free(&rrset->owner);
//		rrset->owner = (*node)->owner;
//	}

//	debug_dnslib_zone("RRSet OK.\n");
//	return ret;
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_add_rrsigs(dnslib_zone_t *zone, dnslib_rrset_t *rrsigs,
                           dnslib_rrset_t **rrset, dnslib_node_t **node,
                           dnslib_rrset_dupl_handling_t dupl,
                           int use_domain_table)
{
	if (zone == NULL) {
		return DNSLIB_EBADARG;
	}

	return dnslib_zone_contents_add_rrsigs(zone->contents, rrsigs, rrset,
	                                      node, dupl, use_domain_table);

//	if (zone == NULL || rrsigs == NULL || rrset == NULL || node == NULL
//	    || zone->contents == NULL || zone->contents->apex == NULL
//	    || zone->contents->apex->owner == NULL) {
//		return DNSLIB_EBADARG;
//	}

//	// check if the RRSet belongs to the zone
//	if (*rrset != NULL
//	    && dnslib_dname_compare(dnslib_rrset_owner(*rrset),
//	                            zone->contents->apex->owner) != 0
//	    && !dnslib_dname_is_subdomain(dnslib_rrset_owner(*rrset),
//	                                  zone->contents->apex->owner)) {
//		return DNSLIB_EBADZONE;
//	}

//	// check if the RRSIGs belong to the RRSet
//	if (*rrset != NULL
//	    && (dnslib_dname_compare(dnslib_rrset_owner(rrsigs),
//	                             dnslib_rrset_owner(*rrset)) != 0)) {
//		return DNSLIB_EBADARG;
//	}

//	// if no RRSet given, try to find the right RRSet
//	if (*rrset == NULL) {
//		// even no node given
//		// find proper node
//		dnslib_node_t *(*get_node)(const dnslib_zone_t *,
//		                           const dnslib_dname_t *)
//		    = (dnslib_rdata_rrsig_type_covered(
//		            dnslib_rrset_rdata(rrsigs)) == DNSLIB_RRTYPE_NSEC3)
//		       ? dnslib_zone_get_nsec3_node
//		       : dnslib_zone_get_node;

//		if (*node == NULL
//		    && (*node = get_node(
//		                   zone, dnslib_rrset_owner(rrsigs))) == NULL) {
//			debug_dnslib_zone("Failed to find node for RRSIGs.\n");
//			return DNSLIB_EBADARG;  /*! \todo Other error code? */
//		}

//		assert(*node != NULL);

//		// find the RRSet in the node
//		// take only the first RDATA from the RRSIGs
//		debug_dnslib_zone("Finding RRSet for type %s\n",
//		                  dnslib_rrtype_to_string(
//		                      dnslib_rdata_rrsig_type_covered(
//		                      dnslib_rrset_rdata(rrsigs))));
//		*rrset = dnslib_node_get_rrset(
//		             *node, dnslib_rdata_rrsig_type_covered(
//		                      dnslib_rrset_rdata(rrsigs)));
//		if (*rrset == NULL) {
//			debug_dnslib_zone("Failed to find RRSet for RRSIGs.\n");
//			return DNSLIB_EBADARG;  /*! \todo Other error code? */
//		}
//	}

//	assert(*rrset != NULL);

//	// add all domain names from the RRSet to domain name table
//	int rc;
//	int ret = DNSLIB_EOK;

//	rc = dnslib_rrset_add_rrsigs(*rrset, rrsigs, dupl);
//	if (rc < 0) {
//		debug_dnslib_dname("Failed to add RRSIGs to RRSet.\n");
//		return rc;
//	} else if (rc > 0) {
//		assert(dupl == DNSLIB_RRSET_DUPL_MERGE);
//		ret = 1;
//	}

//	if (use_domain_table) {
//		debug_dnslib_zone("Saving RRSIG RRSet to table.\n");
//		rc = dnslib_zone_dnames_from_rrset_to_table(
//		       zone->contents->dname_table, rrsigs, 0, (*rrset)->owner);
//		if (rc != DNSLIB_EOK) {
//			debug_dnslib_zone("Error saving domain names from "
//					  "RRSIGs to the domain name table.\n "
//					  "The zone may be in an inconsistent "
//					  "state.\n");
//			// WARNING: the zone is not in consistent state now -
//			// there may be domain names in it that are not inserted
//			// into the domain table
//			return rc;
//		}
//	}

//	// replace RRSet's owner with the node's owner (that is already in the
//	// table)
//	if ((*rrset)->owner != (*rrset)->rrsigs->owner) {
//		dnslib_dname_free(&rrsigs->owner);
//		(*rrset)->rrsigs->owner = (*rrset)->owner;
//	}

//	debug_dnslib_zone("RRSIGs OK\n");
//	return ret;
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_add_nsec3_node(dnslib_zone_t *zone, dnslib_node_t *node,
                               int create_parents, int use_domain_table)
{
	if (zone == NULL) {
		return DNSLIB_EBADARG;
	}

	return dnslib_zone_contents_add_nsec3_node(zone->contents, node,
	                                           create_parents,
	                                           use_domain_table);
//	if (zone == NULL || node == NULL || zone->contents == NULL) {
//		return DNSLIB_EBADARG;
//	}

//	int ret = 0;
//	if ((ret = dnslib_zone_check_node(zone->contents, node)) != 0) {
//		return ret;
//	}

//	// how to know if this is successfull??
////	TREE_INSERT(zone->nsec3_nodes, dnslib_node, avl, node);
//	dnslib_zone_tree_insert(zone->contents->nsec3_nodes, node);

//	if (use_domain_table) {
//		ret = dnslib_zone_dnames_from_node_to_table(
//		           zone->contents->dname_table, node);
//		if (ret != DNSLIB_EOK) {
//			/*! \todo Remove the node from the tree. */
//			debug_dnslib_zone("Failed to add dnames into table.\n");
//			return ret;
//		}
//	}

//	return DNSLIB_EOK;
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_add_nsec3_rrset(dnslib_zone_t *zone, dnslib_rrset_t *rrset,
                                dnslib_node_t **node,
                                dnslib_rrset_dupl_handling_t dupl,
                                int use_domain_table)
{
	if (zone == NULL) {
		return DNSLIB_EBADARG;
	}

	return dnslib_zone_contents_add_nsec3_rrset(zone->contents, rrset, node,
	                                            dupl,
	                                            use_domain_table);

//	if (zone == NULL || rrset == NULL || zone->contents == NULL
//	    || zone->contents->apex == NULL
//	    || zone->contents->apex->owner == NULL || node == NULL) {
//		return DNSLIB_EBADARG;
//	}

//	// check if the RRSet belongs to the zone
//	if (dnslib_dname_compare(dnslib_rrset_owner(rrset),
//	                         zone->contents->apex->owner) != 0
//	    && !dnslib_dname_is_subdomain(dnslib_rrset_owner(rrset),
//	                                  zone->contents->apex->owner)) {
//		return DNSLIB_EBADZONE;
//	}

//	if ((*node) == NULL
//	    && (*node = dnslib_zone_get_nsec3_node(
//	                      zone, dnslib_rrset_owner(rrset))) == NULL) {
//		return DNSLIB_ENONODE;
//	}

//	assert(*node != NULL);

//	// add all domain names from the RRSet to domain name table
//	int rc;

//	/*! \todo REMOVE RRSET */
//	rc = dnslib_node_add_rrset(*node, rrset,
//	                           dupl == DNSLIB_RRSET_DUPL_MERGE);
//	if (rc < 0) {
//		return rc;
//	}

//	int ret = rc;

//	if (use_domain_table) {
//		debug_dnslib_zone("Saving NSEC3 RRSet to table.\n");
//		rc = dnslib_zone_dnames_from_rrset_to_table(
//		         zone->contents->dname_table, rrset, 0, (*node)->owner);
//		if (rc != DNSLIB_EOK) {
//			debug_dnslib_zone("Error saving domain names from "
//					  "RRSIGs to the domain name table.\n "
//					  "The zone may be in an inconsistent "
//					  "state.\n");
//			// WARNING: the zone is not in consistent state now -
//			// there may be domain names in it that are not inserted
//			// into the domain table
//			return rc;
//		}
//	}

//	// replace RRSet's owner with the node's owner (that is already in the
//	// table)
//	/*! \todo Do even if domain table is not used? */
//	if (rrset->owner != (*node)->owner) {
//		dnslib_dname_free(&rrset->owner);
//		rrset->owner = (*node)->owner;
//	}

//	debug_dnslib_zone("NSEC3 OK\n");
//	return ret;
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_create_and_fill_hash_table(dnslib_zone_t *zone)
{
	if (zone == NULL) {
		return DNSLIB_EBADARG;
	}

	return dnslib_zone_contents_create_and_fill_hash_table(zone->contents);

//	if (zone == NULL || zone->contents == NULL
//	    || zone->contents->apex == NULL
//	    || zone->contents->apex->owner == NULL) {
//		return DNSLIB_EBADARG;
//	}
//	/*
//	 * 1) Create hash table.
//	 */
//#ifdef USE_HASH_TABLE
//	if (zone->contents->node_count > 0) {
//		zone->contents->table =
//			ck_create_table(zone->contents->node_count);
//		if (zone->contents->table == NULL) {
//			return DNSLIB_ENOMEM;
//		}

//		// insert the apex into the hash table
//		if (ck_insert_item(zone->contents->table,
//		                (const char *)zone->contents->apex->owner->name,
//		                zone->contents->apex->owner->size,
//		                (void *)zone->contents->apex) != 0) {
//			return DNSLIB_EHASH;
//		}
//	} else {
//		zone->contents->table = NULL;
//		return DNSLIB_EOK;	// OK?
//	}

//	/*
//	 * 2) Fill in the hash table.
//	 *
//	 * In this point, the nodes in the zone must be adjusted, so that only
//	 * relevant nodes (authoritative and delegation points are inserted.
//	 *
//	 * TODO: how to know if this was successful??
//	 */
////	TREE_FORWARD_APPLY(zone->tree, dnslib_node, avl,
////	                   dnslib_zone_node_to_hash, zone);
//	/*! \todo Replace by zone tree. */
//	int ret = dnslib_zone_tree_forward_apply_inorder(zone->contents->nodes,
//	                                        dnslib_zone_node_to_hash, zone);
//	if (ret != DNSLIB_EOK) {
//		debug_dnslib_zone("Failed to insert nodes to hash table.\n");
//		return ret;
//	}

//#endif
//	return DNSLIB_EOK;
}

/*----------------------------------------------------------------------------*/

dnslib_node_t *dnslib_zone_get_node(const dnslib_zone_t *zone,
                                    const dnslib_dname_t *name)
{
	if (zone == NULL) {
		return NULL;
	}

	return dnslib_zone_contents_get_node(zone->contents, name);

//	if (zone == NULL || name == NULL || zone->contents == NULL) {
//		return NULL;
//	}

//	// create dummy node to use for lookup
////	dnslib_node_t *tmp = dnslib_node_new((dnslib_dname_t *)name, NULL);
////	dnslib_node_t *n = TREE_FIND(zone->tree, dnslib_node, avl, tmp);
////	dnslib_node_free(&tmp, 0);

//	dnslib_node_t *n;
//	int ret = dnslib_zone_tree_get(zone->contents->nodes, name, &n);
//	if (ret != DNSLIB_EOK) {
//		debug_dnslib_zone("Failed to find name in the zone tree.\n");
//		return NULL;
//	}

//	return n;
}

/*----------------------------------------------------------------------------*/

dnslib_node_t *dnslib_zone_get_nsec3_node(const dnslib_zone_t *zone,
                                          const dnslib_dname_t *name)
{
	if (zone == NULL) {
		return NULL;
	}

	return dnslib_zone_contents_get_nsec3_node(zone->contents, name);

//	if (zone == NULL || name == NULL || zone->contents == NULL) {
//		return NULL;
//	}

//	// create dummy node to use for lookup
////	dnslib_node_t *tmp = dnslib_node_new((dnslib_dname_t *)name, NULL);
////	dnslib_node_t *n = TREE_FIND(zone->nsec3_nodes, dnslib_node, avl, tmp);
////	dnslib_node_free(&tmp, 0);
//	dnslib_node_t *n;
//	int ret = dnslib_zone_tree_get(zone->contents->nsec3_nodes, name, &n);

//	if (ret != DNSLIB_EOK) {
//		debug_dnslib_zone("Failed to find NSEC3 name in the zone tree."
//		                  "\n");
//		return NULL;
//	}

//	return n;
}

/*----------------------------------------------------------------------------*/

const dnslib_node_t *dnslib_zone_find_node(const dnslib_zone_t *zone,
                                           const dnslib_dname_t *name)
{
	if (zone == NULL) {
		return NULL;
	}

	return dnslib_zone_contents_find_node(zone->contents, name);
//	return dnslib_zone_get_node(zone, name);
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_find_dname(const dnslib_zone_t *zone,
                           const dnslib_dname_t *name,
                           const dnslib_node_t **node,
                           const dnslib_node_t **closest_encloser,
                           const dnslib_node_t **previous)
{
	if (zone == NULL) {
		return DNSLIB_EBADARG;
	}

	return dnslib_zone_contents_find_dname(zone->contents, name, node,
	                                       closest_encloser, previous);

//	if (zone == NULL || name == NULL || node == NULL
//	    || closest_encloser == NULL || previous == NULL
//	    || zone->contents == NULL || zone->contents->apex == NULL
//	    || zone->contents->apex->owner == NULL) {
//		return DNSLIB_EBADARG;
//	}

//DEBUG_DNSLIB_ZONE(
//	char *name_str = dnslib_dname_to_str(name);
//	char *zone_str = dnslib_dname_to_str(zone->contents->apex->owner);
//	debug_dnslib_zone("Searching for name %s in zone %s...\n",
//	                  name_str, zone_str);
//	free(name_str);
//	free(zone_str);
//);

//	if (dnslib_dname_compare(name, zone->contents->apex->owner) == 0) {
//		*node = zone->contents->apex;
//		*closest_encloser = *node;
//		return DNSLIB_ZONE_NAME_FOUND;
//	}

//	if (!dnslib_dname_is_subdomain(name, zone->contents->apex->owner)) {
//		*node = NULL;
//		*closest_encloser = NULL;
//		return DNSLIB_EBADZONE;
//	}

//	int exact_match = dnslib_zone_find_in_tree(zone, name, node, previous);

//DEBUG_DNSLIB_ZONE(
//	char *name_str = (*node) ? dnslib_dname_to_str((*node)->owner)
//	                         : "(nil)";
//	char *name_str2 = (*previous != NULL)
//	                  ? dnslib_dname_to_str((*previous)->owner)
//	                  : "(nil)";
//	debug_dnslib_zone("Search function returned %d, node %s and prev: %s\n",
//			  exact_match, name_str, name_str2);

//	if (*node) {
//		free(name_str);
//	}
//	if (*previous != NULL) {
//		free(name_str2);
//	}
//);

//	*closest_encloser = *node;

//	// there must be at least one node with domain name less or equal to
//	// the searched name if the name belongs to the zone (the root)
//	if (*node == NULL) {
//		return DNSLIB_EBADZONE;
//	}

//	// TODO: this could be replaced by saving pointer to closest encloser
//	//       in node

//	if (!exact_match) {
//		int matched_labels = dnslib_dname_matched_labels(
//				(*closest_encloser)->owner, name);
//		while (matched_labels
//		       < dnslib_dname_label_count((*closest_encloser)->owner)) {
//			(*closest_encloser) = (*closest_encloser)->parent;
//			assert(*closest_encloser);
//		}
//	}
//DEBUG_DNSLIB_ZONE(
//	char *n = dnslib_dname_to_str((*closest_encloser)->owner);
//	debug_dnslib_zone("Closest encloser: %s\n", n);
//	free(n);
//);

//	debug_dnslib_zone("find_dname() returning %d\n", exact_match);

//	return (exact_match)
//	       ? DNSLIB_ZONE_NAME_FOUND
//	       : DNSLIB_ZONE_NAME_NOT_FOUND;
}

/*----------------------------------------------------------------------------*/

const dnslib_node_t *dnslib_zone_find_previous(const dnslib_zone_t *zone,
                                               const dnslib_dname_t *name)
{
	if (zone == NULL) {
		return NULL;
	}

	return dnslib_zone_contents_find_previous(zone->contents, name);

//	if (zone == NULL || name == NULL || zone->contents == NULL) {
//		return NULL;
//	}

//	const dnslib_node_t *found = NULL, *prev = NULL;

//	(void)dnslib_zone_find_in_tree(zone, name, &found, &prev);
//	assert(prev != NULL);

//	return prev;
}

/*----------------------------------------------------------------------------*/
#ifdef USE_HASH_TABLE
int dnslib_zone_find_dname_hash(const dnslib_zone_t *zone,
                                const dnslib_dname_t *name,
                                const dnslib_node_t **node,
                                const dnslib_node_t **closest_encloser)
{
	if (zone == NULL) {
		return DNSLIB_EBADARG;
	}

	return dnslib_zone_contents_find_dname_hash(zone->contents, name, node,
	                                            closest_encloser);

//	if (zone == NULL || name == NULL || node == NULL
//	    || closest_encloser == NULL || zone->contents == NULL) {
//		return DNSLIB_EBADARG;
//	}

//DEBUG_DNSLIB_ZONE(
//	char *name_str = dnslib_dname_to_str(name);
//	char *zone_str = dnslib_dname_to_str(zone->contents->apex->owner);
//	debug_dnslib_zone("Searching for name %s in zone %s...\n",
//	                  name_str, zone_str);
//	free(name_str);
//	free(zone_str);
//);

//	if (dnslib_dname_compare(name, zone->contents->apex->owner) == 0) {
//		*node = zone->contents->apex;
//		*closest_encloser = *node;
//		return DNSLIB_ZONE_NAME_FOUND;
//	}

//	if (!dnslib_dname_is_subdomain(name, zone->contents->apex->owner)) {
//		*node = NULL;
//		*closest_encloser = NULL;
//		return DNSLIB_EBADZONE;
//	}

//	const ck_hash_table_item_t *item = ck_find_item(zone->contents->table,
//	                                               (const char *)name->name,
//	                                               name->size);

//	if (item != NULL) {
//		*node = (const dnslib_node_t *)item->value;
//		*closest_encloser = *node;

//		debug_dnslib_zone("Found node in hash table: %p (owner %p, "
//		                  "labels: %d)\n", *node, (*node)->owner,
//		                  dnslib_dname_label_count((*node)->owner));
//		assert(*node != NULL);
//		assert(*closest_encloser != NULL);
//		return DNSLIB_ZONE_NAME_FOUND;
//	}

//	*node = NULL;

//	// chop leftmost labels until some node is found
//	// copy the name for chopping
//	dnslib_dname_t *name_copy = dnslib_dname_copy(name);
//DEBUG_DNSLIB_ZONE(
//	char *n = dnslib_dname_to_str(name_copy);
//	debug_dnslib_zone("Finding closest encloser..\nStarting with: %s\n", n);
//	free(n);
//);

//	while (item == NULL) {
//		dnslib_dname_left_chop_no_copy(name_copy);
//DEBUG_DNSLIB_ZONE(
//		char *n = dnslib_dname_to_str(name_copy);
//		debug_dnslib_zone("Chopped leftmost label: %s (%.*s, size %u)"
//		                  "\n", n, name_copy->size, name_copy->name,
//		                  name_copy->size);
//		free(n);
//);
//		// not satisfied in root zone!!
//		assert(name_copy->label_count > 0);

//		item = ck_find_item(zone->contents->table,
//		                    (const char *)name_copy->name,
//		                    name_copy->size);
//	}

//	dnslib_dname_free(&name_copy);

//	assert(item != NULL);
//	*closest_encloser = (const dnslib_node_t *)item->value;

//	return DNSLIB_ZONE_NAME_NOT_FOUND;
}
#endif
/*----------------------------------------------------------------------------*/

const dnslib_node_t *dnslib_zone_find_nsec3_node(const dnslib_zone_t *zone,
                                                 const dnslib_dname_t *name)
{
	if (zone == NULL) {
		return NULL;
	}

	return dnslib_zone_contents_find_nsec3_node(zone->contents, name);
//	return dnslib_zone_get_nsec3_node(zone, name);
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_find_nsec3_for_name(const dnslib_zone_t *zone,
                                    const dnslib_dname_t *name,
                                    const dnslib_node_t **nsec3_node,
                                    const dnslib_node_t **nsec3_previous)
{
	if (zone == NULL) {
		return DNSLIB_EBADARG;
	}

	return dnslib_zone_contents_find_nsec3_for_name(zone->contents, name,
	                                            nsec3_node, nsec3_previous);

//	if (zone == NULL || name == NULL
//	    || nsec3_node == NULL || nsec3_previous == NULL
//	    || zone->contents == NULL) {
//		return DNSLIB_EBADARG;
//	}

//	dnslib_dname_t *nsec3_name = NULL;
//	int ret = dnslib_zone_nsec3_name(zone, name, &nsec3_name);

//	if (ret != DNSLIB_EOK) {
//		return ret;
//	}

//DEBUG_DNSLIB_ZONE(
//	char *n = dnslib_dname_to_str(nsec3_name);
//	debug_dnslib_zone("NSEC3 node name: %s.\n", n);
//	free(n);
//);

//	const dnslib_node_t *found = NULL, *prev = NULL;

//	// create dummy node to use for lookup
//	int exact_match = dnslib_zone_tree_find_less_or_equal(
//		zone->contents->nsec3_nodes, name, &found, &prev);

//DEBUG_DNSLIB_ZONE(
//	if (found) {
//		char *n = dnslib_dname_to_str(found->owner);
//		debug_dnslib_zone("Found NSEC3 node: %s.\n", n);
//		free(n);
//	} else {
//		debug_dnslib_zone("Found no NSEC3 node.\n");
//	}

//	if (prev) {
//		assert(prev->owner);
//		char *n = dnslib_dname_to_str(prev->owner);
//		debug_dnslib_zone("Found previous NSEC3 node: %s.\n", n);
//		free(n);
//	} else {
//		debug_dnslib_zone("Found no previous NSEC3 node.\n");
//	}
//);
//	*nsec3_node = found;

//	if (prev == NULL) {
//		// either the returned node is the root of the tree, or it is
//		// the leftmost node in the tree; in both cases node was found
//		// set the previous node of the found node
//		assert(exact_match);
//		assert(*nsec3_node != NULL);
//		*nsec3_previous = dnslib_node_previous(*nsec3_node);
//	} else {
//		*nsec3_previous = prev;
//	}

//	debug_dnslib_zone("find_nsec3_for_name() returning %d\n", exact_match);

//	return (exact_match)
//	       ? DNSLIB_ZONE_NAME_FOUND
//	       : DNSLIB_ZONE_NAME_NOT_FOUND;
}

/*----------------------------------------------------------------------------*/

const dnslib_node_t *dnslib_zone_apex(const dnslib_zone_t *zone)
{
	if (zone == NULL) {
		return NULL;
	}

	return dnslib_zone_contents_apex(zone->contents);

//	if (zone == NULL || zone->contents == NULL) {
//		return NULL;
//	}

//	return zone->contents->apex;
}

/*----------------------------------------------------------------------------*/

dnslib_node_t *dnslib_zone_get_apex(const dnslib_zone_t *zone)
{
	if (zone == NULL) {
		return NULL;
	}

	return dnslib_zone_contents_get_apex(zone->contents);

//	if (zone == NULL || zone->contents == NULL) {
//		return NULL;
//	}

//	return zone->contents->apex;
}

/*----------------------------------------------------------------------------*/

dnslib_dname_t *dnslib_zone_name(const dnslib_zone_t *zone)
{
	if (zone == NULL) {
		return NULL;
	}

	return zone->name;
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_adjust_dnames(dnslib_zone_t *zone)
{
	if (zone == NULL) {
		return DNSLIB_EBADARG;
	}

	return dnslib_zone_contents_adjust_dnames(zone->contents);

//	if (zone == NULL || zone->contents == NULL) {
//		return DNSLIB_EBADARG;
//	}

//	// load NSEC3PARAM (needed on adjusting function)
//	dnslib_zone_load_nsec3param(zone);

//	/*! \todo Replace by zone tree. */
////	TREE_FORWARD_APPLY(zone->tree, dnslib_node, avl,
////	                   dnslib_zone_adjust_node_in_tree, zone);

////	TREE_FORWARD_APPLY(zone->nsec3_nodes, dnslib_node, avl,
////	                   dnslib_zone_adjust_nsec3_node_in_tree, zone);

//	int ret = dnslib_zone_tree_forward_apply_inorder(zone->contents->nodes,
//	                                 dnslib_zone_adjust_node_in_tree, zone);
//	if (ret != DNSLIB_EOK) {
//		return ret;
//	}

//	ret = dnslib_zone_tree_forward_apply_inorder(
//	              zone->contents->nsec3_nodes,
//	              dnslib_zone_adjust_nsec3_node_in_tree, zone);

//	return ret;
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_load_nsec3param(dnslib_zone_t *zone)
{
	if (zone == NULL) {
		return DNSLIB_EBADARG;
	}

	return dnslib_zone_contents_load_nsec3param(zone->contents);

//	if (zone == NULL || zone->contents == NULL
//	    || zone->contents->apex == NULL) {
//		return DNSLIB_EBADARG;
//	}

//	const dnslib_rrset_t *rrset = dnslib_node_rrset(zone->contents->apex,
//						      DNSLIB_RRTYPE_NSEC3PARAM);

//	if (rrset != NULL) {
//		dnslib_nsec3_params_from_wire(&zone->contents->nsec3_params,
//		                              rrset);
//	} else {
//		memset(&zone->contents->nsec3_params, 0,
//		       sizeof(dnslib_nsec3_params_t));
//	}

//	return DNSLIB_EOK;
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_nsec3_enabled(const dnslib_zone_t *zone)
{
	if (zone == NULL) {
		return DNSLIB_EBADARG;
	}

	return dnslib_zone_contents_nsec3_enabled(zone->contents);

//	if (zone == NULL || zone->contents == NULL) {
//		return DNSLIB_EBADARG;
//	}

//	return (zone->contents->nsec3_params.algorithm != 0);
}

/*----------------------------------------------------------------------------*/

const dnslib_nsec3_params_t *dnslib_zone_nsec3params(const dnslib_zone_t *zone)
{
	if (zone == NULL) {
		return NULL;
	}

	return dnslib_zone_contents_nsec3params(zone->contents);

//	if (zone == NULL || zone->contents == NULL) {
//		return NULL;
//	}

//	if (dnslib_zone_nsec3_enabled(zone)) {
//		return &zone->contents->nsec3_params;
//	} else {
//		return NULL;
//	}
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_tree_apply_postorder(dnslib_zone_t *zone,
                              void (*function)(dnslib_node_t *node, void *data),
                              void *data)
{
	if (zone == NULL) {
		return DNSLIB_EBADARG;
	}

	return dnslib_zone_contents_tree_apply_postorder(zone->contents,
	                                                 function, data);

//	if (zone == NULL || zone->contents == NULL) {
//		return DNSLIB_EBADARG;
//	}

//	return dnslib_zone_tree_forward_apply_postorder(zone->contents->nodes,
//	                                                function, data);
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_tree_apply_inorder(dnslib_zone_t *zone,
                              void (*function)(dnslib_node_t *node, void *data),
                              void *data)
{
	if (zone == NULL) {
		return DNSLIB_EBADARG;
	}

	return dnslib_zone_contents_tree_apply_inorder(zone->contents,
	                                               function, data);

//	if (zone == NULL || zone->contents == NULL) {
//		return DNSLIB_EBADARG;
//	}

//	return dnslib_zone_tree_forward_apply_inorder(zone->contents->nodes,
//	                                              function, data);
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_tree_apply_inorder_reverse(dnslib_zone_t *zone,
                              void (*function)(dnslib_node_t *node, void *data),
                              void *data)
{
	if (zone == NULL) {
		return DNSLIB_EBADARG;
	}

	return dnslib_zone_contents_tree_apply_inorder_reverse(zone->contents,
	                                                       function, data);

//	if (zone == NULL || zone->contents == NULL) {
//		return DNSLIB_EBADARG;
//	}

//	return dnslib_zone_tree_reverse_apply_inorder(zone->contents->nodes,
//	                                              function, data);
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_nsec3_apply_postorder(dnslib_zone_t *zone,
                              void (*function)(dnslib_node_t *node, void *data),
                              void *data)
{
	if (zone == NULL) {
		return DNSLIB_EBADARG;
	}

	return dnslib_zone_contents_nsec3_apply_postorder(zone->contents,
	                                                  function, data);

//	if (zone == NULL || zone->contents == NULL) {
//		return DNSLIB_EBADARG;
//	}

//	return dnslib_zone_tree_forward_apply_postorder(
//			zone->contents->nsec3_nodes, function, data);
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_nsec3_apply_inorder(dnslib_zone_t *zone,
                              void (*function)(dnslib_node_t *node, void *data),
                              void *data)
{
	if (zone == NULL) {
		return DNSLIB_EBADARG;
	}

	return dnslib_zone_contents_nsec3_apply_inorder(zone->contents,
	                                                function, data);

//	if (zone == NULL || zone->contents == NULL) {
//		return DNSLIB_EBADARG;
//	}

//	return dnslib_zone_tree_forward_apply_inorder(
//			zone->contents->nsec3_nodes, function, data);
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_nsec3_apply_inorder_reverse(dnslib_zone_t *zone,
                              void (*function)(dnslib_node_t *node, void *data),
                              void *data)
{
	if (zone == NULL) {
		return DNSLIB_EBADARG;
	}

	return dnslib_zone_contents_nsec3_apply_inorder_reverse(zone->contents,
	                                                        function, data);

//	if (zone == NULL || zone->contents == NULL) {
//		return DNSLIB_EBADARG;
//	}

//	return dnslib_zone_tree_reverse_apply_inorder(
//			zone->contents->nsec3_nodes, function, data);
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_shallow_copy(const dnslib_zone_t *from,
                             dnslib_zone_contents_t **to)
{
	if (from == NULL) {
		return DNSLIB_EBADARG;
	}

	return dnslib_zone_contents_shallow_copy(from->contents, to);

//	if (from == NULL || to == NULL || from->contents == NULL) {
//		return DNSLIB_EBADARG;
//	}

//	int ret = DNSLIB_EOK;

//	dnslib_zone_contents_t *contents = (dnslib_zone_contents_t *)calloc(
//	                                     1, sizeof(dnslib_zone_contents_t));
//	if (contents == NULL) {
//		ERR_ALLOC_FAILED;
//		return DNSLIB_ENOMEM;
//	}

//	contents->apex = from->contents->apex;

//	contents->nodes = malloc(sizeof(dnslib_zone_tree_t));
//	if (contents->nodes == NULL) {
//		ERR_ALLOC_FAILED;
//		ret = DNSLIB_ENOMEM;
//		goto cleanup;
//	}

//	contents->nsec3_nodes = malloc(sizeof(dnslib_zone_tree_t));
//	if (contents->nsec3_nodes == NULL) {
//		ERR_ALLOC_FAILED;
//		ret = DNSLIB_ENOMEM;
//		goto cleanup;
//	}

//	if (from->contents->dname_table != NULL) {
//		contents->dname_table = dnslib_dname_table_new();
//		if (contents->dname_table == NULL) {
//			ERR_ALLOC_FAILED;
//			ret = DNSLIB_ENOMEM;
//			goto cleanup;
//		}
//		if ((ret = dnslib_dname_table_copy(from->contents->dname_table,
//		                        contents->dname_table)) != DNSLIB_EOK) {
//			goto cleanup;
//		}
//	} else {
//		contents->dname_table = NULL;
//	}

//	contents->node_count = from->contents->node_count;
//	contents->generation = from->contents->generation;

//	/* Initialize NSEC3 params */
//	memcpy(&contents->nsec3_params, &from->contents->nsec3_params,
//	       sizeof(dnslib_nsec3_params_t));

//	if ((ret = dnslib_zone_tree_copy(from->contents->nodes,
//	                                 contents->nodes)) != DNSLIB_EOK
//	    || (ret = dnslib_zone_tree_copy(from->contents->nsec3_nodes,
//	                                contents->nsec3_nodes)) != DNSLIB_EOK) {
//		goto cleanup;
//	}

//#ifdef USE_HASH_TABLE
//	ret = ck_copy_table(from->contents->table, &contents->table);
//	if (ret != 0) {
//		ret = DNSLIB_ERROR;
//		goto cleanup;
//	}
//#endif

//	*to = contents;
//	return DNSLIB_EOK;

//cleanup:
//	dnslib_zone_tree_free(&contents->nodes);
//	dnslib_zone_tree_free(&contents->nsec3_nodes);
//	free(contents->dname_table);
//	free(contents);
//	return ret;
}

/*----------------------------------------------------------------------------*/

dnslib_zone_contents_t *dnslib_zone_switch_contents(dnslib_zone_t *zone,
                                           dnslib_zone_contents_t *new_contents)
{
	if (zone == NULL) {
		return NULL;
	}

	dnslib_zone_contents_t *old_contents =
		rcu_xchg_pointer(&zone->contents, new_contents);
	return old_contents;
}

/*----------------------------------------------------------------------------*/

void dnslib_zone_free(dnslib_zone_t **zone)
{
	if (zone == NULL || *zone == NULL) {
		return;
	}

	debug_dnslib_zone("zone_free().\n");

	if ((*zone)->contents && (*zone)->contents->generation != 0) {
		// zone is in the middle of an update, report
		debug_dnslib_zone("Destroying zone that is in the middle of an "
		                  "update.\n");
	}

	dnslib_dname_free(&(*zone)->name);

	/* Call zone data destructor if exists. */
	if ((*zone)->dtor) {
		(*zone)->dtor(*zone);
	}

	dnslib_zone_contents_free(&(*zone)->contents);

//	if ((*zone)->contents != NULL) {
//		// free the zone tree, but only the structure
//		dnslib_zone_tree_free(&(*zone)->contents->nodes);
//		dnslib_zone_tree_free(&(*zone)->contents->nsec3_nodes);

//#ifdef USE_HASH_TABLE
//		if ((*zone)->contents->table != NULL) {
//			ck_destroy_table(&(*zone)->contents->table, NULL, 0);
//		}
//#endif
//		dnslib_nsec3_params_free(&(*zone)->contents->nsec3_params);
//	}

//	free((*zone)->contents);
	free(*zone);
	*zone = NULL;

	debug_dnslib_zone("Done.\n");
}

/*----------------------------------------------------------------------------*/

void dnslib_zone_deep_free(dnslib_zone_t **zone, int free_rdata_dnames)
{
	if (zone == NULL || *zone == NULL) {
		return;
	}

	if ((*zone)->contents->generation != 0) {
		// zone is in the middle of an update, report
		debug_dnslib_zone("Destroying zone that is in the middle of an "
		                  "update.\n");
	}

DEBUG_DNSLIB_ZONE(
	char *name = dnslib_dname_to_str((*zone)->name);
	debug_dnslib_zone("Destroying zone %p, name: %s.\n", *zone, name);
	free(name);
);

	dnslib_dname_free(&(*zone)->name);

	/* Call zone data destructor if exists. */
	if ((*zone)->dtor) {
		(*zone)->dtor(*zone);
	}

	dnslib_zone_contents_deep_free(&(*zone)->contents);

//	if ((*zone)->contents != NULL) {

//#ifdef USE_HASH_TABLE
//		if ((*zone)->contents->table != NULL) {
//			ck_destroy_table(&(*zone)->contents->table, NULL, 0);
//		}
//#endif
//		/* has to go through zone twice, rdata may contain references to
//		   node owners earlier in the zone which may be already freed */
//		/* NSEC3 tree is deleted first as it may contain references to
//		   the normal tree. */

//		dnslib_zone_tree_forward_apply_postorder(
//			(*zone)->contents->nsec3_nodes,
//			dnslib_zone_destroy_node_rrsets_from_tree, 0);

//		dnslib_zone_tree_forward_apply_postorder(
//			(*zone)->contents->nsec3_nodes,
//			dnslib_zone_destroy_node_owner_from_tree, 0);

//		dnslib_zone_tree_forward_apply_postorder(
//			(*zone)->contents->nodes,
//			dnslib_zone_destroy_node_rrsets_from_tree, 0);

//		dnslib_zone_tree_forward_apply_postorder(
//			(*zone)->contents->nodes,
//			dnslib_zone_destroy_node_owner_from_tree, 0);

//		// free the zone tree, but only the structure
//		// (nodes are already destroyed)
//		debug_dnslib_zone("Destroying zone tree.\n");
//		dnslib_zone_tree_free(&(*zone)->contents->nodes);
//		debug_dnslib_zone("Destroying NSEC3 zone tree.\n");
//		dnslib_zone_tree_free(&(*zone)->contents->nsec3_nodes);

//		dnslib_nsec3_params_free(&(*zone)->contents->nsec3_params);

//		dnslib_dname_table_deep_free(&(*zone)->contents->dname_table);
//	}

//	free((*zone)->contents);
	free(*zone);
	*zone = NULL;
}
