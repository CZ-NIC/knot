#include <assert.h>

#include "zone-contents.h"
#include "dnslib/error.h"
#include "dnslib/debug.h"
#include "common/base32hex.h"

/*----------------------------------------------------------------------------*/
/* Non-API functions                                                          */
/*----------------------------------------------------------------------------*/
/*!
 * \brief Checks if the given node can be inserted into the given zone.
 *
 * Checks if both the arguments are non-NULL and if the owner of the node
 * belongs to the zone (i.e. is a subdomain of the zone apex).
 *
 * \param zone Zone to which the node is going to be inserted.
 * \param node Node to check.
 *
 * \retval DNSLIB_EOK if both arguments are non-NULL and the node belongs to the
 *         zone.
 * \retval DNSLIB_EBADARG if either of the arguments is NULL.
 * \retval DNSLIB_EBADZONE if the node does not belong to the zone.
 */
static int dnslib_zone_contents_check_node(
	const dnslib_zone_contents_t *contents, const dnslib_node_t *node)
{
	if (contents == NULL || node == NULL) {
		return DNSLIB_EBADARG;
	}

	// assert or just check??
	assert(contents->apex != NULL);

	if (!dnslib_dname_is_subdomain(node->owner,
	                               dnslib_node_owner(contents->apex))) {
DEBUG_DNSLIB_ZONE(
		char *node_owner = dnslib_dname_to_str(dnslib_node_owner(node));
		char *apex_owner = dnslib_dname_to_str(contents->apex->owner);
		debug_dnslib_zone("zone: Trying to insert foreign node to a "
				  "zone. Node owner: %s, zone apex: %s\n",
				  node_owner, apex_owner);
		free(node_owner);
		free(apex_owner);
);
		return DNSLIB_EBADZONE;
	}
	return DNSLIB_EOK;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Destroys all RRSets in a node.
 *
 * This function is designed to be used in the tree-iterating functions.
 *
 * \param node Node to destroy RRSets from.
 * \param data Unused parameter.
 */
static void dnslib_zone_contents_destroy_node_rrsets_from_tree(
	dnslib_node_t *node, void *data)
{
	int free_rdata_dnames = (int)((intptr_t)data);
	dnslib_node_free_rrsets(node, free_rdata_dnames);
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Destroys node owner.
 *
 * This function is designed to be used in the tree-iterating functions.
 *
 * \param node Node to destroy the owner of.
 * \param data Unused parameter.
 */
static void dnslib_zone_contents_destroy_node_owner_from_tree(
	dnslib_node_t *node, void *data)
{
	UNUSED(data);
	/*!< \todo change completely! */
	dnslib_node_free(&node, 0);
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Adjusts one RDATA item by replacing domain name by one present in the
 *        zone.
 *
 * This function tries to find the domain name in the zone. If the name is not
 * in the zone, it does nothing. If it is there, it destroys the domain name
 * stored in the RDATA item and replaces it by pointer to the domain name from
 * the zone.
 *
 * \warning Call this function only with RDATA items which store domain names,
 *          otherwise the behaviour is undefined.
 *
 * \param rdata RDATA where the item is located.
 * \param zone Zone to which the RDATA belongs.
 * \param pos Position of the RDATA item in the RDATA.
 */
static void dnslib_zone_contents_adjust_rdata_item(dnslib_rdata_t *rdata,
                                          dnslib_zone_contents_t *zone, int pos)
{
	const dnslib_rdata_item_t *dname_item
			= dnslib_rdata_item(rdata, pos);

	if (dname_item != NULL) {
		dnslib_dname_t *dname = dname_item->dname;
		const dnslib_node_t *n = NULL;
		const dnslib_node_t *closest_encloser = NULL;
		const dnslib_node_t *prev = NULL;

		int ret = dnslib_zone_contents_find_dname(zone, dname, &n,
		                                      &closest_encloser, &prev);

		//		n = dnslib_zone_find_node(zone, dname);

		if (ret == DNSLIB_EBADARG || ret == DNSLIB_EBADZONE) {
			// TODO: do some cleanup if needed
			return;
		}

		assert(ret != DNSLIB_ZONE_NAME_FOUND
		       || n == closest_encloser);

		if (ret != DNSLIB_ZONE_NAME_FOUND
		                && (closest_encloser != NULL)) {
			debug_dnslib_zdump("Saving closest encloser to RDATA."
			                   "\n");
			// save pointer to the closest encloser
			dnslib_rdata_item_t *item =
					dnslib_rdata_get_item(rdata, pos);
			assert(item->dname != NULL);
			//assert(item->dname->node == NULL);
			//skip_insert(list, (void *)item->dname,
			//	    (void *)closest_encloser->owner, NULL);
			item->dname->node = closest_encloser->owner->node;
		}
	}
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Adjusts all RDATA in the given RRSet by replacing domain names by ones
 *        present in the zone.
 *
 * This function selects the RDATA items containing a domain name (according to
 * RR type descriptor of the RRSet's type and adjusts the item using
 * dnslib_zone_adjust_rdata_item().
 *
 * \param rrset RRSet to adjust RDATA in.
 * \param zone Zone to which the RRSet belongs.
 */
static void dnslib_zone_contents_adjust_rdata_in_rrset(dnslib_rrset_t *rrset,
                                                   dnslib_zone_contents_t *zone)
{
	uint16_t type = dnslib_rrset_type(rrset);

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

				dnslib_zone_contents_adjust_rdata_item(rdata,
				                                       zone, i);
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

			dnslib_zone_contents_adjust_rdata_item(rdata, zone, i);
		}
	}

}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Adjusts all RRSets in the given node by replacing domain names in
 *        RDATA by ones present in the zone.
 *
 * This function just calls dnslib_zone_adjust_rdata_in_rrset() for all RRSets
 * in the node (including all RRSIG RRSets).
 *
 * \param node Zone node to adjust the RRSets in.
 * \param zone Zone to which the node belongs.
 */
static void dnslib_zone_contents_adjust_rrsets(dnslib_node_t *node,
                                               dnslib_zone_contents_t *zone)
{
	return;
	dnslib_rrset_t **rrsets = dnslib_node_get_rrsets(node);
	short count = dnslib_node_rrset_count(node);

	assert(count == 0 || rrsets != NULL);

	for (int r = 0; r < count; ++r) {
		assert(rrsets[r] != NULL);
		dnslib_zone_contents_adjust_rdata_in_rrset(rrsets[r], zone);
		dnslib_rrset_t *rrsigs = rrsets[r]->rrsigs;
		if (rrsigs != NULL) {
			dnslib_zone_contents_adjust_rdata_in_rrset(rrsigs,
			                                           zone);
		}
	}

	free(rrsets);
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Adjusts zone node for faster query processing.
 *
 * - Adjusts RRSets in the node (see dnslib_zone_adjust_rrsets()).
 * - Marks the node as delegation point or non-authoritative (below a zone cut)
 *   if applicable.
 * - Stores reference to corresponding NSEC3 node if applicable.
 *
 * \param node Zone node to adjust.
 * \param zone Zone the node belongs to.
 */
static void dnslib_zone_contents_adjust_node(dnslib_node_t *node,
                                             dnslib_zone_contents_t *zone)
{

DEBUG_DNSLIB_ZONE(
	char *name = dnslib_dname_to_str(node->owner);
	debug_dnslib_zone("----- Adjusting node %s -----\n", name);
	free(name);
);

	// adjust domain names in RDATA
	dnslib_zone_contents_adjust_rrsets(node, zone);

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

	// authorative node?
//	if (!dnslib_node_is_non_auth(node)) {
		zone->node_count++;
//	}

	// assure that owner has proper node
	if (dnslib_dname_node(dnslib_node_owner(node)) == NULL) {
		dnslib_dname_set_node(dnslib_node_get_owner(node), node);
		node->owner->node = node;
	}

	// NSEC3 node
	const dnslib_node_t *prev;
	const dnslib_node_t *nsec3;
	int match = dnslib_zone_contents_find_nsec3_for_name(zone,
	                                                dnslib_node_owner(node),
	                                                &nsec3, &prev);
	if (match != DNSLIB_ZONE_NAME_FOUND) {
		nsec3 = NULL;
	}

	dnslib_node_set_nsec3_node(node, (dnslib_node_t *)nsec3);

	debug_dnslib_zone("Set flags to the node: \n");
	debug_dnslib_zone("Delegation point: %s\n",
	       dnslib_node_is_deleg_point(node) ? "yes" : "no");
	debug_dnslib_zone("Non-authoritative: %s\n",
	       dnslib_node_is_non_auth(node) ? "yes" : "no");
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Adjusts a NSEC3 node for faster query processing.
 *
 * This function just adjusts all RRSets in the node, similarly as the
 * dnslib_zone_adjust_rrsets() function.
 *
 * \param node Zone node to adjust.
 * \param zone Zone the node belongs to.
 */
static void dnslib_zone_contents_adjust_nsec3_node(dnslib_node_t *node,
                                                   dnslib_zone_contents_t *zone)
{

DEBUG_DNSLIB_ZONE(
	char *name = dnslib_dname_to_str(node->owner);
	debug_dnslib_zone("----- Adjusting node %s -----\n", name);
	free(name);
);

	// adjust domain names in RDATA
	dnslib_rrset_t **rrsets = dnslib_node_get_rrsets(node);
	short count = dnslib_node_rrset_count(node);

	assert(count == 0 || rrsets != NULL);

	for (int r = 0; r < count; ++r) {
		assert(rrsets[r] != NULL);
	}

	free(rrsets);
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Adjusts zone node for faster query processing.
 *
 * This function is just a wrapper over dnslib_zone_adjust_node() to be used
 * in tree-traversing functions.
 *
 * \param node Zone node to adjust.
 * \param data Zone the node belongs to.
 */
static void dnslib_zone_contents_adjust_node_in_tree(dnslib_node_t *node,
                                                     void *data)
{
	assert(data != NULL);
	dnslib_zone_contents_t *zone = (dnslib_zone_contents_t *)data;

	dnslib_zone_contents_adjust_node(node, zone);
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Adjusts NSEC3 node for faster query processing.
 *
 * This function is just a wrapper over dnslib_zone_adjust_nsec3_node() to be
 * used in tree-traversing functions.
 *
 * \param node Zone node to adjust.
 * \param data Zone the node belongs to.
 */
static void dnslib_zone_contents_adjust_nsec3_node_in_tree(dnslib_node_t *node,
                                                           void *data)
{
	assert(data != NULL);
	dnslib_zone_contents_t *zone = (dnslib_zone_contents_t *)data;

	dnslib_zone_contents_adjust_nsec3_node(node, zone);
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Creates a NSEC3 hashed name for the given domain name.
 *
 * \note The zone's NSEC3PARAM record must be parsed prior to calling this
 *       function (see dnslib_zone_load_nsec3param()).
 *
 * \param zone Zone from which to take the NSEC3 parameters.
 * \param name Domain name to hash.
 * \param nsec3_name Hashed name.
 *
 * \retval DNSLIB_EOK
 * \retval DNSLIB_ENSEC3PAR
 * \retval DNSLIB_ECRYPTO
 * \retval DNSLIB_ERROR if an error occured while creating a new domain name
 *                      from the hash or concatenating it with the zone name.
 */
static int dnslib_zone_contents_nsec3_name(const dnslib_zone_contents_t *zone,
                                           const dnslib_dname_t *name,
                                           dnslib_dname_t **nsec3_name)
{
	assert(nsec3_name != NULL);

	*nsec3_name = NULL;

	const dnslib_nsec3_params_t *nsec3_params =
		dnslib_zone_contents_nsec3params(zone);

	if (nsec3_params == NULL) {
DEBUG_DNSLIB_ZONE(
		char *n = dnslib_dname_to_str(zone->apex->owner);
		debug_dnslib_zone("No NSEC3PARAM for zone %s.\n", n);
		free(n);
);
		return DNSLIB_ENSEC3PAR;
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
		debug_dnslib_zone("Error while hashing name %s.\n", n);
		free(n);
		return DNSLIB_ECRYPTO;
	}

	debug_dnslib_zone("Hash: ");
	debug_dnslib_zone_hex((char *)hashed_name, hash_size);
	debug_dnslib_zone("\n");

	char *name_b32 = NULL;
	size_t size = base32hex_encode_alloc((char *)hashed_name, hash_size,
	                                     &name_b32);

	if (size == 0) {
		char *n = dnslib_dname_to_str(name);
		debug_dnslib_zone("Error while encoding hashed name %s to "
		                  "base32.\n", n);
		free(n);
		if (name_b32 != NULL) {
			free(name_b32);
		}
		return DNSLIB_ECRYPTO;
	}

	assert(name_b32 != NULL);
	free(hashed_name);

	debug_dnslib_zone("Base32-encoded hash: %s\n", name_b32);

	*nsec3_name = dnslib_dname_new_from_str(name_b32, size, NULL);

	free(name_b32);

	if (*nsec3_name == NULL) {
		debug_dnslib_zone("Error while creating domain name for hashed"
		                  " name.\n");
		return DNSLIB_ERROR;
	}

	assert(zone->apex->owner != NULL);
	dnslib_dname_t *ret = dnslib_dname_cat(*nsec3_name, zone->apex->owner);

	if (ret == NULL) {
		debug_dnslib_zone("Error while creating NSEC3 domain name for "
		                  "hashed name.\n");
		dnslib_dname_free(nsec3_name);
		return DNSLIB_ERROR;
	}

	assert(ret == *nsec3_name);

	return DNSLIB_EOK;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Tries to find the given domain name in the zone tree.
 *
 * \param zone Zone to search in.
 * \param name Domain name to find.
 * \param node Found node.
 * \param previous Previous node in canonical order (i.e. the one directly
 *                 preceding \a name in canonical order, regardless if the name
 *                 is in the zone or not).
 *
 * \retval <> 0 if the domain name was found. In such case \a node holds the
 *              zone node with \a name as its owner. \a previous is set
 *              properly.
 * \retval 0 if the domain name was not found. \a node may hold any (or none)
 *           node. \a previous is set properly.
 */
static int dnslib_zone_contents_find_in_tree(const dnslib_zone_contents_t *zone,
                                             const dnslib_dname_t *name,
                                             const dnslib_node_t **node,
                                             const dnslib_node_t **previous)
{
	assert(zone != NULL);
	assert(name != NULL);
	assert(node != NULL);
	assert(previous != NULL);

	dnslib_node_t *found = NULL, *prev = NULL;
//	dnslib_node_t *found2 = NULL, *prev2 = NULL;

	int exact_match = dnslib_zone_tree_get_less_or_equal(
	                         zone->nodes, name, &found, &prev);

	*node = found;

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

	return exact_match;
}

/*----------------------------------------------------------------------------*/

static void dnslib_zone_contents_node_to_hash(dnslib_node_t *node, void *data)
{
	assert(node != NULL && node->owner != NULL && data != NULL);

	dnslib_zone_contents_t *zone = (dnslib_zone_contents_t *)data;
	/*
	 * By the original approach, only authoritative nodes and delegation
	 * points should be added to the hash table, but currently, all nodes
	 * are being added when the zone is created (don't know why actually:),
	 * so we will do no distinction here neither.
	 */

#ifdef USE_HASH_TABLE
DEBUG_DNSLIB_ZONE(
	char *name = dnslib_dname_to_str(node->owner);
	debug_dnslib_zone("Adding node with owner %s to hash table.\n", name);
	free(name);
);
	//assert(zone->table != NULL);
	// add the node also to the hash table if authoritative, or deleg. point
	if (zone->table != NULL
	    && ck_insert_item(zone->table,
	                      (const char *)node->owner->name,
	                      node->owner->size, (void *)node) != 0) {
		debug_dnslib_zone("Error inserting node into hash table!\n");
	}
#endif
}

/*----------------------------------------------------------------------------*/

static int dnslib_zone_contents_dnames_from_rdata_to_table(
	dnslib_dname_table_t *table, dnslib_rdata_t *rdata,
	dnslib_rrtype_descriptor_t *d)
{
	unsigned int count = dnslib_rdata_item_count(rdata);
	int rc = 0;
	assert(count <= d->length);
	// for each RDATA item
	for (unsigned int j = 0; j < count; ++j) {
		if (d->wireformat[j]
		    == DNSLIB_RDATA_WF_COMPRESSED_DNAME
		    || d->wireformat[j]
		       == DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME
		    || d->wireformat[j]
		       == DNSLIB_RDATA_WF_LITERAL_DNAME) {
			debug_dnslib_zone("Saving dname from "
					  "rdata to dname table"
					  ".\n");
			rc = dnslib_dname_table_add_dname2(table,
			&dnslib_rdata_get_item(rdata, j)->dname);
			if (rc < 0) {
				debug_dnslib_zone("Error: %s\n",
				  dnslib_strerror(rc));
				return rc;
			}
		}
	}

	debug_dnslib_zone("RDATA OK.\n");
	return DNSLIB_EOK;
}

/*----------------------------------------------------------------------------*/

static int dnslib_zone_contents_dnames_from_rrset_to_table(
	dnslib_dname_table_t *table, dnslib_rrset_t *rrset, int replace_owner,
	dnslib_dname_t *owner)
{
	assert(table != NULL && rrset != NULL && owner != NULL);

	if (replace_owner) {
		// discard the old owner and replace it with the new
		//dnslib_dname_free(&rrset->owner);
		rrset->owner = owner;
	}
	debug_dnslib_zone("RRSet owner: %p\n", rrset->owner);

	dnslib_rrtype_descriptor_t *desc = dnslib_rrtype_descriptor_by_type(
		dnslib_rrset_type(rrset));
	if (desc == NULL) {
		// not recognized RR type, ignore
		debug_dnslib_zone("RRSet type not recognized.\n");
		return DNSLIB_EOK;
	}
	// for each RDATA in RRSet
	dnslib_rdata_t *rdata = dnslib_rrset_get_rdata(rrset);
	while (rdata != NULL) {
		int rc = dnslib_zone_contents_dnames_from_rdata_to_table(table,
		                                                   rdata, desc);
		if (rc != DNSLIB_EOK) {
			return rc;
		}

		rdata = dnslib_rrset_rdata_get_next(rrset, rdata);
	}

	debug_dnslib_zone("RRSet OK.\n");
	return DNSLIB_EOK;
}

/*----------------------------------------------------------------------------*/

static int dnslib_zone_contents_dnames_from_node_to_table(
	dnslib_dname_table_t *table, dnslib_node_t *node)
{
	/*
	 * Assuming that all the RRSets have the same owner as the node.
	 */

	// insert owner
	char *name = dnslib_dname_to_str(node->owner);
	debug_dnslib_zone("Node owner before inserting to dname table: %p.\n",
	                  node->owner);
	debug_dnslib_zone("Node owner before inserting to dname table: %s.\n",
	                  name);
	free(name);
	//dnslib_dname_t *old_owner = node->owner;
	int rc = dnslib_dname_table_add_dname2(table, &node->owner);
	if (rc < 0) {
		debug_dnslib_zone("Failed to add dname to dname table.\n");
		return rc;
	}
	int replace_owner = (rc > 0);
	debug_dnslib_zone("Node owner after inserting to dname table: %p.\n",
	                  node->owner);
	name = dnslib_dname_to_str(node->owner);
	debug_dnslib_zone("Node owner after inserting to dname table: %s.\n",
	                  name);
	free(name);

	dnslib_rrset_t **rrsets = dnslib_node_get_rrsets(node);
	// for each RRSet
	for (int i = 0; i < dnslib_node_rrset_count(node); ++i) {
		debug_dnslib_zone("Inserting RRSets from node to table.\n");
		rc = dnslib_zone_contents_dnames_from_rrset_to_table(table, rrsets[i],
		                                      replace_owner,
		                                      node->owner);
		if (rc != DNSLIB_EOK) {
			return rc;
		}
	}

	free(rrsets);

	debug_dnslib_zone("Node OK\n");
	return DNSLIB_EOK;
}

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

dnslib_zone_contents_t *dnslib_zone_contents_new(dnslib_node_t *apex,
                                                 uint node_count,
                                                 int use_domain_table)
{
	dnslib_zone_contents_t *contents = (dnslib_zone_contents_t *)
	                              calloc(1, sizeof(dnslib_zone_contents_t));
	if (contents == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	contents->apex = apex;

	debug_dnslib_zone("Creating tree for normal nodes.\n");
	contents->nodes = malloc(sizeof(dnslib_zone_tree_t));
	if (contents->nodes == NULL) {
		ERR_ALLOC_FAILED;
		goto cleanup;
	}

	debug_dnslib_zone("Creating tree for NSEC3 nodes.\n");
	contents->nsec3_nodes = malloc(sizeof(dnslib_zone_tree_t));
	if (contents->nsec3_nodes == NULL) {
		ERR_ALLOC_FAILED;
		goto cleanup;
	}

	if (use_domain_table) {
		debug_dnslib_zone("Creating domain name table.\n");
		contents->dname_table = dnslib_dname_table_new();
		if (contents->dname_table == NULL) {
			ERR_ALLOC_FAILED;
			goto cleanup;
		}
	} else {
		contents->dname_table = NULL;
	}

	contents->node_count = node_count;

	/* Initialize NSEC3 params */
	debug_dnslib_zone("Initializing NSEC3 parameters.\n");
	contents->nsec3_params.algorithm = 0;
	contents->nsec3_params.flags = 0;
	contents->nsec3_params.iterations = 0;
	contents->nsec3_params.salt_length = 0;
	contents->nsec3_params.salt = NULL;

	debug_dnslib_zone("Initializing zone trees.\n");
	if (dnslib_zone_tree_init(contents->nodes) != DNSLIB_EOK
	    || dnslib_zone_tree_init(contents->nsec3_nodes) != DNSLIB_EOK) {
		goto cleanup;
	}

	debug_dnslib_zone("Inserting apex into the zone tree.\n");
	if (dnslib_zone_tree_insert(contents->nodes, apex) != DNSLIB_EOK) {
		debug_dnslib_zone("Failed to insert apex to the zone tree.\n");
		goto cleanup;
	}

#ifdef USE_HASH_TABLE
	if (contents->node_count > 0) {
		debug_dnslib_zone("Creating hash table.\n");
		contents->table = ck_create_table(contents->node_count);
		if (contents->table == NULL) {
			goto cleanup;
		}

		// insert the apex into the hash table
		debug_dnslib_zone("Inserting apex into the hash table.\n");
		if (ck_insert_item(contents->table,
		                   (const char *)dnslib_dname_name(
		                                       dnslib_node_owner(apex)),
		                   dnslib_dname_size(dnslib_node_owner(apex)),
		                   (void *)apex) != 0) {
			ck_destroy_table(&contents->table, NULL, 0);
			goto cleanup;
		}
	} else {
		contents->table = NULL;
	}
#endif

	// insert names from the apex to the domain table
	if (use_domain_table) {
		debug_dnslib_zone("Inserting names from apex to table.\n");
		int rc = dnslib_zone_contents_dnames_from_node_to_table(
		             contents->dname_table, apex);
		if (rc != DNSLIB_EOK) {
			ck_destroy_table(&contents->table, NULL, 0);
			goto cleanup;
		}
	}

	return contents;

cleanup:
	debug_dnslib_zone("Cleaning up.\n");
	free(contents->dname_table);
	free(contents->nodes);
	free(contents->nsec3_nodes);
	free(contents);
	return NULL;
}

/*----------------------------------------------------------------------------*/

time_t dnslib_zone_contents_version(const dnslib_zone_contents_t *zone)
{
	return zone->version;
}

/*----------------------------------------------------------------------------*/

void dnslib_zone_contents_set_version(dnslib_zone_contents_t *zone, time_t version)
{
	zone->version = version;
}

/*----------------------------------------------------------------------------*/

short dnslib_zone_contents_generation(const dnslib_zone_contents_t *zone)
{
	return zone->generation;
}

/*----------------------------------------------------------------------------*/

void dnslib_zone_contents_switch_generation(dnslib_zone_contents_t *zone)
{
	zone->generation = 1 - zone->generation;
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_contents_add_node(dnslib_zone_contents_t *zone, dnslib_node_t *node,
                         int create_parents, int use_domain_table)
{
	if (zone == NULL || node == NULL) {
		return DNSLIB_EBADARG;
	}

	int ret = 0;
	if ((ret = dnslib_zone_contents_check_node(zone, node)) != 0) {
		return ret;
	}

	ret = dnslib_zone_tree_insert(zone->nodes, node);
	if (ret != DNSLIB_EOK) {
		debug_dnslib_zone("Failed to insert node into zone tree.\n");
		return ret;
	}

#ifdef USE_HASH_TABLE
DEBUG_DNSLIB_ZONE(
	char *name = dnslib_dname_to_str(node->owner);
	debug_dnslib_zone("Adding node with owner %s to hash table.\n", name);
	free(name);
);
	//assert(zone->table != NULL);
	// add the node also to the hash table if authoritative, or deleg. point
	if (zone->table != NULL
	    && ck_insert_item(zone->table,
	                      (const char *)node->owner->name,
	                      node->owner->size, (void *)node) != 0) {
		debug_dnslib_zone("Error inserting node into hash table!\n");
		/*! \todo Remove the node from the tree. */
		return DNSLIB_EHASH;
	}
#endif
	assert(dnslib_zone_contents_find_node(zone, node->owner));

	if (use_domain_table) {
		ret = dnslib_zone_contents_dnames_from_node_to_table(
		          zone->dname_table, node);
		if (ret != DNSLIB_EOK) {
			/*! \todo Remove the node from the tree and hash table. */
			debug_dnslib_zone("Failed to add dnames into table.\n");
			return ret;
		}
	}

	if (!create_parents) {
		return DNSLIB_EOK;
	}

	debug_dnslib_zone("Creating parents of the node.\n");

	dnslib_dname_t *chopped =
		dnslib_dname_left_chop(node->owner);
	if (dnslib_dname_compare(zone->apex->owner, chopped) == 0) {
		debug_dnslib_zone("Zone apex is the parent.\n");
		node->parent = zone->apex;
	} else {
		dnslib_node_t *next_node;
		while ((next_node
		      = dnslib_zone_contents_get_node(zone, chopped)) == NULL) {
			/* Adding new dname to zone + add to table. */
			debug_dnslib_zone("Creating new node.\n");
			next_node = dnslib_node_new(chopped, NULL);
			if (next_node == NULL) {
				dnslib_dname_free(&chopped);
				return DNSLIB_ENOMEM;
			}
			if (use_domain_table) {
				ret = dnslib_zone_contents_dnames_from_node_to_table(
					zone->dname_table, next_node);
				if (ret != DNSLIB_EOK) {
					return ret;
				}
			}
			node->parent = next_node;

			if (next_node->owner != chopped) {
				assert(0);
				/* Node owner was in RDATA */
				chopped = next_node->owner;
			}

			assert(dnslib_zone_contents_find_node(zone, chopped) == NULL);
			assert(next_node->owner == chopped);

			debug_dnslib_zone("Inserting new node to zone tree.\n");
//			TREE_INSERT(zone->tree, dnslib_node, avl, next_node);

			ret = dnslib_zone_tree_insert(zone->nodes,
			                              next_node);
			if (ret != DNSLIB_EOK) {
				debug_dnslib_zone("Failed to insert new node "
				                  "to zone tree.\n");
				dnslib_dname_free(&chopped);
				return ret;
			}

#ifdef USE_HASH_TABLE
DEBUG_DNSLIB_ZONE(
			char *name = dnslib_dname_to_str(next_node->owner);
			debug_dnslib_zone("Adding new node with owner %s to "
			                  "hash table.\n", name);
			free(name);
);

			if (zone->table != NULL
			    && ck_insert_item(zone->table,
			      (const char *)next_node->owner->name,
			      next_node->owner->size, (void *)next_node) != 0) {
				debug_dnslib_zone("Error inserting node into "
				                  "hash table!\n");
				dnslib_dname_free(&chopped);
				return DNSLIB_EHASH;
			}
#endif
			debug_dnslib_zone("Next parent.\n");
			node =  next_node;
			chopped = dnslib_dname_left_chop(chopped);
		}
		debug_dnslib_zone("Created all parents.\n");
	}
	dnslib_dname_free(&chopped);

	return DNSLIB_EOK;
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_contents_add_rrset(dnslib_zone_contents_t *zone, dnslib_rrset_t *rrset,
                          dnslib_node_t **node,
                          dnslib_rrset_dupl_handling_t dupl,
                          int use_domain_table)
{
	if (zone == NULL || rrset == NULL || zone->apex == NULL
	    || zone->apex->owner == NULL || node == NULL) {
		return DNSLIB_EBADARG;
	}

	// check if the RRSet belongs to the zone
	if (dnslib_dname_compare(dnslib_rrset_owner(rrset),
	                         zone->apex->owner) != 0
	    && !dnslib_dname_is_subdomain(dnslib_rrset_owner(rrset),
	                                  zone->apex->owner)) {
		return DNSLIB_EBADZONE;
	}

	if ((*node) == NULL
	    && (*node = dnslib_zone_contents_get_node(zone, dnslib_rrset_owner(rrset)))
	        == NULL) {
		return DNSLIB_ENONODE;
	}

	assert(*node != NULL);

	// add all domain names from the RRSet to domain name table
	int rc;

	/*! \todo REMOVE RRSET */
	rc = dnslib_node_add_rrset(*node, rrset,
	                           dupl == DNSLIB_RRSET_DUPL_MERGE);
	if (rc < 0) {
		debug_dnslib_zone("Failed to add RRSet to node.\n");
		return rc;
	}

	int ret = rc;

	if (use_domain_table) {
		debug_dnslib_zone("Saving RRSet to table.\n");
		rc = dnslib_zone_contents_dnames_from_rrset_to_table(
		         zone->dname_table, rrset, 0, (*node)->owner);
		if (rc != DNSLIB_EOK) {
			debug_dnslib_zone("Error saving domain names from "
					  "RRSIGs to the domain name table.\n "
					  "The zone may be in an inconsistent "
					  "state.\n");
			// WARNING: the zone is not in consistent state now -
			// there may be domain names in it that are not inserted
			// into the domain table
			return rc;
		}
	}

	// replace RRSet's owner with the node's owner (that is already in the
	// table)
	/*! \todo Do even if domain table is not used?? */
	if (ret == DNSLIB_EOK && rrset->owner != (*node)->owner) {
		dnslib_dname_free(&rrset->owner);
		rrset->owner = (*node)->owner;
	}

	debug_dnslib_zone("RRSet OK.\n");
	return ret;
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_contents_add_rrsigs(dnslib_zone_contents_t *zone, dnslib_rrset_t *rrsigs,
                           dnslib_rrset_t **rrset, dnslib_node_t **node,
                           dnslib_rrset_dupl_handling_t dupl,
                           int use_domain_table)
{
	if (zone == NULL || rrsigs == NULL || rrset == NULL || node == NULL
	    || zone->apex == NULL || zone->apex->owner == NULL) {
		return DNSLIB_EBADARG;
	}

	// check if the RRSet belongs to the zone
	if (*rrset != NULL
	    && dnslib_dname_compare(dnslib_rrset_owner(*rrset),
	                            zone->apex->owner) != 0
	    && !dnslib_dname_is_subdomain(dnslib_rrset_owner(*rrset),
	                                  zone->apex->owner)) {
		return DNSLIB_EBADZONE;
	}

	// check if the RRSIGs belong to the RRSet
	if (*rrset != NULL
	    && (dnslib_dname_compare(dnslib_rrset_owner(rrsigs),
	                             dnslib_rrset_owner(*rrset)) != 0)) {
		return DNSLIB_EBADARG;
	}

	// if no RRSet given, try to find the right RRSet
	if (*rrset == NULL) {
		// even no node given
		// find proper node
		dnslib_node_t *(*get_node)(const dnslib_zone_contents_t *,
		                           const dnslib_dname_t *)
		    = (dnslib_rdata_rrsig_type_covered(
		            dnslib_rrset_rdata(rrsigs)) == DNSLIB_RRTYPE_NSEC3)
		       ? dnslib_zone_contents_get_nsec3_node
		       : dnslib_zone_contents_get_node;

		if (*node == NULL
		    && (*node = get_node(
		                   zone, dnslib_rrset_owner(rrsigs))) == NULL) {
			debug_dnslib_zone("Failed to find node for RRSIGs.\n");
			return DNSLIB_EBADARG;  /*! \todo Other error code? */
		}

		assert(*node != NULL);

		// find the RRSet in the node
		// take only the first RDATA from the RRSIGs
		debug_dnslib_zone("Finding RRSet for type %s\n",
		                  dnslib_rrtype_to_string(
		                      dnslib_rdata_rrsig_type_covered(
		                      dnslib_rrset_rdata(rrsigs))));
		*rrset = dnslib_node_get_rrset(
		             *node, dnslib_rdata_rrsig_type_covered(
		                      dnslib_rrset_rdata(rrsigs)));
		if (*rrset == NULL) {
			debug_dnslib_zone("Failed to find RRSet for RRSIGs.\n");
			return DNSLIB_EBADARG;  /*! \todo Other error code? */
		}
	}

	assert(*rrset != NULL);

	// add all domain names from the RRSet to domain name table
	int rc;
	int ret = DNSLIB_EOK;

	rc = dnslib_rrset_add_rrsigs(*rrset, rrsigs, dupl);
	if (rc < 0) {
		debug_dnslib_dname("Failed to add RRSIGs to RRSet.\n");
		return rc;
	} else if (rc > 0) {
		assert(dupl == DNSLIB_RRSET_DUPL_MERGE);
		ret = 1;
	}

	if (use_domain_table) {
		debug_dnslib_zone("Saving RRSIG RRSet to table.\n");
		rc = dnslib_zone_contents_dnames_from_rrset_to_table(
		       zone->dname_table, rrsigs, 0, (*rrset)->owner);
		if (rc != DNSLIB_EOK) {
			debug_dnslib_zone("Error saving domain names from "
					  "RRSIGs to the domain name table.\n "
					  "The zone may be in an inconsistent "
					  "state.\n");
			// WARNING: the zone is not in consistent state now -
			// there may be domain names in it that are not inserted
			// into the domain table
			return rc;
		}
	}

	// replace RRSet's owner with the node's owner (that is already in the
	// table)
	if ((*rrset)->owner != (*rrset)->rrsigs->owner) {
		dnslib_dname_free(&rrsigs->owner);
		(*rrset)->rrsigs->owner = (*rrset)->owner;
	}

	debug_dnslib_zone("RRSIGs OK\n");
	return ret;
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_contents_add_nsec3_node(dnslib_zone_contents_t *zone, dnslib_node_t *node,
                               int create_parents, int use_domain_table)
{
	if (zone == NULL || node == NULL) {
		return DNSLIB_EBADARG;
	}

	int ret = 0;
	if ((ret = dnslib_zone_contents_check_node(zone, node)) != 0) {
		return ret;
	}

	// how to know if this is successfull??
//	TREE_INSERT(zone->nsec3_nodes, dnslib_node, avl, node);
	dnslib_zone_tree_insert(zone->nsec3_nodes, node);

	if (use_domain_table) {
		ret = dnslib_zone_contents_dnames_from_node_to_table(
		           zone->dname_table, node);
		if (ret != DNSLIB_EOK) {
			/*! \todo Remove the node from the tree. */
			debug_dnslib_zone("Failed to add dnames into table.\n");
			return ret;
		}
	}

	return DNSLIB_EOK;
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_contents_add_nsec3_rrset(dnslib_zone_contents_t *zone, dnslib_rrset_t *rrset,
                                dnslib_node_t **node,
                                dnslib_rrset_dupl_handling_t dupl,
                                int use_domain_table)
{
	if (zone == NULL || rrset == NULL || zone->apex == NULL
	    || zone->apex->owner == NULL || node == NULL) {
		return DNSLIB_EBADARG;
	}

	// check if the RRSet belongs to the zone
	if (dnslib_dname_compare(dnslib_rrset_owner(rrset),
	                         zone->apex->owner) != 0
	    && !dnslib_dname_is_subdomain(dnslib_rrset_owner(rrset),
	                                  zone->apex->owner)) {
		return DNSLIB_EBADZONE;
	}

	if ((*node) == NULL
	    && (*node = dnslib_zone_contents_get_nsec3_node(
	                      zone, dnslib_rrset_owner(rrset))) == NULL) {
		return DNSLIB_ENONODE;
	}

	assert(*node != NULL);

	// add all domain names from the RRSet to domain name table
	int rc;

	/*! \todo REMOVE RRSET */
	rc = dnslib_node_add_rrset(*node, rrset,
	                           dupl == DNSLIB_RRSET_DUPL_MERGE);
	if (rc < 0) {
		return rc;
	}

	int ret = rc;

	if (use_domain_table) {
		debug_dnslib_zone("Saving NSEC3 RRSet to table.\n");
		rc = dnslib_zone_contents_dnames_from_rrset_to_table(
		         zone->dname_table, rrset, 0, (*node)->owner);
		if (rc != DNSLIB_EOK) {
			debug_dnslib_zone("Error saving domain names from "
					  "RRSIGs to the domain name table.\n "
					  "The zone may be in an inconsistent "
					  "state.\n");
			// WARNING: the zone is not in consistent state now -
			// there may be domain names in it that are not inserted
			// into the domain table
			return rc;
		}
	}

	// replace RRSet's owner with the node's owner (that is already in the
	// table)
	/*! \todo Do even if domain table is not used? */
	if (rrset->owner != (*node)->owner) {
		dnslib_dname_free(&rrset->owner);
		rrset->owner = (*node)->owner;
	}

	debug_dnslib_zone("NSEC3 OK\n");
	return ret;
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_contents_create_and_fill_hash_table(dnslib_zone_contents_t *zone)
{
	if (zone == NULL || zone->apex == NULL || zone->apex->owner == NULL) {
		return DNSLIB_EBADARG;
	}
	/*
	 * 1) Create hash table.
	 */
#ifdef USE_HASH_TABLE
	if (zone->node_count > 0) {
		zone->table = ck_create_table(zone->node_count);
		if (zone->table == NULL) {
			return DNSLIB_ENOMEM;
		}

		// insert the apex into the hash table
		if (ck_insert_item(zone->table,
		                (const char *)zone->apex->owner->name,
		                zone->apex->owner->size,
		                (void *)zone->apex) != 0) {
			return DNSLIB_EHASH;
		}
	} else {
		zone->table = NULL;
		return DNSLIB_EOK;	// OK?
	}

	/*
	 * 2) Fill in the hash table.
	 *
	 * In this point, the nodes in the zone must be adjusted, so that only
	 * relevant nodes (authoritative and delegation points are inserted.
	 *
	 * TODO: how to know if this was successful??
	 */
//	TREE_FORWARD_APPLY(zone->tree, dnslib_node, avl,
//	                   dnslib_zone_node_to_hash, zone);
	/*! \todo Replace by zone tree. */
	int ret = dnslib_zone_tree_forward_apply_inorder(zone->nodes,
	                                        dnslib_zone_contents_node_to_hash, zone);
	if (ret != DNSLIB_EOK) {
		debug_dnslib_zone("Failed to insert nodes to hash table.\n");
		return ret;
	}

#endif
	return DNSLIB_EOK;
}

/*----------------------------------------------------------------------------*/

dnslib_node_t *dnslib_zone_contents_get_node(const dnslib_zone_contents_t *zone,
				    const dnslib_dname_t *name)
{
	if (zone == NULL || name == NULL) {
		return NULL;
	}

	// create dummy node to use for lookup
//	dnslib_node_t *tmp = dnslib_node_new((dnslib_dname_t *)name, NULL);
//	dnslib_node_t *n = TREE_FIND(zone->tree, dnslib_node, avl, tmp);
//	dnslib_node_free(&tmp, 0);

	dnslib_node_t *n;
	int ret = dnslib_zone_tree_get(zone->nodes, name, &n);
	if (ret != DNSLIB_EOK) {
		debug_dnslib_zone("Failed to find name in the zone tree.\n");
		return NULL;
	}

	return n;
}

/*----------------------------------------------------------------------------*/

dnslib_node_t *dnslib_zone_contents_get_nsec3_node(const dnslib_zone_contents_t *zone,
					  const dnslib_dname_t *name)
{
	if (zone == NULL || name == NULL) {
		return NULL;
	}

	// create dummy node to use for lookup
//	dnslib_node_t *tmp = dnslib_node_new((dnslib_dname_t *)name, NULL);
//	dnslib_node_t *n = TREE_FIND(zone->nsec3_nodes, dnslib_node, avl, tmp);
//	dnslib_node_free(&tmp, 0);
	dnslib_node_t *n;
	int ret = dnslib_zone_tree_get(zone->nsec3_nodes, name, &n);

	if (ret != DNSLIB_EOK) {
		debug_dnslib_zone("Failed to find NSEC3 name in the zone tree."
		                  "\n");
		return NULL;
	}

	return n;
}

/*----------------------------------------------------------------------------*/

const dnslib_node_t *dnslib_zone_contents_find_node(const dnslib_zone_contents_t *zone,
					   const dnslib_dname_t *name)
{
	return dnslib_zone_contents_get_node(zone, name);
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_contents_find_dname(const dnslib_zone_contents_t *zone,
                           const dnslib_dname_t *name,
                           const dnslib_node_t **node,
                           const dnslib_node_t **closest_encloser,
                           const dnslib_node_t **previous)
{
	if (zone == NULL || name == NULL || node == NULL
	    || closest_encloser == NULL || previous == NULL
	    || zone->apex == NULL || zone->apex->owner == NULL) {
		return DNSLIB_EBADARG;
	}

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
		return DNSLIB_EBADZONE;
	}

	int exact_match = dnslib_zone_contents_find_in_tree(zone, name, node, previous);

DEBUG_DNSLIB_ZONE(
	char *name_str = (*node) ? dnslib_dname_to_str((*node)->owner)
	                         : "(nil)";
	char *name_str2 = (*previous != NULL)
	                  ? dnslib_dname_to_str((*previous)->owner)
	                  : "(nil)";
	debug_dnslib_zone("Search function returned %d, node %s and prev: %s\n",
			  exact_match, name_str, name_str2);

	if (*node) {
		free(name_str);
	}
	if (*previous != NULL) {
		free(name_str2);
	}
);

	*closest_encloser = *node;

	// there must be at least one node with domain name less or equal to
	// the searched name if the name belongs to the zone (the root)
	if (*node == NULL) {
		return DNSLIB_EBADZONE;
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
DEBUG_DNSLIB_ZONE(
	char *n = dnslib_dname_to_str((*closest_encloser)->owner);
	debug_dnslib_zone("Closest encloser: %s\n", n);
	free(n);
);

	debug_dnslib_zone("find_dname() returning %d\n", exact_match);

	return (exact_match)
	       ? DNSLIB_ZONE_NAME_FOUND
	       : DNSLIB_ZONE_NAME_NOT_FOUND;
}

/*----------------------------------------------------------------------------*/

const dnslib_node_t *dnslib_zone_contents_find_previous(const dnslib_zone_contents_t *zone,
                                               const dnslib_dname_t *name)
{
	if (zone == NULL || name == NULL) {
		return NULL;
	}

	const dnslib_node_t *found = NULL, *prev = NULL;

	(void)dnslib_zone_contents_find_in_tree(zone, name, &found, &prev);
	assert(prev != NULL);

	return prev;
}

/*----------------------------------------------------------------------------*/
#ifdef USE_HASH_TABLE
int dnslib_zone_contents_find_dname_hash(const dnslib_zone_contents_t *zone,
                                const dnslib_dname_t *name,
                                const dnslib_node_t **node,
                                const dnslib_node_t **closest_encloser)
{
	if (zone == NULL || name == NULL || node == NULL
	    || closest_encloser == NULL) {
		return DNSLIB_EBADARG;
	}

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
		return DNSLIB_EBADZONE;
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
DEBUG_DNSLIB_ZONE(
	char *n = dnslib_dname_to_str(name_copy);
	debug_dnslib_zone("Finding closest encloser..\nStarting with: %s\n", n);
	free(n);
);

	while (item == NULL) {
		dnslib_dname_left_chop_no_copy(name_copy);
DEBUG_DNSLIB_ZONE(
		char *n = dnslib_dname_to_str(name_copy);
		debug_dnslib_zone("Chopped leftmost label: %s (%.*s, size %u)"
		                  "\n", n, name_copy->size, name_copy->name,
		                  name_copy->size);
		free(n);
);
		// not satisfied in root zone!!
		assert(name_copy->label_count > 0);

		item = ck_find_item(zone->table,
		                    (const char *)name_copy->name,
		                    name_copy->size);
	}

	dnslib_dname_free(&name_copy);

	assert(item != NULL);
	*closest_encloser = (const dnslib_node_t *)item->value;

	return DNSLIB_ZONE_NAME_NOT_FOUND;
}
#endif
/*----------------------------------------------------------------------------*/

const dnslib_node_t *dnslib_zone_contents_find_nsec3_node(const dnslib_zone_contents_t *zone,
                                                 const dnslib_dname_t *name)
{
	return dnslib_zone_contents_get_nsec3_node(zone, name);
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_contents_find_nsec3_for_name(const dnslib_zone_contents_t *zone,
                                    const dnslib_dname_t *name,
                                    const dnslib_node_t **nsec3_node,
                                    const dnslib_node_t **nsec3_previous)
{
	if (zone == NULL || name == NULL
	    || nsec3_node == NULL || nsec3_previous == NULL) {
		return DNSLIB_EBADARG;
	}

	dnslib_dname_t *nsec3_name = NULL;
	int ret = dnslib_zone_contents_nsec3_name(zone, name, &nsec3_name);

	if (ret != DNSLIB_EOK) {
		return ret;
	}

DEBUG_DNSLIB_ZONE(
	char *n = dnslib_dname_to_str(nsec3_name);
	debug_dnslib_zone("NSEC3 node name: %s.\n", n);
	free(n);
);

	const dnslib_node_t *found = NULL, *prev = NULL;

	// create dummy node to use for lookup
	int exact_match = dnslib_zone_tree_find_less_or_equal(
		zone->nsec3_nodes, name, &found, &prev);

DEBUG_DNSLIB_ZONE(
	if (found) {
		char *n = dnslib_dname_to_str(found->owner);
		debug_dnslib_zone("Found NSEC3 node: %s.\n", n);
		free(n);
	} else {
		debug_dnslib_zone("Found no NSEC3 node.\n");
	}

	if (prev) {
		assert(prev->owner);
		char *n = dnslib_dname_to_str(prev->owner);
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
		*nsec3_previous = dnslib_node_previous(*nsec3_node);
	} else {
		*nsec3_previous = prev;
	}

	debug_dnslib_zone("find_nsec3_for_name() returning %d\n", exact_match);

	return (exact_match)
	       ? DNSLIB_ZONE_NAME_FOUND
	       : DNSLIB_ZONE_NAME_NOT_FOUND;
}

/*----------------------------------------------------------------------------*/

const dnslib_node_t *dnslib_zone_contents_apex(const dnslib_zone_contents_t *zone)
{
	if (zone == NULL) {
		return NULL;
	}

	return zone->apex;
}

/*----------------------------------------------------------------------------*/

dnslib_node_t *dnslib_zone_contents_get_apex(const dnslib_zone_contents_t *zone)
{
	if (zone == NULL) {
		return NULL;
	}

	return zone->apex;
}

/*----------------------------------------------------------------------------*/

//dnslib_dname_t *dnslib_zone_contents_name(const dnslib_zone_contents_t *zone)
//{
//	if (zone == NULL) {
//		return NULL;
//	}

//	return zone->name;
//}

/*----------------------------------------------------------------------------*/

int dnslib_zone_contents_adjust_dnames(dnslib_zone_contents_t *zone)
{
	if (zone == NULL) {
		return DNSLIB_EBADARG;
	}

	// load NSEC3PARAM (needed on adjusting function)
	dnslib_zone_contents_load_nsec3param(zone);

	/*! \todo Replace by zone tree. */
//	TREE_FORWARD_APPLY(zone->tree, dnslib_node, avl,
//	                   dnslib_zone_adjust_node_in_tree, zone);

//	TREE_FORWARD_APPLY(zone->nsec3_nodes, dnslib_node, avl,
//	                   dnslib_zone_adjust_nsec3_node_in_tree, zone);

	int ret = dnslib_zone_tree_forward_apply_inorder(zone->nodes,
	                                 dnslib_zone_contents_adjust_node_in_tree, zone);
	if (ret != DNSLIB_EOK) {
		return ret;
	}

	ret = dnslib_zone_tree_forward_apply_inorder(
	              zone->nsec3_nodes,
	              dnslib_zone_contents_adjust_nsec3_node_in_tree, zone);

	return ret;
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_contents_load_nsec3param(dnslib_zone_contents_t *zone)
{
	if (zone == NULL || zone->apex == NULL) {
		return DNSLIB_EBADARG;
	}

	const dnslib_rrset_t *rrset = dnslib_node_rrset(zone->apex,
						      DNSLIB_RRTYPE_NSEC3PARAM);

	if (rrset != NULL) {
		dnslib_nsec3_params_from_wire(&zone->nsec3_params, rrset);
	} else {
		memset(&zone->nsec3_params, 0, sizeof(dnslib_nsec3_params_t));
	}

	return DNSLIB_EOK;
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_contents_nsec3_enabled(const dnslib_zone_contents_t *zone)
{
	if (zone == NULL) {
		return DNSLIB_EBADARG;
	}

	return (zone->nsec3_params.algorithm != 0);
}

/*----------------------------------------------------------------------------*/

const dnslib_nsec3_params_t *dnslib_zone_contents_nsec3params(const dnslib_zone_contents_t *zone)
{
	if (zone == NULL) {
		return NULL;
	}

	if (dnslib_zone_contents_nsec3_enabled(zone)) {
		return &zone->nsec3_params;
	} else {
		return NULL;
	}
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_contents_tree_apply_postorder(dnslib_zone_contents_t *zone,
                              void (*function)(dnslib_node_t *node, void *data),
                              void *data)
{
	if (zone == NULL) {
		return DNSLIB_EBADARG;
	}

	return dnslib_zone_tree_forward_apply_postorder(zone->nodes,
	                                                function, data);
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_contents_tree_apply_inorder(dnslib_zone_contents_t *zone,
                              void (*function)(dnslib_node_t *node, void *data),
                              void *data)
{
	if (zone == NULL) {
		return DNSLIB_EBADARG;
	}

	return dnslib_zone_tree_forward_apply_inorder(zone->nodes,
	                                              function, data);
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_contents_tree_apply_inorder_reverse(dnslib_zone_contents_t *zone,
                              void (*function)(dnslib_node_t *node, void *data),
                              void *data)
{
	if (zone == NULL) {
		return DNSLIB_EBADARG;
	}

	return dnslib_zone_tree_reverse_apply_inorder(zone->nodes,
	                                              function, data);
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_contents_nsec3_apply_postorder(dnslib_zone_contents_t *zone,
                              void (*function)(dnslib_node_t *node, void *data),
                              void *data)
{
	if (zone == NULL) {
		return DNSLIB_EBADARG;
	}

	return dnslib_zone_tree_forward_apply_postorder(
			zone->nsec3_nodes, function, data);
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_contents_nsec3_apply_inorder(dnslib_zone_contents_t *zone,
                              void (*function)(dnslib_node_t *node, void *data),
                              void *data)
{
	if (zone == NULL) {
		return DNSLIB_EBADARG;
	}

	/*! \todo Replace by zone tree. */
//	TREE_FORWARD_APPLY(zone->nsec3_nodes, dnslib_node, avl, function, data);
	return dnslib_zone_tree_forward_apply_inorder(
			zone->nsec3_nodes, function, data);
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_contents_nsec3_apply_inorder_reverse(dnslib_zone_contents_t *zone,
                              void (*function)(dnslib_node_t *node, void *data),
                              void *data)
{
	if (zone == NULL) {
		return DNSLIB_EBADARG;
	}

	return dnslib_zone_tree_reverse_apply_inorder(
			zone->nsec3_nodes, function, data);
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_contents_shallow_copy(const dnslib_zone_contents_t *from,
                             dnslib_zone_contents_t **to)
{
	if (from == NULL || to == NULL) {
		return DNSLIB_EBADARG;
	}

	int ret = DNSLIB_EOK;

	dnslib_zone_contents_t *contents = (dnslib_zone_contents_t *)calloc(
	                                     1, sizeof(dnslib_zone_contents_t));
	if (contents == NULL) {
		ERR_ALLOC_FAILED;
		return DNSLIB_ENOMEM;
	}

	contents->apex = from->apex;

	contents->nodes = malloc(sizeof(dnslib_zone_tree_t));
	if (contents->nodes == NULL) {
		ERR_ALLOC_FAILED;
		ret = DNSLIB_ENOMEM;
		goto cleanup;
	}

	contents->nsec3_nodes = malloc(sizeof(dnslib_zone_tree_t));
	if (contents->nsec3_nodes == NULL) {
		ERR_ALLOC_FAILED;
		ret = DNSLIB_ENOMEM;
		goto cleanup;
	}

	if (from->dname_table != NULL) {
		contents->dname_table = dnslib_dname_table_new();
		if (contents->dname_table == NULL) {
			ERR_ALLOC_FAILED;
			ret = DNSLIB_ENOMEM;
			goto cleanup;
		}
		if ((ret = dnslib_dname_table_copy(from->dname_table,
		                        contents->dname_table)) != DNSLIB_EOK) {
			goto cleanup;
		}
	} else {
		contents->dname_table = NULL;
	}

	contents->node_count = from->node_count;
	contents->generation = from->generation;

	/* Initialize NSEC3 params */
	memcpy(&contents->nsec3_params, &from->nsec3_params,
	       sizeof(dnslib_nsec3_params_t));

	if ((ret = dnslib_zone_tree_copy(from->nodes,
	                                 contents->nodes)) != DNSLIB_EOK
	    || (ret = dnslib_zone_tree_copy(from->nsec3_nodes,
	                                contents->nsec3_nodes)) != DNSLIB_EOK) {
		goto cleanup;
	}

#ifdef USE_HASH_TABLE
	ret = ck_copy_table(from->table, &contents->table);
	if (ret != 0) {
		ret = DNSLIB_ERROR;
		goto cleanup;
	}
#endif

	*to = contents;
	return DNSLIB_EOK;

cleanup:
	dnslib_zone_tree_free(&contents->nodes);
	dnslib_zone_tree_free(&contents->nsec3_nodes);
	free(contents->dname_table);
	free(contents);
	return ret;
}

/*----------------------------------------------------------------------------*/

void dnslib_zone_contents_free(dnslib_zone_contents_t **contents)
{
	if (contents == NULL || *contents == NULL) {
		return;
	}

	// free the zone tree, but only the structure
	dnslib_zone_tree_free(&(*contents)->nodes);
	dnslib_zone_tree_free(&(*contents)->nsec3_nodes);

#ifdef USE_HASH_TABLE
	if ((*contents)->table != NULL) {
		ck_destroy_table(&(*contents)->table, NULL, 0);
	}
#endif
	dnslib_nsec3_params_free(&(*contents)->nsec3_params);

	free(*contents);
	*contents = NULL;
}

/*----------------------------------------------------------------------------*/

void dnslib_zone_contents_deep_free(dnslib_zone_contents_t **contents)
{
	if (contents == NULL || *contents == NULL) {
		return;
	}

	if ((*contents) != NULL) {

#ifdef USE_HASH_TABLE
		if ((*contents)->table != NULL) {
			ck_destroy_table(&(*contents)->table, NULL, 0);
		}
#endif
		/* has to go through zone twice, rdata may contain references to
		   node owners earlier in the zone which may be already freed */
		/* NSEC3 tree is deleted first as it may contain references to
		   the normal tree. */

		dnslib_zone_tree_forward_apply_postorder(
			(*contents)->nsec3_nodes,
			dnslib_zone_contents_destroy_node_rrsets_from_tree, 0);

		dnslib_zone_tree_forward_apply_postorder(
			(*contents)->nsec3_nodes,
			dnslib_zone_contents_destroy_node_owner_from_tree, 0);

		dnslib_zone_tree_forward_apply_postorder(
			(*contents)->nodes,
			dnslib_zone_contents_destroy_node_rrsets_from_tree, 0);

		dnslib_zone_tree_forward_apply_postorder(
			(*contents)->nodes,
			dnslib_zone_contents_destroy_node_owner_from_tree, 0);

		// free the zone tree, but only the structure
		// (nodes are already destroyed)
		debug_dnslib_zone("Destroying zone tree.\n");
		dnslib_zone_tree_free(&(*contents)->nodes);
		debug_dnslib_zone("Destroying NSEC3 zone tree.\n");
		dnslib_zone_tree_free(&(*contents)->nsec3_nodes);

		dnslib_nsec3_params_free(&(*contents)->nsec3_params);

		dnslib_dname_table_deep_free(&(*contents)->dname_table);
	}

	free((*contents));
	*contents = NULL;
}

