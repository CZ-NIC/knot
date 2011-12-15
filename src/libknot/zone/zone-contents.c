/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <assert.h>

#include "zone/zone-contents.h"
#include "util/error.h"
#include "util/debug.h"
#include "common/base32hex.h"
#include "consts.h"

/*----------------------------------------------------------------------------*/
/* Non-API functions                                                          */
/*----------------------------------------------------------------------------*/

typedef struct {
	void (*func)(knot_node_t *, void *);
	void *data;
} knot_zone_tree_func_t;

typedef struct {
	knot_node_t *first_node;
	knot_zone_contents_t *zone;
	knot_node_t *previous_node;
	int check_ver;
} knot_zone_adjust_arg_t;

/*----------------------------------------------------------------------------*/

static void knot_zone_tree_apply(knot_zone_tree_node_t *node,
                                   void *data)
{
	if (node == NULL || data == NULL) {
		return;
	}

	knot_zone_tree_func_t *f = (knot_zone_tree_func_t *)data;
	f->func(node->node, f->data);
}

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
 * \retval KNOT_EOK if both arguments are non-NULL and the node belongs to the
 *         zone.
 * \retval KNOT_EBADARG if either of the arguments is NULL.
 * \retval KNOT_EBADZONE if the node does not belong to the zone.
 */
static int knot_zone_contents_check_node(
	const knot_zone_contents_t *contents, const knot_node_t *node)
{
	if (contents == NULL || node == NULL) {
		return KNOT_EBADARG;
	}

	// assert or just check??
	assert(contents->apex != NULL);

	if (!knot_dname_is_subdomain(node->owner,
	                               knot_node_owner(contents->apex))) {
dbg_zone_exec(
		char *node_owner = knot_dname_to_str(knot_node_owner(node));
		char *apex_owner = knot_dname_to_str(contents->apex->owner);
		dbg_zone("zone: Trying to insert foreign node to a "
				  "zone. Node owner: %s, zone apex: %s\n",
				  node_owner, apex_owner);
		free(node_owner);
		free(apex_owner);
);
		return KNOT_EBADZONE;
	}
	return KNOT_EOK;
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
static void knot_zone_contents_destroy_node_rrsets_from_tree(
	knot_zone_tree_node_t *tnode, void *data)
{
	assert(tnode != NULL);
	assert(tnode->node != NULL);

	int free_rdata_dnames = (int)((intptr_t)data);
	knot_node_free_rrsets(tnode->node, free_rdata_dnames);
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
static void knot_zone_contents_destroy_node_owner_from_tree(
	knot_zone_tree_node_t *tnode, void *data)
{
	assert(tnode != NULL);
	assert(tnode->node != NULL);

	UNUSED(data);
	/*!< \todo change completely! */
	knot_node_free(&tnode->node, 0, 0);
}

/*!
 * \brief Finds and sets wildcard child for given node's owner.
 *
 * \param zone Current zone.
 * \param node Node to be used.
 */
static void find_and_set_wildcard_child(knot_zone_contents_t *zone,
				 knot_node_t *node)
{
	knot_dname_t *chopped = knot_dname_left_chop(node->owner);
	assert(chopped);
	knot_node_t *wildcard_parent;
	wildcard_parent =
		knot_zone_contents_get_node(zone, chopped);

	knot_dname_free(&chopped);

	assert(wildcard_parent); /* it *has* to be there */

	knot_node_set_wildcard_child(wildcard_parent, node);
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
static void knot_zone_contents_adjust_rdata_item(knot_rdata_t *rdata,
                                          knot_zone_contents_t *zone,
                                          knot_node_t *node,
                                          int pos)
{
	return;
	const knot_rdata_item_t *dname_item
			= knot_rdata_item(rdata, pos);

	assert(dname_item);

	if (dname_item != NULL) {
		knot_dname_t *dname = dname_item->dname;
		const knot_node_t *n = NULL;
		const knot_node_t *closest_encloser = NULL;
		const knot_node_t *prev = NULL;

		if (knot_dname_is_wildcard(dname)) {
			find_and_set_wildcard_child(zone, node);
		}

		int ret = knot_zone_contents_find_dname(zone, dname, &n,
		                                      &closest_encloser, &prev);

		//		n = knot_zone_find_node(zone, dname);

		if (ret == KNOT_EBADARG || ret == KNOT_EBADZONE) {
			// TODO: do some cleanup if needed
			return;
		}

		assert(ret != KNOT_ZONE_NAME_FOUND
		       || n == closest_encloser);

		if (ret != KNOT_ZONE_NAME_FOUND
		                && (closest_encloser != NULL)) {
			dbg_zone("Saving closest encloser to RDATA.\n");
			// save pointer to the closest encloser
			knot_rdata_item_t *item =
					knot_rdata_get_item(rdata, pos);
			assert(item->dname != NULL);
			assert(item->dname->node == NULL);
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
 * knot_zone_adjust_rdata_item().
 *
 * \param rrset RRSet to adjust RDATA in.
 * \param zone Zone to which the RRSet belongs.
 */
static void knot_zone_contents_adjust_rdata_in_rrset(knot_rrset_t *rrset,
                                                   knot_zone_contents_t *zone,
                                                   knot_node_t *node)
{
	uint16_t type = knot_rrset_type(rrset);

	knot_rrtype_descriptor_t *desc =
		knot_rrtype_descriptor_by_type(type);
	assert(desc);

	knot_rdata_t *rdata_first = knot_rrset_get_rdata(rrset);
	knot_rdata_t *rdata = rdata_first;

	if (rdata == NULL) {
		return;
	}

	while (rdata->next != rdata_first) {
		for (int i = 0; i < rdata->count; ++i) {
			if (desc->wireformat[i]
			    == KNOT_RDATA_WF_COMPRESSED_DNAME
			    || desc->wireformat[i]
			       == KNOT_RDATA_WF_UNCOMPRESSED_DNAME
			    || desc->wireformat[i]
			       == KNOT_RDATA_WF_LITERAL_DNAME) {
				dbg_zone("Adjusting domain name at "
				  "position %d of RDATA of record with owner "
				  "%s and type %s.\n",
				  i, rrset->owner->name,
				  knot_rrtype_to_string(type));

				knot_zone_contents_adjust_rdata_item(rdata,
				                                       zone,
				                                       node,
				                                       i);
			}
		}
		rdata = rdata->next;
	}

	for (int i = 0; i < rdata->count; ++i) {
		if (desc->wireformat[i]
		    == KNOT_RDATA_WF_COMPRESSED_DNAME
		    || desc->wireformat[i]
		       == KNOT_RDATA_WF_UNCOMPRESSED_DNAME
		    || desc->wireformat[i]
		       == KNOT_RDATA_WF_LITERAL_DNAME) {
			dbg_zone("Adjusting domain name at "
			  "position %d of RDATA of record with owner "
			  "%s and type %s.\n",
			  i, rrset->owner->name,
			  knot_rrtype_to_string(type));

			knot_zone_contents_adjust_rdata_item(rdata, zone,
			                                       node, i);
		}
	}

}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Adjusts all RRSets in the given node by replacing domain names in
 *        RDATA by ones present in the zone.
 *
 * This function just calls knot_zone_adjust_rdata_in_rrset() for all RRSets
 * in the node (including all RRSIG RRSets).
 *
 * \param node Zone node to adjust the RRSets in.
 * \param zone Zone to which the node belongs.
 */
static void knot_zone_contents_adjust_rrsets(knot_node_t *node,
                                               knot_zone_contents_t *zone)
{
	//return;
	knot_rrset_t **rrsets = knot_node_get_rrsets(node);
	short count = knot_node_rrset_count(node);

	assert(count == 0 || rrsets != NULL);

	for (int r = 0; r < count; ++r) {
		assert(rrsets[r] != NULL);
		dbg_zone("Adjusting next RRSet.\n");
		knot_zone_contents_adjust_rdata_in_rrset(rrsets[r], zone,
		                                           node);
		knot_rrset_t *rrsigs = rrsets[r]->rrsigs;
		if (rrsigs != NULL) {
			dbg_zone("Adjusting next RRSIGs.\n");
			knot_zone_contents_adjust_rdata_in_rrset(rrsigs,
			                                           zone,
			                                           node);
		}
	}

	free(rrsets);
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Adjusts zone node for faster query processing.
 *
 * - Adjusts RRSets in the node (see knot_zone_adjust_rrsets()).
 * - Marks the node as delegation point or non-authoritative (below a zone cut)
 *   if applicable.
 * - Stores reference to corresponding NSEC3 node if applicable.
 *
 * \param node Zone node to adjust.
 * \param zone Zone the node belongs to.
 */
static void knot_zone_contents_adjust_node(knot_node_t *node,
                                             knot_zone_contents_t *zone,
					     int check_ver)
{

dbg_zone_exec(
	char *name = knot_dname_to_str(node->owner);
	dbg_zone("----- Adjusting node %s -----\n", name);
	free(name);
);

	// adjust domain names in RDATA
	knot_zone_contents_adjust_rrsets(node, zone);

dbg_zone_exec(
	if (knot_node_parent(node, 1)) {
		char *name = knot_dname_to_str(knot_node_owner(
				knot_node_parent(node, check_ver)));
		dbg_zone("Parent: %s\n", name);
		dbg_zone("Parent is delegation point: %s\n",
		       knot_node_is_deleg_point(knot_node_parent(node, check_ver))
		       ? "yes" : "no");
		dbg_zone("Parent is non-authoritative: %s\n",
		       knot_node_is_non_auth(knot_node_parent(node, check_ver))
		       ? "yes" : "no");
		free(name);
	} else {
		dbg_zone("No parent!\n");
	}
);
	// delegation point / non-authoritative node
	if (knot_node_parent(node, check_ver)
	    && (knot_node_is_deleg_point(knot_node_parent(node, check_ver))
		|| knot_node_is_non_auth(knot_node_parent(node, check_ver)))) {
		knot_node_set_non_auth(node);
	} else if (knot_node_rrset(node, KNOT_RRTYPE_NS) != NULL
		   && node != zone->apex) {
		knot_node_set_deleg_point(node);
	}

	// authorative node?
//	if (!knot_node_is_non_auth(node)) {
		zone->node_count++;
//	}

	// assure that owner has proper node
	if (knot_dname_node(knot_node_owner(node), 0) == NULL) {
		knot_dname_set_node(knot_node_get_owner(node), node);
		knot_dname_set_node(knot_node_get_owner(node), node);
	}

	// NSEC3 node (only if NSEC3 tree is not empty)
	const knot_node_t *prev;
	const knot_node_t *nsec3;
	int match = knot_zone_contents_find_nsec3_for_name(zone,
					knot_node_owner(node),
					&nsec3, &prev, check_ver);
	if (match != KNOT_ZONE_NAME_FOUND) {
		nsec3 = NULL;
	}

	knot_node_set_nsec3_node(node, (knot_node_t *)nsec3);

	dbg_zone("Set flags to the node: \n");
	dbg_zone("Delegation point: %s\n",
	       knot_node_is_deleg_point(node) ? "yes" : "no");
	dbg_zone("Non-authoritative: %s\n",
	       knot_node_is_non_auth(node) ? "yes" : "no");
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Adjusts zone node for faster query processing.
 *
 * This function is just a wrapper over knot_zone_adjust_node() to be used
 * in tree-traversing functions.
 *
 * \param node Zone node to adjust.
 * \param data Zone the node belongs to.
 */
static void knot_zone_contents_adjust_node_in_tree(
		knot_zone_tree_node_t *tnode, void *data)
{
	assert(data != NULL);
	assert(tnode != NULL);
	assert(tnode->node != NULL);

	knot_zone_adjust_arg_t *args = (knot_zone_adjust_arg_t *)data;
	knot_node_t *node = tnode->node;
	knot_node_set_previous(node, args->previous_node);
	args->previous_node = node;
	if (args->first_node == NULL) {
		args->first_node = node;
	}
	knot_zone_contents_t *zone = args->zone;

	knot_zone_contents_adjust_node(node, zone, args->check_ver);
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Adjusts NSEC3 node for faster query processing.
 *
 * This function is just a wrapper over knot_zone_adjust_nsec3_node() to be
 * used in tree-traversing functions.
 *
 * \param node Zone node to adjust.
 * \param data Zone the node belongs to.
 */
static void knot_zone_contents_adjust_nsec3_node_in_tree(
		knot_zone_tree_node_t *tnode, void *data)
{
	assert(data != NULL);
	assert(tnode != NULL);
	assert(tnode->node != NULL);

	knot_zone_adjust_arg_t *args = (knot_zone_adjust_arg_t *)data;
	knot_node_t *node = tnode->node;
	knot_node_set_previous(node, args->previous_node);
	args->previous_node = node;
	if (args->first_node == NULL) {
		args->first_node = node;
	}

	/* Not needed anymore. */
//	knot_zone_contents_t *zone = args->zone;
//	knot_zone_contents_adjust_nsec3_node(node, zone, 1);
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Creates a NSEC3 hashed name for the given domain name.
 *
 * \note The zone's NSEC3PARAM record must be parsed prior to calling this
 *       function (see knot_zone_load_nsec3param()).
 *
 * \param zone Zone from which to take the NSEC3 parameters.
 * \param name Domain name to hash.
 * \param nsec3_name Hashed name.
 *
 * \retval KNOT_EOK
 * \retval KNOT_ENSEC3PAR
 * \retval KNOT_ECRYPTO
 * \retval KNOT_ERROR if an error occured while creating a new domain name
 *                      from the hash or concatenating it with the zone name.
 */
static int knot_zone_contents_nsec3_name(const knot_zone_contents_t *zone,
                                           const knot_dname_t *name,
                                           knot_dname_t **nsec3_name)
{
	assert(nsec3_name != NULL);

	*nsec3_name = NULL;

	const knot_nsec3_params_t *nsec3_params =
		knot_zone_contents_nsec3params(zone);

	if (nsec3_params == NULL) {
dbg_zone_exec(
		char *n = knot_dname_to_str(zone->apex->owner);
		dbg_zone("No NSEC3PARAM for zone %s.\n", n);
		free(n);
);
		return KNOT_ENSEC3PAR;
	}

	uint8_t *hashed_name = NULL;
	size_t hash_size = 0;

dbg_zone_exec(
	char *n = knot_dname_to_str(name);
	dbg_zone("Hashing name %s.\n", n);
	free(n);
);

	int res = knot_nsec3_sha1(nsec3_params, knot_dname_name(name),
	                            knot_dname_size(name), &hashed_name,
	                            &hash_size);

	if (res != 0) {
		char *n = knot_dname_to_str(name);
		dbg_zone("Error while hashing name %s.\n", n);
		free(n);
		return KNOT_ECRYPTO;
	}

	dbg_zone("Hash: ");
	dbg_zone_hex((char *)hashed_name, hash_size);
	dbg_zone("\n");

	char *name_b32 = NULL;
	size_t size = base32hex_encode_alloc((char *)hashed_name, hash_size,
	                                     &name_b32);

	if (size == 0) {
		char *n = knot_dname_to_str(name);
		dbg_zone("Error while encoding hashed name %s to "
		                  "base32.\n", n);
		free(n);
		if (name_b32 != NULL) {
			free(name_b32);
		}
		return KNOT_ECRYPTO;
	}

	assert(name_b32 != NULL);
	free(hashed_name);

	dbg_zone("Base32-encoded hash: %s\n", name_b32);

	/* Will be returned to caller, make sure it is released after use. */
	*nsec3_name = knot_dname_new_from_str(name_b32, size, NULL);

	free(name_b32);

	if (*nsec3_name == NULL) {
		dbg_zone("Error while creating domain name for hashed"
		                  " name.\n");
		return KNOT_ERROR;
	}

	assert(zone->apex->owner != NULL);
	knot_dname_t *ret = knot_dname_cat(*nsec3_name, zone->apex->owner);

	if (ret == NULL) {
		dbg_zone("Error while creating NSEC3 domain name for "
		                  "hashed name.\n");
		knot_dname_release(*nsec3_name);
		return KNOT_ERROR;
	}

	assert(ret == *nsec3_name);

	return KNOT_EOK;
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
static int knot_zone_contents_find_in_tree(knot_zone_tree_t *tree,
                                             const knot_dname_t *name,
                                             knot_node_t **node,
                                             knot_node_t **previous)
{
	assert(tree != NULL);
	assert(name != NULL);
	assert(node != NULL);
	assert(previous != NULL);

	knot_node_t *found = NULL, *prev = NULL;
//	knot_node_t *found2 = NULL, *prev2 = NULL;

	int exact_match = knot_zone_tree_get_less_or_equal(
	                         tree, name, &found, &prev, 1);

//	assert(prev != NULL);
	assert(exact_match >= 0);
	*node = found;
	*previous = prev;

//	if (prev == NULL) {
//		// either the returned node is the root of the tree, or it is
//		// the leftmost node in the tree; in both cases node was found
//		// set the previous node of the found node
//		assert(exact_match);
//		assert(found != NULL);
//		*previous = knot_node_get_previous(found, 1);
//	} else {
//		// otherwise check if the previous node is not an empty
//		// non-terminal
//		*previous = (knot_node_rrset_count(prev) == 0)
//		            ? knot_node_get_previous(prev, 1)
//		            : prev;
//	}

	return exact_match;
}

/*----------------------------------------------------------------------------*/

static void knot_zone_contents_node_to_hash(knot_zone_tree_node_t *tnode,
                                              void *data)
{
	assert(tnode != NULL && tnode->node != NULL
	       && tnode->node->owner != NULL && data != NULL);

	knot_node_t *node = tnode->node;

	knot_zone_contents_t *zone = (knot_zone_contents_t *)data;
	/*
	 * By the original approach, only authoritative nodes and delegation
	 * points should be added to the hash table, but currently, all nodes
	 * are being added when the zone is created (don't know why actually:),
	 * so we will do no distinction here neither.
	 */

#ifdef USE_HASH_TABLE
//dbg_zone_exec(
//	char *name = knot_dname_to_str(node->owner);
//	dbg_zone("Adding node with owner %s to hash table.\n", name);
//	free(name);
//);
	//assert(zone->table != NULL);
	// add the node also to the hash table if authoritative, or deleg. point
	if (zone->table != NULL
	    && ck_insert_item(zone->table,
	                      (const char *)node->owner->name,
	                      node->owner->size, (void *)node) != 0) {
		dbg_zone("Error inserting node into hash table!\n");
	}
#endif
}

/*----------------------------------------------------------------------------*/

static int knot_zone_contents_dnames_from_rdata_to_table(
	knot_dname_table_t *table, knot_rdata_t *rdata,
	knot_rrtype_descriptor_t *d)
{
	unsigned int count = knot_rdata_item_count(rdata);
	int rc = 0;
	if (d->fixed_items) {
		assert(count <= d->length);
	}
	// for each RDATA item
	for (unsigned int j = 0; j < count; ++j) {
		if (d->wireformat[j]
		    == KNOT_RDATA_WF_COMPRESSED_DNAME
		    || d->wireformat[j]
		       == KNOT_RDATA_WF_UNCOMPRESSED_DNAME
		    || d->wireformat[j]
		       == KNOT_RDATA_WF_LITERAL_DNAME) {
			dbg_zone("Saving dname from "
					  "rdata to dname table"
					  ".\n");
			rc = knot_dname_table_add_dname_check(table,
			&knot_rdata_get_item(rdata, j)->dname);
			if (rc < 0) {
				dbg_zone("Error: %s\n",
				  knot_strerror(rc));
				return rc;
			}
		}
	}

	dbg_zone("RDATA OK.\n");
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int knot_zone_contents_dnames_from_rrset_to_table(
	knot_dname_table_t *table, knot_rrset_t *rrset, int replace_owner,
	knot_dname_t *owner)
{
	assert(table != NULL && rrset != NULL && owner != NULL);

	if (replace_owner) {
		// discard the old owner and replace it with the new
		knot_rrset_set_owner(rrset, owner);
	}
	dbg_zone("RRSet owner: %p\n", rrset->owner);

	knot_rrtype_descriptor_t *desc = knot_rrtype_descriptor_by_type(
		knot_rrset_type(rrset));
	if (desc == NULL) {
		// not recognized RR type, ignore
		dbg_zone("RRSet type not recognized.\n");
		return KNOT_EOK;
	}
	// for each RDATA in RRSet
	knot_rdata_t *rdata = knot_rrset_get_rdata(rrset);
	while (rdata != NULL) {
		int rc = knot_zone_contents_dnames_from_rdata_to_table(table,
		                                                   rdata, desc);
		if (rc != KNOT_EOK) {
			return rc;
		}

		rdata = knot_rrset_rdata_get_next(rrset, rdata);
	}

	dbg_zone("RRSet OK.\n");
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int knot_zone_contents_dnames_from_node_to_table(
	knot_dname_table_t *table, knot_node_t *node)
{
	/*
	 * Assuming that all the RRSets have the same owner as the node.
	 */

	// insert owner
	char *name = knot_dname_to_str(node->owner);
	dbg_zone("Node owner before inserting to dname table: %p.\n",
	                  node->owner);
	dbg_zone("Node owner before inserting to dname table: %s.\n",
	                  name);
	free(name);
	//knot_dname_t *old_owner = node->owner;
	int rc = knot_dname_table_add_dname_check(table, &node->owner);
	if (rc < 0) {
		dbg_zone("Failed to add dname to dname table.\n");
		return rc;
	}
	int replace_owner = (rc > 0);
	dbg_zone("Node owner after inserting to dname table: %p.\n",
	                  node->owner);
	name = knot_dname_to_str(node->owner);
	dbg_zone("Node owner after inserting to dname table: %s.\n",
	                  name);
	free(name);

	knot_rrset_t **rrsets = knot_node_get_rrsets(node);
	// for each RRSet
	for (int i = 0; i < knot_node_rrset_count(node); ++i) {
		dbg_zone("Inserting RRSets from node to table.\n");
		rc = knot_zone_contents_dnames_from_rrset_to_table(table,
			rrsets[i], replace_owner, node->owner);
		if (rc != KNOT_EOK) {
			return rc;
		}
	}

	free(rrsets);

	dbg_zone("Node OK\n");
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

knot_zone_contents_t *knot_zone_contents_new(knot_node_t *apex,
                                                 uint node_count,
                                                 int use_domain_table,
                                                 struct knot_zone *zone)
{
	knot_zone_contents_t *contents = (knot_zone_contents_t *)
	                              calloc(1, sizeof(knot_zone_contents_t));
	if (contents == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

//	printf("created cont: %p (%s)\n",
//	       contents, knot_dname_to_str(apex->owner));

	contents->apex = apex;
	contents->zone = zone;
	knot_node_set_zone(apex, zone);

	dbg_zone("Creating tree for normal nodes.\n");
	contents->nodes = malloc(sizeof(knot_zone_tree_t));
	if (contents->nodes == NULL) {
		ERR_ALLOC_FAILED;
		goto cleanup;
	}

	dbg_zone("Creating tree for NSEC3 nodes.\n");
	contents->nsec3_nodes = malloc(sizeof(knot_zone_tree_t));
	if (contents->nsec3_nodes == NULL) {
		ERR_ALLOC_FAILED;
		goto cleanup;
	}

	if (use_domain_table) {
		dbg_zone("Creating domain name table.\n");
		contents->dname_table = knot_dname_table_new();
		if (contents->dname_table == NULL) {
			ERR_ALLOC_FAILED;
			goto cleanup;
		}
	} else {
		contents->dname_table = NULL;
	}

	contents->node_count = node_count;

	/* Initialize NSEC3 params */
	dbg_zone("Initializing NSEC3 parameters.\n");
	contents->nsec3_params.algorithm = 0;
	contents->nsec3_params.flags = 0;
	contents->nsec3_params.iterations = 0;
	contents->nsec3_params.salt_length = 0;
	contents->nsec3_params.salt = NULL;

	dbg_zone("Initializing zone trees.\n");
	if (knot_zone_tree_init(contents->nodes) != KNOT_EOK
	    || knot_zone_tree_init(contents->nsec3_nodes) != KNOT_EOK) {
		goto cleanup;
	}

	dbg_zone("Inserting apex into the zone tree.\n");
	if (knot_zone_tree_insert(contents->nodes, apex) != KNOT_EOK) {
		dbg_zone("Failed to insert apex to the zone tree.\n");
		goto cleanup;
	}

#ifdef USE_HASH_TABLE
	if (contents->node_count > 0) {
		dbg_zone("Creating hash table.\n");
		contents->table = ck_create_table(contents->node_count);
		if (contents->table == NULL) {
			goto cleanup;
		}

		// insert the apex into the hash table
		dbg_zone("Inserting apex into the hash table.\n");
		if (ck_insert_item(contents->table,
		                   (const char *)knot_dname_name(
		                                       knot_node_owner(apex)),
		                   knot_dname_size(knot_node_owner(apex)),
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
		dbg_zone("Inserting names from apex to table.\n");
		int rc = knot_zone_contents_dnames_from_node_to_table(
		             contents->dname_table, apex);
		if (rc != KNOT_EOK) {
			ck_destroy_table(&contents->table, NULL, 0);
			goto cleanup;
		}
	}

	return contents;

cleanup:
	dbg_zone("Cleaning up.\n");
	free(contents->dname_table);
	free(contents->nodes);
	free(contents->nsec3_nodes);
	free(contents);
	return NULL;
}

/*----------------------------------------------------------------------------*/

//short knot_zone_contents_generation(const knot_zone_contents_t *zone)
//{
//	return zone->generation;
//}

/*----------------------------------------------------------------------------*/

int knot_zone_contents_gen_is_old(const knot_zone_contents_t *contents)
{
	return (contents->generation == 0);
}

/*----------------------------------------------------------------------------*/

int knot_zone_contents_gen_is_new(const knot_zone_contents_t *contents)
{
	return (contents->generation == 1);
}

/*----------------------------------------------------------------------------*/

int knot_zone_contents_gen_is_finished(const knot_zone_contents_t *contents)
{
	return (contents->generation == -1);
}

/*----------------------------------------------------------------------------*/

//void knot_zone_contents_switch_generation(knot_zone_contents_t *zone)
//{
//	zone->generation = 1 - zone->generation;
//}

/*----------------------------------------------------------------------------*/

void knot_zone_contents_set_gen_old(knot_zone_contents_t *contents)
{
	contents->generation = 0;
}

/*----------------------------------------------------------------------------*/

void knot_zone_contents_set_gen_new(knot_zone_contents_t *contents)
{
	contents->generation = 1;
}

/*----------------------------------------------------------------------------*/

void knot_zone_contents_set_gen_new_finished(knot_zone_contents_t *contents)
{
	contents->generation = -1;
}

/*----------------------------------------------------------------------------*/

uint16_t knot_zone_contents_class(const knot_zone_contents_t *contents)
{
	if (contents == NULL || contents->apex == NULL
	    || knot_node_rrset(contents->apex, KNOT_RRTYPE_SOA) == NULL) {
		return KNOT_EBADARG;
	}

	return knot_rrset_class(knot_node_rrset(contents->apex,
	                                        KNOT_RRTYPE_SOA));
}

/*----------------------------------------------------------------------------*/

int knot_zone_contents_add_node(knot_zone_contents_t *zone,
                                  knot_node_t *node, int create_parents,
                                  uint8_t flags, int use_domain_table)
{
	if (zone == NULL || node == NULL) {
		return KNOT_EBADARG;
	}

	int ret = 0;
	if ((ret = knot_zone_contents_check_node(zone, node)) != 0) {
		return ret;
	}

	ret = knot_zone_tree_insert(zone->nodes, node);
	if (ret != KNOT_EOK) {
		dbg_zone("Failed to insert node into zone tree.\n");
		return ret;
	}

#ifdef USE_HASH_TABLE
	char *name = knot_dname_to_str(node->owner);
//	dbg_zone("Adding node with owner %s to hash table.\n", name);
	free(name);
	//assert(zone->table != NULL);
	// add the node also to the hash table if authoritative, or deleg. point
	if (zone->table != NULL
	    && ck_insert_item(zone->table,
	                      (const char *)node->owner->name,
	                      node->owner->size, (void *)node) != 0) {
		dbg_zone("Error inserting node into hash table!\n");
		/*! \todo Remove the node from the tree. */
		return KNOT_EHASH;
	}
#endif
	assert(knot_zone_contents_find_node(zone, node->owner));

	if (use_domain_table) {
		ret = knot_zone_contents_dnames_from_node_to_table(
		          zone->dname_table, node);
		if (ret != KNOT_EOK) {
			/*! \todo Remove node from the tree and hash table.*/
			dbg_zone("Failed to add dnames into table.\n");
			return ret;
		}
	}

	knot_node_set_zone(node, zone->zone);

	if (!create_parents) {
		return KNOT_EOK;
	}

	dbg_zone("Creating parents of the node.\n");

	knot_dname_t *chopped =
		knot_dname_left_chop(knot_node_owner(node));
	if (knot_dname_compare(knot_node_owner(zone->apex), chopped) == 0) {
		dbg_zone("Zone apex is the parent.\n");
		knot_node_set_parent(node, zone->apex);
	} else {
		knot_node_t *next_node;
		while ((next_node
		      = knot_zone_contents_get_node(zone, chopped)) == NULL) {
			/* Adding new dname to zone + add to table. */
			dbg_zone("Creating new node.\n");
			next_node = knot_node_new(chopped, NULL, flags);
			if (next_node == NULL) {
				/* Directly discard. */
				knot_dname_free(&chopped);
				return KNOT_ENOMEM;
			}
			if (use_domain_table) {
				ret =
				 knot_zone_contents_dnames_from_node_to_table(
					zone->dname_table, next_node);
				if (ret != KNOT_EOK) {
					/*! \todo Will next_node leak? */
					knot_dname_release(chopped);
					return ret;
				}
			}

			if (next_node->owner != chopped) {
				/* Node owner was in RDATA */
				chopped = next_node->owner;
			}

			assert(knot_zone_contents_find_node(zone, chopped)
			       == NULL);
			assert(knot_node_owner(next_node) == chopped);

			dbg_zone("Inserting new node to zone tree.\n");
//			TREE_INSERT(zone->tree, knot_node, avl, next_node);

			ret = knot_zone_tree_insert(zone->nodes,
			                              next_node);
			if (ret != KNOT_EOK) {
				dbg_zone("Failed to insert new node "
				                  "to zone tree.\n");
				/*! \todo Delete the node?? */
				/* Directly discard. */
				knot_dname_release(chopped);
				return ret;
			}

#ifdef USE_HASH_TABLE
dbg_zone_exec(
			char *name = knot_dname_to_str(
					knot_node_owner(next_node));
			dbg_zone("Adding new node with owner %s to "
			                  "hash table.\n", name);
			free(name);
);

			if (zone->table != NULL
			    && ck_insert_item(zone->table,
			      (const char *)knot_dname_name(
			                    knot_node_owner(next_node)),
			      knot_dname_size(knot_node_owner(next_node)),
			      (void *)next_node) != 0) {
				dbg_zone("Error inserting node into "
				                  "hash table!\n");
				/*! \todo Delete the node?? */
				/* Directly discard. */
				knot_dname_release(chopped);
				return KNOT_EHASH;
			}

			// set parent
			knot_node_set_parent(node, next_node);

			// set zone
			knot_node_set_zone(next_node, zone->zone);

			// check if the node is not wildcard child of the parent
			if (knot_dname_is_wildcard(
					knot_node_owner(node))) {
				knot_node_set_wildcard_child(next_node, node);
			}
#endif
			dbg_zone("Next parent.\n");
			node = next_node;
			knot_dname_t *chopped_last = chopped;
			chopped = knot_dname_left_chop(chopped);

			/* Release last chop, reference is already stored
			 * in next_node.
			 */
			knot_dname_release(chopped_last);

		}
		// set the found parent (in the zone) as the parent of the last
		// inserted node
		assert(knot_node_parent(node, 0) == NULL);
		knot_node_set_parent(node, next_node);

		dbg_zone("Created all parents.\n");
	}

	/* Directly discard. */
	/*! \todo This may be double-release. */
	knot_dname_release(chopped);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_zone_contents_add_rrset(knot_zone_contents_t *zone,
                                   knot_rrset_t *rrset, knot_node_t **node,
                                   knot_rrset_dupl_handling_t dupl,
                                   int use_domain_table)
{
	if (zone == NULL || rrset == NULL || zone->apex == NULL
	    || zone->apex->owner == NULL || node == NULL) {
		return KNOT_EBADARG;
	}

	// check if the RRSet belongs to the zone
	if (knot_dname_compare(knot_rrset_owner(rrset),
	                         zone->apex->owner) != 0
	    && !knot_dname_is_subdomain(knot_rrset_owner(rrset),
	                                  zone->apex->owner)) {
		return KNOT_EBADZONE;
	}

	if ((*node) == NULL
	    && (*node = knot_zone_contents_get_node(zone,
	                            knot_rrset_owner(rrset))) == NULL) {
		return KNOT_ENONODE;
	}

	assert(*node != NULL);

	// add all domain names from the RRSet to domain name table
	int rc;

	/*! \todo REMOVE RRSET */
	rc = knot_node_add_rrset(*node, rrset,
	                           dupl == KNOT_RRSET_DUPL_MERGE);
	if (rc < 0) {
		dbg_zone("Failed to add RRSet to node.\n");
		return rc;
	}

	int ret = rc;

	if (use_domain_table) {
		dbg_zone("Saving RRSet to table.\n");
		rc = knot_zone_contents_dnames_from_rrset_to_table(
		         zone->dname_table, rrset, 0, (*node)->owner);
		if (rc != KNOT_EOK) {
			dbg_zone("Error saving domain names from "
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
	if (ret == KNOT_EOK && rrset->owner != (*node)->owner) {
		knot_rrset_set_owner(rrset, (*node)->owner);
	}

	dbg_zone("RRSet OK.\n");
	return ret;
}

/*----------------------------------------------------------------------------*/

int knot_zone_contents_add_rrsigs(knot_zone_contents_t *zone,
                                    knot_rrset_t *rrsigs,
                                    knot_rrset_t **rrset,
                                    knot_node_t **node,
                                    knot_rrset_dupl_handling_t dupl,
                                    int use_domain_table)
{
	if (zone == NULL || rrsigs == NULL || rrset == NULL || node == NULL
	    || zone->apex == NULL || zone->apex->owner == NULL) {
dbg_zone_exec(
		dbg_zone("Parameters: zone=%p, rrsigs=%p, rrset=%p, "
				"node=%p\n", zone, rrsigs, rrset, node);
		if (zone != NULL) {
			dbg_zone("zone->apex=%p\n", zone->apex);
			if (zone->apex != NULL) {
				dbg_zone("zone->apex->owner=%p\n", 
						zone->apex->owner);
			}
		}
);
		return KNOT_EBADARG;
	}

	// check if the RRSet belongs to the zone
	if (*rrset != NULL
	    && knot_dname_compare(knot_rrset_owner(*rrset),
	                            zone->apex->owner) != 0
	    && !knot_dname_is_subdomain(knot_rrset_owner(*rrset),
	                                  zone->apex->owner)) {
		return KNOT_EBADZONE;
	}

	// check if the RRSIGs belong to the RRSet
	if (*rrset != NULL
	    && (knot_dname_compare(knot_rrset_owner(rrsigs),
	                             knot_rrset_owner(*rrset)) != 0)) {
		dbg_zone("RRSIGs does not belong to the given RRSet.\n");
		return KNOT_EBADARG;
	}

	// if no RRSet given, try to find the right RRSet
	if (*rrset == NULL) {
		// even no node given
		// find proper node
		knot_node_t *(*get_node)(const knot_zone_contents_t *,
		                           const knot_dname_t *)
		    = (knot_rdata_rrsig_type_covered(
		            knot_rrset_rdata(rrsigs)) == KNOT_RRTYPE_NSEC3)
		       ? knot_zone_contents_get_nsec3_node
		       : knot_zone_contents_get_node;

		if (*node == NULL
		    && (*node = get_node(
		                   zone, knot_rrset_owner(rrsigs))) == NULL) {
			dbg_zone("Failed to find node for RRSIGs.\n");
			return KNOT_ENONODE;
		}

		assert(*node != NULL);

		// find the RRSet in the node
		// take only the first RDATA from the RRSIGs
		dbg_zone("Finding RRSet for type %s\n",
		                  knot_rrtype_to_string(
		                      knot_rdata_rrsig_type_covered(
		                      knot_rrset_rdata(rrsigs))));
		*rrset = knot_node_get_rrset(
		             *node, knot_rdata_rrsig_type_covered(
		                      knot_rrset_rdata(rrsigs)));
		if (*rrset == NULL) {
			dbg_zone("Failed to find RRSet for RRSIGs.\n");
			return KNOT_ENORRSET;
		}
	}

	assert(*rrset != NULL);

	// add all domain names from the RRSet to domain name table
	int rc;
	int ret = KNOT_EOK;

	rc = knot_rrset_add_rrsigs(*rrset, rrsigs, dupl);
	if (rc < 0) {
		dbg_dname("Failed to add RRSIGs to RRSet.\n");
		return rc;
	} else if (rc > 0) {
		assert(dupl == KNOT_RRSET_DUPL_MERGE);
		ret = 1;
	}

	if (use_domain_table) {
		dbg_zone("Saving RRSIG RRSet to table.\n");
		rc = knot_zone_contents_dnames_from_rrset_to_table(
		       zone->dname_table, rrsigs, 0, (*rrset)->owner);
		if (rc != KNOT_EOK) {
			dbg_zone("Error saving domain names from "
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
		knot_rrset_set_owner((*rrset)->rrsigs, (*rrset)->owner);
	}

	dbg_zone("RRSIGs OK\n");
	return ret;
}

/*----------------------------------------------------------------------------*/

int knot_zone_contents_add_nsec3_node(knot_zone_contents_t *zone,
                                        knot_node_t *node, int create_parents,
                                        uint8_t flags, int use_domain_table)
{
	UNUSED(create_parents);
	UNUSED(flags);

	if (zone == NULL || node == NULL) {
		return KNOT_EBADARG;
	}

	int ret = 0;
	if ((ret = knot_zone_contents_check_node(zone, node)) != 0) {
		return ret;
	}

	// how to know if this is successfull??
//	TREE_INSERT(zone->nsec3_nodes, knot_node, avl, node);
	knot_zone_tree_insert(zone->nsec3_nodes, node);

	if (use_domain_table) {
		ret = knot_zone_contents_dnames_from_node_to_table(
		           zone->dname_table, node);
		if (ret != KNOT_EOK) {
			/*! \todo Remove the node from the tree. */
			dbg_zone("Failed to add dnames into table.\n");
			return ret;
		}
	}

	// no parents to be created, the only parent is the zone apex
	// set the apex as the parent of the node
	knot_node_set_parent(node, zone->apex);

	// set the zone to the node
	knot_node_set_zone(node, zone->zone);

	// cannot be wildcard child, so nothing to be done

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_zone_contents_add_nsec3_rrset(knot_zone_contents_t *zone,
                                         knot_rrset_t *rrset,
                                         knot_node_t **node,
                                         knot_rrset_dupl_handling_t dupl,
                                         int use_domain_table)
{
	if (zone == NULL || rrset == NULL || zone->apex == NULL
	    || zone->apex->owner == NULL || node == NULL) {
		return KNOT_EBADARG;
	}

	// check if the RRSet belongs to the zone
	if (knot_dname_compare(knot_rrset_owner(rrset),
	                         zone->apex->owner) != 0
	    && !knot_dname_is_subdomain(knot_rrset_owner(rrset),
	                                  zone->apex->owner)) {
		return KNOT_EBADZONE;
	}

	if ((*node) == NULL
	    && (*node = knot_zone_contents_get_nsec3_node(
	                      zone, knot_rrset_owner(rrset))) == NULL) {
		return KNOT_ENONODE;
	}

	assert(*node != NULL);

	// add all domain names from the RRSet to domain name table
	int rc;

	/*! \todo REMOVE RRSET */
	rc = knot_node_add_rrset(*node, rrset,
	                           dupl == KNOT_RRSET_DUPL_MERGE);
	if (rc < 0) {
		return rc;
	}

	int ret = rc;

	if (use_domain_table) {
		dbg_zone("Saving NSEC3 RRSet to table.\n");
		rc = knot_zone_contents_dnames_from_rrset_to_table(
		         zone->dname_table, rrset, 0, (*node)->owner);
		if (rc != KNOT_EOK) {
			dbg_zone("Error saving domain names from "
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
		knot_rrset_set_owner(rrset, (*node)->owner);
	}

	dbg_zone("NSEC3 OK\n");
	return ret;
}

/*----------------------------------------------------------------------------*/

int knot_zone_contents_remove_node(knot_zone_contents_t *contents, 
	const knot_node_t *node, knot_zone_tree_node_t **removed_tree, 
	ck_hash_table_item_t **removed_hash)
{
	if (contents == NULL || node == NULL) {
		return KNOT_EBADARG;
	}

	const knot_dname_t *owner = knot_node_owner(node);

	// 1) remove the node from hash table
	*removed_hash = NULL;
	*removed_hash = ck_remove_item(contents->table, 
	                               (const char *)knot_dname_name(owner),
	                               knot_dname_size(owner));
//	int ret = ck_detete_item(contents->table,
//	               (const char *)knot_dname_name(owner),
//	               knot_dname_size(owner), NULL, 0);
	if (*removed_hash == NULL) {
		return KNOT_ENONODE;
	}

	// 2) remove the node from the zone tree
	*removed_tree = NULL;
	int ret = knot_zone_tree_remove(contents->nodes, owner, removed_tree);
	if (ret != KNOT_EOK) {
		return KNOT_ENONODE;
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_zone_contents_remove_nsec3_node(knot_zone_contents_t *contents, 
	const knot_node_t *node, knot_zone_tree_node_t **removed)
{
	if (contents == NULL || node == NULL) {
		return KNOT_EBADARG;
	}

	const knot_dname_t *owner = knot_node_owner(node);

	// remove the node from the zone tree
	*removed = NULL;
	int ret = knot_zone_tree_remove(contents->nsec3_nodes, owner, removed);
	if (ret != KNOT_EOK) {
		return KNOT_ENONODE;
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_zone_contents_create_and_fill_hash_table(
	knot_zone_contents_t *zone)
{
	if (zone == NULL || zone->apex == NULL || zone->apex->owner == NULL) {
		return KNOT_EBADARG;
	}
	/*
	 * 1) Create hash table.
	 */
#ifdef USE_HASH_TABLE
	if (zone->node_count > 0) {
		zone->table = ck_create_table(zone->node_count);
		if (zone->table == NULL) {
			return KNOT_ENOMEM;
		}

		// insert the apex into the hash table
		if (ck_insert_item(zone->table,
		                (const char *)zone->apex->owner->name,
		                zone->apex->owner->size,
		                (void *)zone->apex) != 0) {
			return KNOT_EHASH;
		}
	} else {
		zone->table = NULL;
		return KNOT_EOK;	// OK?
	}

	/*
	 * 2) Fill in the hash table.
	 *
	 * In this point, the nodes in the zone must be adjusted, so that only
	 * relevant nodes (authoritative and delegation points are inserted.
	 *
	 * TODO: how to know if this was successful??
	 */
	/*! \todo Replace by zone tree. */
	int ret = knot_zone_tree_forward_apply_inorder(zone->nodes,
	                               knot_zone_contents_node_to_hash, zone);
	if (ret != KNOT_EOK) {
		dbg_zone("Failed to insert nodes to hash table.\n");
		return ret;
	}

#endif
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

knot_node_t *knot_zone_contents_get_node(const knot_zone_contents_t *zone,
				    const knot_dname_t *name)
{
	if (zone == NULL || name == NULL) {
		return NULL;
	}

	// create dummy node to use for lookup
//	knot_node_t *tmp = knot_node_new((knot_dname_t *)name, NULL);
//	knot_node_t *n = TREE_FIND(zone->tree, knot_node, avl, tmp);
//	knot_node_free(&tmp, 0);

	knot_node_t *n;
	int ret = knot_zone_tree_get(zone->nodes, name, &n);
	if (ret != KNOT_EOK) {
		dbg_zone("Failed to find name in the zone tree.\n");
		return NULL;
	}

	return n;
}

/*----------------------------------------------------------------------------*/

knot_node_t *knot_zone_contents_get_nsec3_node(
	const knot_zone_contents_t *zone, const knot_dname_t *name)
{
	if (zone == NULL || name == NULL) {
		return NULL;
	}

	// create dummy node to use for lookup
//	knot_node_t *tmp = knot_node_new((knot_dname_t *)name, NULL);
//	knot_node_t *n = TREE_FIND(zone->nsec3_nodes, knot_node, avl, tmp);
//	knot_node_free(&tmp, 0);
	knot_node_t *n;
	int ret = knot_zone_tree_get(zone->nsec3_nodes, name, &n);

	if (ret != KNOT_EOK) {
		dbg_zone("Failed to find NSEC3 name in the zone tree."
		                  "\n");
		return NULL;
	}

	return n;
}

/*----------------------------------------------------------------------------*/

const knot_node_t *knot_zone_contents_find_node(
	const knot_zone_contents_t *zone,const knot_dname_t *name)
{
	return knot_zone_contents_get_node(zone, name);
}

/*----------------------------------------------------------------------------*/

int knot_zone_contents_find_dname(const knot_zone_contents_t *zone,
                           const knot_dname_t *name,
                           const knot_node_t **node,
                           const knot_node_t **closest_encloser,
                           const knot_node_t **previous)
{
	if (zone == NULL || name == NULL || node == NULL
	    || closest_encloser == NULL || previous == NULL
	    || zone->apex == NULL || zone->apex->owner == NULL) {
		return KNOT_EBADARG;
	}

dbg_zone_exec(
	char *name_str = knot_dname_to_str(name);
	char *zone_str = knot_dname_to_str(zone->apex->owner);
	dbg_zone("Searching for name %s in zone %s...\n",
	                  name_str, zone_str);
	free(name_str);
	free(zone_str);
);

	if (knot_dname_compare(name, zone->apex->owner) == 0) {
		*node = zone->apex;
		*closest_encloser = *node;
		return KNOT_ZONE_NAME_FOUND;
	}

	if (!knot_dname_is_subdomain(name, zone->apex->owner)) {
		*node = NULL;
		*closest_encloser = NULL;
		return KNOT_EBADZONE;
	}

	knot_node_t *found = NULL, *prev = NULL;

	int exact_match = knot_zone_contents_find_in_tree(zone->nodes, name,
	                                                    &found, &prev);
	assert(exact_match >= 0);
	*node = found;
	*previous = prev;

dbg_zone_exec(
	char *name_str = (*node) ? knot_dname_to_str((*node)->owner)
	                         : "(nil)";
	char *name_str2 = (*previous != NULL)
	                  ? knot_dname_to_str((*previous)->owner)
	                  : "(nil)";
	dbg_zone("Search function returned %d, node %s and prev: %s\n",
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
		return KNOT_EBADZONE;
	}

	// TODO: this could be replaced by saving pointer to closest encloser
	//       in node

	if (!exact_match) {
		int matched_labels = knot_dname_matched_labels(
				knot_node_owner((*closest_encloser)), name);
		while (matched_labels < knot_dname_label_count(
				knot_node_owner((*closest_encloser)))) {
			(*closest_encloser) =
				knot_node_parent((*closest_encloser), 1);
			assert(*closest_encloser);
		}
	}
dbg_zone_exec(
	char *n = knot_dname_to_str(knot_node_owner((*closest_encloser)));
	dbg_zone("Closest encloser: %s\n", n);
	free(n);
);

	dbg_zone("find_dname() returning %d\n", exact_match);

	return (exact_match)
	       ? KNOT_ZONE_NAME_FOUND
	       : KNOT_ZONE_NAME_NOT_FOUND;
}

/*----------------------------------------------------------------------------*/

knot_node_t *knot_zone_contents_get_previous(
	const knot_zone_contents_t *zone, const knot_dname_t *name)
{
	if (zone == NULL || name == NULL) {
		return NULL;
	}

	knot_node_t *found = NULL, *prev = NULL;

	int exact_match = knot_zone_contents_find_in_tree(zone->nodes, name,
	                                                    &found, &prev);
	assert(exact_match >= 0);
	assert(prev != NULL);

	return prev;
}

/*----------------------------------------------------------------------------*/

const knot_node_t *knot_zone_contents_find_previous(
	const knot_zone_contents_t *zone, const knot_dname_t *name)
{
	return knot_zone_contents_get_previous(zone, name);
}

/*----------------------------------------------------------------------------*/

knot_node_t *knot_zone_contents_get_previous_nsec3(
	const knot_zone_contents_t *zone, const knot_dname_t *name)
{
	if (zone == NULL || name == NULL) {
		return NULL;
	}

	knot_node_t *found = NULL, *prev = NULL;

	int exact_match = knot_zone_contents_find_in_tree(zone->nsec3_nodes,
	                                                   name, &found, &prev);
	assert(exact_match >= 0);
	assert(prev != NULL);

	return prev;
}

/*----------------------------------------------------------------------------*/

const knot_node_t *knot_zone_contents_find_previous_nsec3(
	const knot_zone_contents_t *zone, const knot_dname_t *name)
{
	return knot_zone_contents_get_previous(zone, name);
}

/*----------------------------------------------------------------------------*/

static void knot_zone_contents_left_chop(char *name, size_t *size)
{
	short label_size = name[0];
	
	memmove(name, name + label_size + 1, *size -label_size - 1);
	*size = *size - label_size - 1;
}

/*----------------------------------------------------------------------------*/
#ifdef USE_HASH_TABLE
int knot_zone_contents_find_dname_hash(const knot_zone_contents_t *zone,
                                const knot_dname_t *name,
                                const knot_node_t **node,
                                const knot_node_t **closest_encloser)
{
	if (zone == NULL || name == NULL || node == NULL
	    || closest_encloser == NULL) {
		return KNOT_EBADARG;
	}

dbg_zone_exec(
	char *name_str = knot_dname_to_str(name);
	char *zone_str = knot_dname_to_str(zone->apex->owner);
	dbg_zone("Searching for name %s in zone %s...\n",
	                  name_str, zone_str);
	free(name_str);
	free(zone_str);
);

	if (knot_dname_compare(name, zone->apex->owner) == 0) {
		*node = zone->apex;
		*closest_encloser = *node;
		return KNOT_ZONE_NAME_FOUND;
	}

	if (!knot_dname_is_subdomain(name, zone->apex->owner)) {
		*node = NULL;
		*closest_encloser = NULL;
		return KNOT_EBADZONE;
	}
	
	// temporary name used for hashing
	char name_tmp[KNOT_MAX_DNAME_LENGTH];
	size_t name_size = name->size;
	if (knot_dname_to_lower_copy(name, name_tmp, KNOT_MAX_DNAME_LENGTH)
	    != KNOT_EOK) {
		return KNOT_ERROR;
	}

	const ck_hash_table_item_t *item = ck_find_item(zone->table,
	                                                name_tmp, name_size);

	if (item != NULL) {
		*node = (const knot_node_t *)item->value;
		*closest_encloser = *node;

		dbg_zone("Found node in hash table: %p (owner %p, "
		                  "labels: %d)\n", *node, (*node)->owner,
		                  knot_dname_label_count((*node)->owner));
		assert(*node != NULL);
		assert(*closest_encloser != NULL);
		return KNOT_ZONE_NAME_FOUND;
	}

	*node = NULL;

	// chop leftmost labels until some node is found
	// copy the name for chopping
	/* Local allocation, will be discarded. */
	//knot_dname_t *name_copy = knot_dname_deep_copy(name);
dbg_zone_exec(
	//char *n = knot_dname_to_str(name_copy);
	dbg_zone("Finding closest encloser..\nStarting with: %.*s\n", 
			(int)name_size, name_tmp);
	//free(n);
);

	while (item == NULL) {
		//knot_dname_left_chop_no_copy(name_copy);
		knot_zone_contents_left_chop(name_tmp, &name_size);
dbg_zone_exec(
		//char *n = knot_dname_to_str(name_copy);
		dbg_zone("Chopped leftmost label: %.*s\n",
				(int)name_size, name_tmp);
		//free(n);
);
		// not satisfied in root zone!!
		//assert(name_copy->label_count > 0);
		assert(name_size > 0);

		item = ck_find_item(zone->table, name_tmp, name_size);
	}

	/* Directly discard. */
	//knot_dname_free(&name_copy);

	assert(item != NULL);
	*closest_encloser = (const knot_node_t *)item->value;

	return KNOT_ZONE_NAME_NOT_FOUND;
}
#endif
/*----------------------------------------------------------------------------*/

const knot_node_t *knot_zone_contents_find_nsec3_node(
	const knot_zone_contents_t *zone, const knot_dname_t *name)
{
	return knot_zone_contents_get_nsec3_node(zone, name);
}

/*----------------------------------------------------------------------------*/

int knot_zone_contents_find_nsec3_for_name(const knot_zone_contents_t *zone,
                                    const knot_dname_t *name,
                                    const knot_node_t **nsec3_node,
                                    const knot_node_t **nsec3_previous,
				    int check_ver)
{
	if (zone == NULL || name == NULL
	    || nsec3_node == NULL || nsec3_previous == NULL) {
		return KNOT_EBADARG;
	}

	knot_dname_t *nsec3_name = NULL;
	int ret = knot_zone_contents_nsec3_name(zone, name, &nsec3_name);

	if (ret != KNOT_EOK) {
		return ret;
	}

dbg_zone_exec(
	char *n = knot_dname_to_str(nsec3_name);
	dbg_zone("NSEC3 node name: %s.\n", n);
	free(n);
);

	const knot_node_t *found = NULL, *prev = NULL;

	// create dummy node to use for lookup
	int exact_match = knot_zone_tree_find_less_or_equal(
		zone->nsec3_nodes, nsec3_name, &found, &prev, check_ver);
	assert(exact_match >= 0);

	knot_dname_release(nsec3_name);

dbg_zone_exec(
	if (found) {
		char *n = knot_dname_to_str(found->owner);
		dbg_zone("Found NSEC3 node: %s.\n", n);
		free(n);
	} else {
		dbg_zone("Found no NSEC3 node.\n");
	}

	if (prev) {
		assert(prev->owner);
		char *n = knot_dname_to_str(prev->owner);
		dbg_zone("Found previous NSEC3 node: %s.\n", n);
		free(n);
	} else {
		dbg_zone("Found no previous NSEC3 node.\n");
	}
);
	*nsec3_node = found;

	if (prev == NULL) {
		// either the returned node is the root of the tree, or it is
		// the leftmost node in the tree; in both cases node was found
		// set the previous node of the found node
		assert(exact_match);
		assert(*nsec3_node != NULL);
		*nsec3_previous = knot_node_previous(*nsec3_node, check_ver);
	} else {
		*nsec3_previous = prev;
	}

	dbg_zone("find_nsec3_for_name() returning %d\n", exact_match);

	return (exact_match)
	       ? KNOT_ZONE_NAME_FOUND
	       : KNOT_ZONE_NAME_NOT_FOUND;
}

/*----------------------------------------------------------------------------*/

const knot_node_t *knot_zone_contents_apex(
	const knot_zone_contents_t *zone)
{
	if (zone == NULL) {
		return NULL;
	}

	return zone->apex;
}

/*----------------------------------------------------------------------------*/

knot_node_t *knot_zone_contents_get_apex(const knot_zone_contents_t *zone)
{
	if (zone == NULL) {
		return NULL;
	}

	return zone->apex;
}

/*----------------------------------------------------------------------------*/

//knot_dname_t *knot_zone_contents_name(const knot_zone_contents_t *zone)
//{
//	if (zone == NULL) {
//		return NULL;
//	}

//	return zone->name;
//}

/*----------------------------------------------------------------------------*/

int knot_zone_contents_adjust(knot_zone_contents_t *zone, int check_ver)
{
	if (zone == NULL) {
		return KNOT_EBADARG;
	}

	// load NSEC3PARAM (needed on adjusting function)
	knot_zone_contents_load_nsec3param(zone);

	knot_zone_adjust_arg_t adjust_arg;
	adjust_arg.zone = zone;
	adjust_arg.first_node = NULL;
	adjust_arg.previous_node = NULL;
	adjust_arg.check_ver = check_ver;

	dbg_zone("Adjusting normal nodes.\n");
	int ret = knot_zone_tree_forward_apply_inorder(zone->nodes,
	                        knot_zone_contents_adjust_node_in_tree,
	                        &adjust_arg);
	if (ret != KNOT_EOK) {
		return ret;
	}
	dbg_zone("Done.\n");

	assert(zone->apex == adjust_arg.first_node);
	knot_node_set_previous(zone->apex, adjust_arg.previous_node);

	adjust_arg.first_node = NULL;
	adjust_arg.previous_node = NULL;

	dbg_zone("Adjusting NSEC3 nodes.\n");
	ret = knot_zone_tree_forward_apply_inorder(
	              zone->nsec3_nodes,
	              knot_zone_contents_adjust_nsec3_node_in_tree,
	                        &adjust_arg);

	dbg_zone("Done.\n");
	if (adjust_arg.first_node) {
		knot_node_set_previous(adjust_arg.first_node,
		                         adjust_arg.previous_node);
	}

	return ret;
}

/*----------------------------------------------------------------------------*/

int knot_zone_contents_load_nsec3param(knot_zone_contents_t *zone)
{
	if (zone == NULL || zone->apex == NULL) {
		return KNOT_EBADARG;
	}

	const knot_rrset_t *rrset = knot_node_rrset(zone->apex,
						      KNOT_RRTYPE_NSEC3PARAM);

	if (rrset != NULL) {
		knot_nsec3_params_from_wire(&zone->nsec3_params, rrset);
	} else {
		memset(&zone->nsec3_params, 0, sizeof(knot_nsec3_params_t));
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_zone_contents_nsec3_enabled(const knot_zone_contents_t *zone)
{
	if (zone == NULL) {
		return KNOT_EBADARG;
	}

	//return (zone->nsec3_params.algorithm != 0);
	return (zone->nsec3_nodes->th_root != NULL);
}

/*----------------------------------------------------------------------------*/

const knot_nsec3_params_t *knot_zone_contents_nsec3params(
	const knot_zone_contents_t *zone)
{
	if (zone == NULL) {
		return NULL;
	}

	if (knot_zone_contents_nsec3_enabled(zone)) {
		return &zone->nsec3_params;
	} else {
		return NULL;
	}
}

/*----------------------------------------------------------------------------*/

int knot_zone_contents_tree_apply_postorder(knot_zone_contents_t *zone,
                              void (*function)(knot_node_t *node, void *data),
                              void *data)
{
	if (zone == NULL) {
		return KNOT_EBADARG;
	}

	knot_zone_tree_func_t f;
	f.func = function;
	f.data = data;

	return knot_zone_tree_forward_apply_postorder(zone->nodes,
	                                            knot_zone_tree_apply, &f);
}

/*----------------------------------------------------------------------------*/

int knot_zone_contents_tree_apply_inorder(knot_zone_contents_t *zone,
			      void (*function)(knot_node_t *node, void *data),
                              void *data)
{
	if (zone == NULL) {
		return KNOT_EBADARG;
	}

	knot_zone_tree_func_t f;
	f.func = function;
	f.data = data;

	return knot_zone_tree_forward_apply_inorder(zone->nodes,
	                                            knot_zone_tree_apply, &f);
}

/*----------------------------------------------------------------------------*/

int knot_zone_contents_tree_apply_inorder_reverse(
	knot_zone_contents_t *zone,
	void (*function)(knot_node_t *node, void *data), void *data)
{
	if (zone == NULL) {
		return KNOT_EBADARG;
	}

	knot_zone_tree_func_t f;
	f.func = function;
	f.data = data;

	return knot_zone_tree_reverse_apply_inorder(zone->nodes,
	                                          knot_zone_tree_apply, &f);
}

/*----------------------------------------------------------------------------*/

int knot_zone_contents_nsec3_apply_postorder(knot_zone_contents_t *zone,
                              void (*function)(knot_node_t *node, void *data),
                              void *data)
{
	if (zone == NULL) {
		return KNOT_EBADARG;
	}

	knot_zone_tree_func_t f;
	f.func = function;
	f.data = data;

	return knot_zone_tree_forward_apply_postorder(
			zone->nsec3_nodes, knot_zone_tree_apply, &f);
}

/*----------------------------------------------------------------------------*/

int knot_zone_contents_nsec3_apply_inorder(knot_zone_contents_t *zone,
			      void (*function)(knot_node_t *node, void *data),
                              void *data)
{
	if (zone == NULL) {
		return KNOT_EBADARG;
	}

	knot_zone_tree_func_t f;
	f.func = function;
	f.data = data;

	return knot_zone_tree_forward_apply_inorder(
			zone->nsec3_nodes, knot_zone_tree_apply, &f);
}

/*----------------------------------------------------------------------------*/

int knot_zone_contents_nsec3_apply_inorder_reverse(
	knot_zone_contents_t *zone,
	void (*function)(knot_node_t *node, void *data), void *data)
{
	if (zone == NULL) {
		return KNOT_EBADARG;
	}

	knot_zone_tree_func_t f;
	f.func = function;
	f.data = data;

	return knot_zone_tree_reverse_apply_inorder(
			zone->nsec3_nodes, knot_zone_tree_apply, &f);
}

/*----------------------------------------------------------------------------*/

knot_zone_tree_t *knot_zone_contents_get_nodes(
		knot_zone_contents_t *contents)
{
	return contents->nodes;
}

/*----------------------------------------------------------------------------*/

knot_zone_tree_t *knot_zone_contents_get_nsec3_nodes(
		knot_zone_contents_t *contents)
{
	return contents->nsec3_nodes;
}

/*----------------------------------------------------------------------------*/

ck_hash_table_t *knot_zone_contents_get_hash_table(
		knot_zone_contents_t *contents)
{
	return contents->table;
}

/*----------------------------------------------------------------------------*/

int knot_zone_contents_dname_table_apply(knot_zone_contents_t *contents,
                                           void (*function)(knot_dname_t *,
                                                            void *),
                                           void *data)
{
	if (contents == NULL || function == NULL) {
		return KNOT_EBADARG;
	}

	knot_dname_table_tree_inorder_apply(contents->dname_table,
	                                    function, data);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_zone_contents_shallow_copy(const knot_zone_contents_t *from,
                             knot_zone_contents_t **to)
{
	if (from == NULL || to == NULL) {
		return KNOT_EBADARG;
	}

	/* Copy to same destination as source. */
	if (from == *to) {
		return KNOT_EBADARG;
	}

	int ret = KNOT_EOK;

	knot_zone_contents_t *contents = (knot_zone_contents_t *)calloc(
	                                     1, sizeof(knot_zone_contents_t));
	if (contents == NULL) {
		ERR_ALLOC_FAILED;
		return KNOT_ENOMEM;
	}

	contents->apex = from->apex;

	contents->nodes = malloc(sizeof(knot_zone_tree_t));
	if (contents->nodes == NULL) {
		ERR_ALLOC_FAILED;
		ret = KNOT_ENOMEM;
		goto cleanup;
	}

	contents->nsec3_nodes = malloc(sizeof(knot_zone_tree_t));
	if (contents->nsec3_nodes == NULL) {
		ERR_ALLOC_FAILED;
		ret = KNOT_ENOMEM;
		goto cleanup;
	}

	if (from->dname_table != NULL) {
		contents->dname_table = knot_dname_table_new();
		if (contents->dname_table == NULL) {
			ERR_ALLOC_FAILED;
			ret = KNOT_ENOMEM;
			goto cleanup;
		}
		if ((ret = knot_dname_table_shallow_copy(from->dname_table,
		                        contents->dname_table)) != KNOT_EOK) {
			goto cleanup;
		}
	} else {
		contents->dname_table = NULL;
	}

	contents->node_count = from->node_count;
	contents->generation = from->generation;

	contents->zone = from->zone;

	/* Initialize NSEC3 params */
	memcpy(&contents->nsec3_params, &from->nsec3_params,
	       sizeof(knot_nsec3_params_t));

	if ((ret = knot_zone_tree_shallow_copy(from->nodes,
	                                 contents->nodes)) != KNOT_EOK
	    || (ret = knot_zone_tree_shallow_copy(from->nsec3_nodes,
	                                contents->nsec3_nodes)) != KNOT_EOK) {
		goto cleanup;
	}

#ifdef USE_HASH_TABLE
	if (from->table != NULL) {
//		ret = ck_copy_table(from->table, &contents->table);
		ret = ck_shallow_copy(from->table, &contents->table);
		if (ret != 0) {
			dbg_zone("knot_zone_contents_shallow_copy: "
					"hash table copied\n");
			ret = KNOT_ERROR;
			goto cleanup;
		}
	}
#endif

	dbg_zone("knot_zone_contents_shallow_copy: "
			"finished OK\n");

	*to = contents;
	return KNOT_EOK;

cleanup:
	knot_zone_tree_free(&contents->nodes);
	knot_zone_tree_free(&contents->nsec3_nodes);
	free(contents->dname_table);
	free(contents);
	return ret;
}

/*----------------------------------------------------------------------------*/

void knot_zone_contents_free(knot_zone_contents_t **contents)
{
	if (contents == NULL || *contents == NULL) {
		return;
	}

	// free the zone tree, but only the structure
	knot_zone_tree_free(&(*contents)->nodes);
	knot_zone_tree_free(&(*contents)->nsec3_nodes);

#ifdef USE_HASH_TABLE
	if ((*contents)->table != NULL) {
		ck_destroy_table(&(*contents)->table, NULL, 0);
	}
#endif
	knot_nsec3_params_free(&(*contents)->nsec3_params);
	
	knot_dname_table_free(&(*contents)->dname_table);

	free(*contents);
	*contents = NULL;
}

/*----------------------------------------------------------------------------*/

void knot_zone_contents_deep_free(knot_zone_contents_t **contents,
                                  int destroy_dname_table)
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

		knot_zone_tree_reverse_apply_postorder(
			(*contents)->nsec3_nodes,
			knot_zone_contents_destroy_node_rrsets_from_tree,
			(void*)1);

		knot_zone_tree_reverse_apply_postorder(
			(*contents)->nsec3_nodes,
			knot_zone_contents_destroy_node_owner_from_tree, 0);

		knot_zone_tree_reverse_apply_postorder(
			(*contents)->nodes,
			knot_zone_contents_destroy_node_rrsets_from_tree,
			(void*)1);

		knot_zone_tree_reverse_apply_postorder(
			(*contents)->nodes,
			knot_zone_contents_destroy_node_owner_from_tree, 0);

		// free the zone tree, but only the structure
		// (nodes are already destroyed)
		dbg_zone("Destroying zone tree.\n");
		knot_zone_tree_free(&(*contents)->nodes);
		dbg_zone("Destroying NSEC3 zone tree.\n");
		knot_zone_tree_free(&(*contents)->nsec3_nodes);

		knot_nsec3_params_free(&(*contents)->nsec3_params);

		if (destroy_dname_table) {
			/*
			 * Hack, used in zcompile - destroys the table using
			 * dname_free() instead of dname_retain().
			 */
			knot_dname_table_destroy(&(*contents)->dname_table);
		} else {
			knot_dname_table_deep_free(&(*contents)->dname_table);
		}
	}

	free((*contents));
	*contents = NULL;
}

