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
#include "util/debug.h"
#include "common/base32hex.h"
/*! \todo XXX TODO FIXME remove once testing is done. */
#include "zcompile/zcompile.h"
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
	int err;
} knot_zone_adjust_arg_t;

/*----------------------------------------------------------------------------*/

const uint8_t KNOT_ZONE_FLAGS_GEN_OLD  = 0;            /* xxxxxx00 */
const uint8_t KNOT_ZONE_FLAGS_GEN_NEW  = 1 << 0;       /* xxxxxx01 */
const uint8_t KNOT_ZONE_FLAGS_GEN_FIN  = 1 << 1;       /* xxxxxx10 */
const uint8_t KNOT_ZONE_FLAGS_GEN_MASK = 3;            /* 00000011 */
const uint8_t KNOT_ZONE_FLAGS_ANY_MASK = 4;            /* 00000100 */
const uint8_t KNOT_ZONE_FLAGS_ANY      = 4;            /* 00000100 */

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
 * \retval KNOT_EINVAL if either of the arguments is NULL.
 * \retval KNOT_EBADZONE if the node does not belong to the zone.
 */
static int knot_zone_contents_check_node(
	const knot_zone_contents_t *contents, const knot_node_t *node)
{
	if (contents == NULL || node == NULL) {
		return KNOT_EINVAL;
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
	knot_node_free(&tnode->node);
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
			rc = knot_dname_table_add_dname_check(table,
					&knot_rdata_get_item(rdata, j)->dname);
			if (rc < 0) {
				dbg_zone("Error: %s\n", knot_strerror(rc));
				return rc;
			}
		}
	}

	dbg_zone_detail("RDATA OK.\n");
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int knot_zone_contents_dnames_from_rrset_to_table(
	knot_dname_table_t *table, knot_rrset_t *rrset, int replace_owner,
	knot_dname_t *owner)
{
	assert(table != NULL && rrset != NULL && owner != NULL);

dbg_zone_exec_detail(
	char *name = knot_dname_to_str(knot_rrset_owner(rrset));
	dbg_zone_detail("Putting dnames from RRSet to table: owner: (%p) %s,"
			" type: %s\n", knot_rrset_owner(rrset),
			name, knot_rrtype_to_string(
				  knot_rrset_type(rrset)));
	free(name);
);

	if (replace_owner) {
		// discard the old owner and replace it with the new
		knot_rrset_set_owner(rrset, owner);
	}
	dbg_zone_detail("RRSet owner: %p\n", rrset->owner);

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
	dbg_zone_detail("Node owner before inserting to dname table: %p.\n",
	                node->owner);
	dbg_zone_detail("Node owner before inserting to dname table: %s.\n",
	                name);
	free(name);
	//knot_dname_t *old_owner = node->owner;
	int rc = knot_dname_table_add_dname_check(table, &node->owner);
	if (rc < 0) {
		dbg_zone("Failed to add dname to dname table.\n");
		return rc;
	}
	int replace_owner = (rc > 0);

dbg_zone_exec_detail(
	name = knot_dname_to_str(node->owner);
	dbg_zone_detail("Node owner after inserting to dname table: %p (%s).\n",
	                node->owner, name);
	free(name);
);

	knot_rrset_t **rrsets = knot_node_get_rrsets(node);
	// for each RRSet
	for (int i = 0; i < knot_node_rrset_count(node); ++i) {
		dbg_zone_detail("Inserting RRSets from node to table.\n");
		rc = knot_zone_contents_dnames_from_rrset_to_table(table,
			rrsets[i], replace_owner, node->owner);

		if (rc == KNOT_EOK && knot_rrset_rrsigs(rrsets[i]) != NULL) {
			rc = knot_zone_contents_dnames_from_rrset_to_table(
				table, knot_rrset_get_rrsigs(rrsets[i]),
			                        replace_owner, node->owner);
		}

		if (rc != KNOT_EOK) {
			return rc;
		}
	}

	free(rrsets);

	dbg_zone("Node OK\n");
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static const knot_node_t *knot_zone_contents_find_wildcard_child(
        knot_zone_contents_t *zone, const knot_node_t *closest_encloser)
{
	assert(zone != NULL);
	assert(closest_encloser != NULL);

	knot_dname_t *tmp = knot_dname_new_from_str("*", 1, NULL);
	CHECK_ALLOC(tmp, NULL);

	knot_dname_t *wildcard = knot_dname_cat(tmp, knot_node_owner(
	                                                closest_encloser));
	if (wildcard == NULL) {
		free(tmp);
		return NULL;
	}

	assert(wildcard == tmp);

dbg_zone_exec_detail(
	char *name = knot_dname_to_str(knot_node_owner(closest_encloser));
	char *name2 = knot_dname_to_str(wildcard);
	dbg_zone_detail("Searching for wildcard child of %s (%s)\n", name,
	                name2);
	free(name);
	free(name2);
);

	const knot_node_t *found = NULL, *ce = NULL, *prev = NULL;
	int ret = knot_zone_contents_find_dname(zone, wildcard, &found, &ce,
	                                        &prev);

	knot_dname_free(&wildcard);

	if (ret != KNOT_ZONE_NAME_FOUND) {
		return NULL;
	} else {
		return found;
	}
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
                                                 knot_node_t *node, int pos)
{
	const knot_rdata_item_t *dname_item = knot_rdata_item(rdata, pos);

	assert(dname_item);

	if (dname_item != NULL) {
		knot_dname_t *dname = dname_item->dname;

		/*
		 * The case when dname.node is already set is handled here.
		 * No use to check it later.
		 */
		if (knot_dname_node(dname) != NULL
		    || !knot_dname_is_subdomain(dname, knot_node_owner(
		                              knot_zone_contents_apex(zone)))) {
			// The name's node is either already set
			// or the name does not belong to the zone
			dbg_zone_detail("Name's (%p) node either set or the name"
			                "does not belong to the zone (%p).\n",
			                dname, knot_dname_node(dname));
			return;
		}

		const knot_node_t *n = NULL;
		const knot_node_t *closest_encloser = NULL;
		const knot_node_t *prev = NULL;

		int ret = knot_zone_contents_find_dname(zone, dname, &n,
		                                      &closest_encloser, &prev);

		if (ret == KNOT_EINVAL || ret == KNOT_EBADZONE) {
			// TODO: do some cleanup if needed
			dbg_zone_detail("Failed to find the name in zone: %s\n",
			                knot_strerror(ret));
			return;
		}

		assert(ret != KNOT_ZONE_NAME_FOUND || n == closest_encloser);

		if (ret != KNOT_ZONE_NAME_FOUND && (closest_encloser != NULL)) {
			/*!
			 * \note There is no need to set closer encloser to the
			 *       name. We may find the possible wildcard child
			 *       right away.
			 *       Having the closest encloser saved in the dname
			 *       would disrupt the query processing algorithms
			 *       anyway.
			 */

			dbg_zone_verb("Trying to find wildcard child.\n");

			n = knot_zone_contents_find_wildcard_child(zone,
			                                      closest_encloser);

			if (n != NULL) {
				knot_dname_set_node(dname, (knot_node_t *)n);
				dbg_zone_exec_detail(
					char *name = knot_dname_to_str(
					                    knot_node_owner(n));
					char *name2 = knot_dname_to_str(dname);
					dbg_zone_detail("Set wildcard node %s "
					                "to RDATA dname %s.\n",
					                name, name2);
					free(name);
					free(name2);
				);
			}
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
				                                     zone, node,
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

			knot_zone_contents_adjust_rdata_item(rdata, zone, node,
			                                     i);
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
			knot_zone_contents_adjust_rdata_in_rrset(rrsigs, zone,
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
 *
 * \todo Consider whether this function should replace RRSet owners with
 *       node owner + store this owner to the dname table. This is now done
 *       in the inserting function, though that may not be always used (e.g.
 *       old changeset processing).
 */
static void knot_zone_contents_adjust_node(knot_node_t *node,
                                           knot_zone_contents_t *zone)
{
	// adjust domain names in RDATA
	/*! \note Enabled again after a LONG time. Should test thoroughly. */
	knot_zone_contents_adjust_rrsets(node, zone);

	// assure that owner has proper node
	if (knot_dname_node(knot_node_owner(node)) == NULL) {
		knot_dname_set_node(knot_node_get_owner(node), node);
	}

	// check if this node is not a wildcard child of its parent
	if (knot_dname_is_wildcard(knot_node_owner(node))) {
		assert(knot_node_parent(node) != NULL);
		knot_node_set_wildcard_child(knot_node_get_parent(node), node);
	}

	// NSEC3 node (only if NSEC3 tree is not empty)
	const knot_node_t *prev;
	const knot_node_t *nsec3;
	int match = knot_zone_contents_find_nsec3_for_name(zone,
	                                                  knot_node_owner(node),
	                                                  &nsec3, &prev);
	UNUSED(prev);
	
	if (match != KNOT_ZONE_NAME_FOUND) {
		nsec3 = NULL;
	}

	knot_node_set_nsec3_node(node, (knot_node_t *)nsec3);

	dbg_zone_detail("Set flags to the node: \n");
	dbg_zone_detail("Delegation point: %s\n",
	                knot_node_is_deleg_point(node) ? "yes" : "no");
	dbg_zone_detail("Non-authoritative: %s\n",
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

	if (args->err != KNOT_EOK) {
		dbg_xfrin_detail("Error during adjusting: %s, skipping node.\n",
		                 knot_strerror(args->err));
		return;
	}

dbg_zone_exec_verb(
	char *name = knot_dname_to_str(node->owner);
	dbg_zone_verb("----- Adjusting node %s -----\n", name);
	free(name);
);

	knot_zone_contents_t *zone = args->zone;

	/*
	 * 1) Store domain names to dname table.
	 * TODO: make optional!
	 */
	assert(zone->dname_table != NULL);

	int ret = knot_zone_contents_dnames_from_node_to_table(
	                        zone->dname_table, node);
	if (ret != KNOT_EOK) {
		dbg_xfrin("Failed to add dnames from adjusted node to "
		          "table: %s\n", knot_strerror(ret));
		args->err = ret;
		return;
	}

	/*
	 * 2) Do other adjusting (flags, closest enclosers, wildcard children,
	 *    etc.).
	 */
	knot_zone_contents_adjust_node(node, zone);
}

/*----------------------------------------------------------------------------*/

static void knot_zone_contents_adjust_node_in_tree_ptr(
		knot_zone_tree_node_t *tnode, void *data)
{
	assert(data != NULL);
	assert(tnode != NULL);
	assert(tnode->node != NULL);

	knot_zone_adjust_arg_t *args = (knot_zone_adjust_arg_t *)data;
	knot_node_t *node = tnode->node;

	dbg_zone_exec_detail(
	if (knot_node_parent(node)) {
		char *name = knot_dname_to_str(knot_node_owner(
				knot_node_parent(node)));
		dbg_zone_detail("Parent: %s\n", name);
		dbg_zone_detail("Parent is delegation point: %s\n",
		       knot_node_is_deleg_point(knot_node_parent(node))
		       ? "yes" : "no");
		dbg_zone_detail("Parent is non-authoritative: %s\n",
		       knot_node_is_non_auth(knot_node_parent(node))
		       ? "yes" : "no");
		free(name);
	} else {
		dbg_zone_detail("No parent!\n");
	}
);
	/*
	 * 1) delegation point / non-authoritative node
	 */
	if (knot_node_parent(node)
	    && (knot_node_is_deleg_point(knot_node_parent(node))
		|| knot_node_is_non_auth(knot_node_parent(node)))) {
		knot_node_set_non_auth(node);
	} else if (knot_node_rrset(node, KNOT_RRTYPE_NS) != NULL
		   && node != args->zone->apex) {
		knot_node_set_deleg_point(node);
	} else {
		knot_node_set_auth(node);
	}

	/*
	 * 2) Set previous node pointer.
	 */
	knot_node_set_previous(node, args->previous_node);

	if (args->first_node == NULL) {
		args->first_node = node;
	}

	/*
	 * 3) Store previous node depending on the type of this node.
	 */
	if (!knot_node_is_non_auth(node)
	    && knot_node_rrset_count(node) > 0) {
		args->previous_node = node;
	}
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

	if (args->err != KNOT_EOK) {
		dbg_xfrin_detail("Error during adjusting: %s, skipping node.\n",
		                 knot_strerror(args->err));
		return;
	}

	// assure that owner has proper node
	if (knot_dname_node(knot_node_owner(node)) == NULL) {
		knot_dname_set_node(knot_node_get_owner(node), node);
	}

	/*
	 * Store domain names to dname table.
	 */
	knot_zone_contents_t *zone = args->zone;
	assert(zone != NULL);

	int ret = knot_zone_contents_dnames_from_node_to_table(
	                        zone->dname_table, node);
	if (ret != KNOT_EOK) {
		dbg_xfrin("Failed to add dnames from adjusted node to "
		          "table: %s\n", knot_strerror(ret));
		args->err = ret;
		return;
	}
}

/*----------------------------------------------------------------------------*/

static void knot_zone_contents_adjust_nsec3_node_in_tree_ptr(
		knot_zone_tree_node_t *tnode, void *data)
{
	assert(data != NULL);
	assert(tnode != NULL);
	assert(tnode->node != NULL);

	knot_zone_adjust_arg_t *args = (knot_zone_adjust_arg_t *)data;
	knot_node_t *node = tnode->node;

	// set previous node
	knot_node_set_previous(node, args->previous_node);

	// here is nothing to consider, all nodes are the same
	args->previous_node = node;

	if (args->first_node == NULL) {
		args->first_node = node;
	}
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

dbg_zone_exec_verb(
	char *n = knot_dname_to_str(name);
	dbg_zone_verb("Hashing name %s.\n", n);
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
		dbg_zone("Error while encoding hashed name %s to base32.\n", n);
		free(n);
		if (name_b32 != NULL) {
			free(name_b32);
		}
		return KNOT_ECRYPTO;
	}

	assert(name_b32 != NULL);
	free(hashed_name);

	dbg_zone_verb("Base32-encoded hash: %s\n", name_b32);

	/* Will be returned to caller, make sure it is released after use. */
	*nsec3_name = knot_dname_new_from_str(name_b32, size, NULL);

	free(name_b32);

	if (*nsec3_name == NULL) {
		dbg_zone("Error while creating domain name for hashed name.\n");
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

	int exact_match = knot_zone_tree_get_less_or_equal(tree, name, &found,
	                                                   &prev);

	assert(exact_match >= 0);
	*node = found;
	*previous = prev;

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
/* CNAME chain checking                                                       */
/*----------------------------------------------------------------------------*/

typedef struct cname_chain {
	const knot_node_t *node;
	struct cname_chain *next;
} cname_chain_t;

/*----------------------------------------------------------------------------*/

static int cname_chain_add(cname_chain_t **last, const knot_node_t *node)
{
	assert(last != NULL);

	cname_chain_t *new_cname =
	                (cname_chain_t *)malloc(sizeof(cname_chain_t));
	CHECK_ALLOC_LOG(new_cname, KNOT_ENOMEM);

	new_cname->node = node;
	new_cname->next = NULL;

	if (*last != NULL) {
		(*last)->next = new_cname;
	} else {
		*last = new_cname;
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int cname_chain_contains(cname_chain_t *chain, const knot_node_t *node)
{
	cname_chain_t *act = chain;
	while (act != NULL) {
		if (act->node == node) {
			return 1;
		}
		act = act->next;
	}

	return 0;
}

/*----------------------------------------------------------------------------*/

static void cname_chain_free(cname_chain_t *chain)
{
	cname_chain_t *act = chain;

	while (act != NULL) {
		chain = chain->next;
		free(act);
		act = chain;
	}
}

/*----------------------------------------------------------------------------*/

typedef struct loop_check_data {
	knot_zone_contents_t *zone;
	int err;
} loop_check_data_t;

/*----------------------------------------------------------------------------*/

static void knot_zone_contents_check_loops_in_tree(knot_zone_tree_node_t *tnode,
                                                   void *data)
{
	assert(tnode != NULL);
	assert(tnode->node != NULL);
	assert(data != NULL);

	loop_check_data_t *args = (loop_check_data_t *)data;
	const knot_node_t *node = tnode->node;

	assert(args->zone != NULL);

	if (args->err != KNOT_EOK) {
		dbg_xfrin_detail("Error during CNAME loop checking, skipping "
		                 "node.\n");
		return;
	}

	// if there is CNAME in the node
	const knot_rrset_t *cname = knot_node_rrset(node, KNOT_RRTYPE_CNAME);
	cname_chain_t *chain = NULL;
	cname_chain_t **act_cname = &chain;
	int ret = 0;

	while (cname != NULL && !cname_chain_contains(chain, node)) {
		ret = cname_chain_add(act_cname, node);
		if (ret != KNOT_EOK) {
			cname_chain_free(chain);
			args->err = ret;
			return;
		}
		act_cname = &(*act_cname)->next;

		// follow the CNAME chain, including wildcards and
		// remember the nodes passed through
		const knot_dname_t *next_name = knot_rdata_cname_name(
		                        knot_rrset_rdata(cname));
		assert(next_name != NULL);
		const knot_node_t *next_node = knot_dname_node(next_name);
		if (next_node == NULL) {
			// try to find the name in the zone
			const knot_node_t *ce = NULL;
			ret = knot_zone_contents_find_dname_hash(
			                        args->zone, next_name,
			                        &next_node, &ce);

			if (ret != KNOT_ZONE_NAME_FOUND
			    && ce != NULL) {
				// try to find wildcard child
				assert(knot_dname_is_subdomain(next_name,
				                          knot_node_owner(ce)));
				next_node = knot_node_wildcard_child(ce);
			}

			assert(next_node == NULL || knot_dname_compare(
			           knot_node_owner(next_node), next_name) == 0
			 || knot_dname_is_wildcard(knot_node_owner(next_node)));
		}

		if (next_node == NULL) {
			// no CNAME node to follow
			cname = NULL;
		} else {
			node = next_node;
			cname = knot_node_rrset(node, KNOT_RRTYPE_CNAME);
		}
	}

	if (cname != NULL) {
		// this means the node is in the chain already
		args->err = KNOT_ECNAME;
	}

	cname_chain_free(chain);
}

/*----------------------------------------------------------------------------*/

static int knot_zc_nsec3_parameters_match(const knot_rdata_t *rdata,
                                          const knot_nsec3_params_t *params)
{
	assert(rdata != NULL && params != NULL);
	
	dbg_zone_detail("RDATA algo: %u, iterations: %u, salt length: %u, salt:"
	                " %.*s\n", 
	                knot_rdata_nsec3_algorithm(rdata),
	                knot_rdata_nsec3_iterations(rdata),
	                knot_rdata_nsec3_salt_length(rdata),
	                knot_rdata_nsec3_salt_length(rdata),
	                knot_rdata_nsec3_salt(rdata));
	dbg_zone_detail("NSEC3PARAM algo: %u, iterations: %u, salt length: %u, "
	                "salt: %.*s\n",  params->algorithm, params->iterations,
	                params->salt_length, params->salt_length, params->salt);
	
	return (knot_rdata_nsec3_algorithm(rdata) == params->algorithm
	        && knot_rdata_nsec3_iterations(rdata) == params->iterations
	        && knot_rdata_nsec3_salt_length(rdata) == params->salt_length
	        && strncmp((const char *)knot_rdata_nsec3_salt(rdata),
	                   (const char *)params->salt, params->salt_length)
	           == 0);
}

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

knot_zone_contents_t *knot_zone_contents_new(knot_node_t *apex,
                                             uint node_count,
                                             int use_domain_table,
                                             struct knot_zone *zone)
{
	dbg_zone("Creating contents for %u nodes.\n", node_count);
	knot_zone_contents_t *contents = (knot_zone_contents_t *)
	                              calloc(1, sizeof(knot_zone_contents_t));
	if (contents == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	contents->apex = apex;
	contents->zone = zone;
	knot_node_set_zone(apex, contents->zone);
	contents->node_count = 1;

	dbg_zone_verb("Creating tree for normal nodes.\n");
	contents->nodes = malloc(sizeof(knot_zone_tree_t));
	if (contents->nodes == NULL) {
		ERR_ALLOC_FAILED;
		goto cleanup;
	}

	dbg_zone_verb("Creating tree for NSEC3 nodes.\n");
	contents->nsec3_nodes = malloc(sizeof(knot_zone_tree_t));
	if (contents->nsec3_nodes == NULL) {
		ERR_ALLOC_FAILED;
		goto cleanup;
	}

	if (use_domain_table) {
		dbg_zone_verb("Creating domain name table.\n");
		contents->dname_table = knot_dname_table_new();
		if (contents->dname_table == NULL) {
			ERR_ALLOC_FAILED;
			goto cleanup;
		}
	} else {
		contents->dname_table = NULL;
	}

	//contents->node_count = node_count;

	/* Initialize NSEC3 params */
	dbg_zone_verb("Initializing NSEC3 parameters.\n");
	contents->nsec3_params.algorithm = 0;
	contents->nsec3_params.flags = 0;
	contents->nsec3_params.iterations = 0;
	contents->nsec3_params.salt_length = 0;
	contents->nsec3_params.salt = NULL;

	dbg_zone_verb("Initializing zone trees.\n");
	if (knot_zone_tree_init(contents->nodes) != KNOT_EOK
	    || knot_zone_tree_init(contents->nsec3_nodes) != KNOT_EOK) {
		goto cleanup;
	}

	dbg_zone_verb("Inserting apex into the zone tree.\n");
	if (knot_zone_tree_insert(contents->nodes, apex) != KNOT_EOK) {
		dbg_zone("Failed to insert apex to the zone tree.\n");
		goto cleanup;
	}

#ifdef USE_HASH_TABLE
	if (node_count > 0) {
		dbg_zone_verb("Creating hash table.\n");
		contents->table = ck_create_table(node_count);
		if (contents->table == NULL) {
			goto cleanup;
		}

		// insert the apex into the hash table
		dbg_zone_verb("Inserting apex into the hash table.\n");
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
		dbg_zone_verb("Inserting names from apex to table.\n");
		int rc = knot_zone_contents_dnames_from_node_to_table(
		             contents->dname_table, apex);
		if (rc != KNOT_EOK) {
			ck_destroy_table(&contents->table, NULL, 0);
			goto cleanup;
		}
	}

	return contents;

cleanup:
	dbg_zone_verb("Cleaning up.\n");
	free(contents->dname_table);
	free(contents->nodes);
	free(contents->nsec3_nodes);
	free(contents);
	return NULL;
}

/*----------------------------------------------------------------------------*/

int knot_zone_contents_gen_is_old(const knot_zone_contents_t *contents)
{
	return ((contents->flags & KNOT_ZONE_FLAGS_GEN_MASK)
	        == KNOT_ZONE_FLAGS_GEN_OLD);
}

/*----------------------------------------------------------------------------*/

int knot_zone_contents_gen_is_new(const knot_zone_contents_t *contents)
{
	return ((contents->flags & KNOT_ZONE_FLAGS_GEN_MASK)
	        == KNOT_ZONE_FLAGS_GEN_NEW);
}

/*----------------------------------------------------------------------------*/

int knot_zone_contents_gen_is_finished(const knot_zone_contents_t *contents)
{
	return ((contents->flags & KNOT_ZONE_FLAGS_GEN_MASK)
	        == KNOT_ZONE_FLAGS_GEN_FIN);
}

/*----------------------------------------------------------------------------*/

void knot_zone_contents_set_gen_old(knot_zone_contents_t *contents)
{
	contents->flags &= ~KNOT_ZONE_FLAGS_GEN_MASK;
	contents->flags |= KNOT_ZONE_FLAGS_GEN_OLD;
}

/*----------------------------------------------------------------------------*/

void knot_zone_contents_set_gen_new(knot_zone_contents_t *contents)
{
	contents->flags &= ~KNOT_ZONE_FLAGS_GEN_MASK;
	contents->flags |= KNOT_ZONE_FLAGS_GEN_NEW;
}

/*----------------------------------------------------------------------------*/

void knot_zone_contents_set_gen_new_finished(knot_zone_contents_t *contents)
{
	contents->flags &= ~KNOT_ZONE_FLAGS_GEN_MASK;
	contents->flags |= KNOT_ZONE_FLAGS_GEN_FIN;
}

/*----------------------------------------------------------------------------*/

int knot_zone_contents_any_disabled(const knot_zone_contents_t *contents)
{
	return ((contents->flags & KNOT_ZONE_FLAGS_ANY_MASK)
	        == KNOT_ZONE_FLAGS_ANY);
}

/*----------------------------------------------------------------------------*/

void knot_zone_contents_disable_any(knot_zone_contents_t *contents)
{
	contents->flags |= KNOT_ZONE_FLAGS_ANY;
}

/*----------------------------------------------------------------------------*/

void knot_zone_contents_enable_any(knot_zone_contents_t *contents)
{
	contents->flags &= ~KNOT_ZONE_FLAGS_ANY_MASK;
}

/*----------------------------------------------------------------------------*/

uint16_t knot_zone_contents_class(const knot_zone_contents_t *contents)
{
	if (contents == NULL || contents->apex == NULL
	    || knot_node_rrset(contents->apex, KNOT_RRTYPE_SOA) == NULL) {
		return KNOT_EINVAL;
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
		return KNOT_EINVAL;
	}

dbg_zone_exec_detail(
	char *name = knot_dname_to_str(knot_node_owner(node));
	dbg_zone_detail("Adding node to zone: %s.\n", name);
	free(name);
);

	int ret = 0;
	if ((ret = knot_zone_contents_check_node(zone, node)) != 0) {
		dbg_zone("Node check failed.\n");
		return ret;
	}

	ret = knot_zone_tree_insert(zone->nodes, node);
	if (ret != KNOT_EOK) {
		dbg_zone("Failed to insert node into zone tree.\n");
		return ret;
	}

	if (use_domain_table) {
		ret = knot_zone_contents_dnames_from_node_to_table(
		          zone->dname_table, node);
		if (ret != KNOT_EOK) {
			/*! \todo Remove node from the tree and hash table.*/
			dbg_zone("Failed to add dnames into table.\n");
			return ret;
		}
	}

#ifdef USE_HASH_TABLE
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

	knot_node_set_zone(node, zone->zone);

	++zone->node_count;

	if (!create_parents) {
		return KNOT_EOK;
	}

	dbg_zone_detail("Creating parents of the node.\n");

	knot_dname_t *chopped =
		knot_dname_left_chop(knot_node_owner(node));
	if(chopped == NULL) {
		/* Root domain and root domain only. */
		assert(node->owner && node->owner->labels && 
		       node->owner->labels[0] == 0);
		return KNOT_EOK;
	}
	
	if (knot_dname_compare(knot_node_owner(zone->apex), chopped) == 0) {
		dbg_zone_detail("Zone apex is the parent.\n");
		knot_node_set_parent(node, zone->apex);

		// check if the node is not wildcard child of the parent
		if (knot_dname_is_wildcard(
				knot_node_owner(node))) {
			knot_node_set_wildcard_child(zone->apex, node);
		}
	} else {
		knot_node_t *next_node;
		while ((next_node
		      = knot_zone_contents_get_node(zone, chopped)) == NULL &&
			chopped != NULL) {
			/* Adding new dname to zone + add to table. */
			dbg_zone_detail("Creating new node.\n");
			
			assert(chopped);
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
					knot_node_free(&next_node);
					knot_dname_release(chopped);
					return ret;
				}
			}

			if (next_node->owner != chopped) {
				/* Node owner was in RDATA */
				knot_dname_release(chopped);
				knot_dname_retain(next_node->owner);
				chopped = next_node->owner;
			}

			assert(knot_zone_contents_find_node(zone, chopped)
			       == NULL);
			assert(knot_node_owner(next_node) == chopped);

			dbg_zone_detail("Inserting new node to zone tree.\n");

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
dbg_zone_exec_detail(
			char *name = knot_dname_to_str(
					knot_node_owner(next_node));
			dbg_zone_detail("Adding new node with owner %s to "
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
#endif
			// set parent
			knot_node_set_parent(node, next_node);

			// set zone
			knot_node_set_zone(next_node, zone->zone);

			// check if the node is not wildcard child of the parent
			if (knot_dname_is_wildcard(
					knot_node_owner(node))) {
				knot_node_set_wildcard_child(next_node, node);
			}

			++zone->node_count;

			dbg_zone_detail("Next parent.\n");
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
		assert(knot_node_parent(node) == NULL);
		knot_node_set_parent(node, next_node);

		dbg_zone_detail("Created all parents.\n");
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
		return KNOT_EINVAL;
	}

dbg_zone_exec_detail(
	char *name = knot_dname_to_str(knot_rrset_owner(rrset));
	dbg_zone_detail("Adding RRSet to zone contents: %s, type %s\n",
	                name, knot_rrtype_to_string(knot_rrset_type(rrset)));
	free(name);
);

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
	if (dupl == KNOT_RRSET_DUPL_MERGE) {
		rc = knot_node_add_rrset_no_dupl(*node, rrset);
	} else {
		rc = knot_node_add_rrset(*node, rrset, 0);
	}

	if (rc < 0) {
		dbg_zone("Failed to add RRSet to node.\n");
		return rc;
	}

	int ret = rc;

	if (use_domain_table) {
		dbg_zone_detail("Saving RRSet to table.\n");
		rc = knot_zone_contents_dnames_from_rrset_to_table(
		         zone->dname_table, rrset, 0, (*node)->owner);
		if (rc != KNOT_EOK) {
			dbg_zone("Error saving domain names from "
			         "RRSIGs to the domain name table.\n "
			         "The zone may be in an inconsistent state.\n");
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

	dbg_zone_detail("RRSet OK.\n");
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
	dbg_zone_verb("Adding RRSIGs to zone contents.\n");

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
		return KNOT_EINVAL;
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
		dbg_zone("RRSIGs do not belong to the given RRSet.\n");
		return KNOT_EINVAL;
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
		dbg_zone_detail("Finding RRSet for type %s\n",
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

	int rc;
	int ret = KNOT_EOK;

	rc = knot_rrset_add_rrsigs(*rrset, rrsigs, dupl);
	if (rc < 0) {
		dbg_zone("Failed to add RRSIGs to RRSet.\n");
		return rc;
	} else if (rc > 0) {
		assert(dupl == KNOT_RRSET_DUPL_MERGE ||
		       dupl == KNOT_RRSET_DUPL_SKIP);
		ret = 1;
	}

	// add all domain names from the RRSet to domain name table
	if (use_domain_table) {
		dbg_zone_detail("Saving RRSIG RRSet to table.\n");
		rc = knot_zone_contents_dnames_from_rrset_to_table(
		       zone->dname_table, (*rrset)->rrsigs, 0, (*rrset)->owner);
		if (rc != KNOT_EOK) {
			dbg_zone("Error saving domain names from "
			         "RRSIGs to the domain name table.\n "
			         "The zone may be in an inconsistent state.\n");
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

	dbg_zone_detail("RRSIGs OK\n");
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
		return KNOT_EINVAL;
	}

	int ret = 0;
	if ((ret = knot_zone_contents_check_node(zone, node)) != 0) {
		dbg_zone("Failed node check: %s\n", knot_strerror(ret));
		return ret;
	}

	// how to know if this is successfull??
//	TREE_INSERT(zone->nsec3_nodes, knot_node, avl, node);
	ret = knot_zone_tree_insert(zone->nsec3_nodes, node);
	if (ret != KNOT_EOK) {
		dbg_zone("Failed to insert node into NSEC3 tree: %s.\n",
		         knot_strerror(ret));
		return ret;
	}

	if (use_domain_table) {
		ret = knot_zone_contents_dnames_from_node_to_table(
		           zone->dname_table, node);
		if (ret != KNOT_EOK) {
			/*! \todo Remove the node from the tree. */
			dbg_zone("Failed to add dnames into table: %s.\n",
			         knot_strerror(ret));
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
		return KNOT_EINVAL;
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
	if (dupl == KNOT_RRSET_DUPL_MERGE) {
		rc = knot_node_add_rrset_no_dupl(*node, rrset);
	} else {
		rc = knot_node_add_rrset(*node, rrset, 0);
	}

	if (rc < 0) {
		return rc;
	}

	int ret = rc;

	if (use_domain_table) {
		dbg_zone_detail("Saving NSEC3 RRSet to table.\n");
		rc = knot_zone_contents_dnames_from_rrset_to_table(
		         zone->dname_table, rrset, 0, (*node)->owner);
		if (rc != KNOT_EOK) {
			dbg_zone("Error saving domain names from "
			         "RRSIGs to the domain name table.\n "
			         "The zone may be in an inconsistent state.\n");
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

	dbg_zone_detail("NSEC3 OK\n");
	return ret;
}

/*----------------------------------------------------------------------------*/

int knot_zone_contents_remove_node(knot_zone_contents_t *contents, 
	const knot_node_t *node, knot_zone_tree_node_t **removed_tree, 
	ck_hash_table_item_t **removed_hash)
{
	if (contents == NULL || node == NULL) {
		return KNOT_EINVAL;
	}

	const knot_dname_t *owner = knot_node_owner(node);

dbg_zone_exec_verb(
	char *name = knot_dname_to_str(owner);
	dbg_zone_verb("Removing zone node: %s\n", name);
	free(name);
);

	// 1) remove the node from hash table
	*removed_hash = NULL;
	*removed_hash = ck_remove_item(contents->table, 
	                               (const char *)knot_dname_name(owner),
	                               knot_dname_size(owner));
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
		return KNOT_EINVAL;
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
		return KNOT_EINVAL;
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
		return KNOT_EINVAL;
	}

dbg_zone_exec_verb(
	char *name_str = knot_dname_to_str(name);
	char *zone_str = knot_dname_to_str(zone->apex->owner);
	dbg_zone_verb("Searching for name %s in zone %s...\n",
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

dbg_zone_exec_detail(
	char *name_str = (*node) ? knot_dname_to_str((*node)->owner)
	                         : "(nil)";
	char *name_str2 = (*previous != NULL)
	                  ? knot_dname_to_str((*previous)->owner)
	                  : "(nil)";
dbg_zone_detail("Search function returned %d, node %s (%p) and prev: %s (%p)\n",
	                exact_match, name_str, *node, name_str2, *previous);

	if (*node) {
		free(name_str);
	}
	if (*previous != NULL) {
		free(name_str2);
	}
);
	// there must be at least one node with domain name less or equal to
	// the searched name if the name belongs to the zone (the root)
	if (*node == NULL && *previous == NULL) {
		return KNOT_EBADZONE;
	}

	/* This function was quite out of date. The find_in_tree() function
	 * may return NULL in the 'found' field, so we cannot search for the
	 * closest encloser from this node.
	 */

	if (exact_match) {
		*closest_encloser = *node;
	} else {
		*closest_encloser = *previous;
		assert(*closest_encloser != NULL);

		int matched_labels = knot_dname_matched_labels(
				knot_node_owner((*closest_encloser)), name);
		while (matched_labels < knot_dname_label_count(
				knot_node_owner((*closest_encloser)))) {
			(*closest_encloser) =
				knot_node_parent((*closest_encloser));
			assert(*closest_encloser);
		}
	}
dbg_zone_exec(
	char *n = knot_dname_to_str(knot_node_owner((*closest_encloser)));
	dbg_zone_detail("Closest encloser: %s\n", n);
	free(n);
);

	dbg_zone_verb("find_dname() returning %d\n", exact_match);

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
		return KNOT_EINVAL;
	}

dbg_zone_exec_verb(
	char *name_str = knot_dname_to_str(name);
	char *zone_str = knot_dname_to_str(zone->apex->owner);
	dbg_zone_verb("Searching for name %s in zone %s...\n",
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

	assert(zone->table != NULL);
	const ck_hash_table_item_t *item = ck_find_item(zone->table,
	                                                name_tmp, name_size);

	if (item != NULL) {
		*node = (const knot_node_t *)item->value;
		*closest_encloser = *node;

		dbg_zone_detail("Found node in hash table: %p (owner %p, "
		                "labels: %d)\n", *node, (*node)->owner,
		                knot_dname_label_count((*node)->owner));
		assert(*node != NULL);
		assert(*closest_encloser != NULL);
		return KNOT_ZONE_NAME_FOUND;
	}

	*node = NULL;

	// chop leftmost labels until some node is found
	// copy the name for chopping

	dbg_zone_detail("Finding closest encloser..\nStarting with: %.*s\n",
	                (int)name_size, name_tmp);

	while (item == NULL) {
		knot_zone_contents_left_chop(name_tmp, &name_size);
dbg_zone_exec_detail(
		dbg_zone_detail("Chopped leftmost label: %.*s\n",
		               (int)name_size, name_tmp);
);
		// not satisfied in root zone!!
		assert(name_size > 0);

		item = ck_find_item(zone->table, name_tmp, name_size);
	}

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
                                    const knot_node_t **nsec3_previous)
{
	if (zone == NULL || name == NULL
	    || nsec3_node == NULL || nsec3_previous == NULL) {
		return KNOT_EINVAL;
	}

	knot_dname_t *nsec3_name = NULL;
	int ret = knot_zone_contents_nsec3_name(zone, name, &nsec3_name);

	if (ret != KNOT_EOK) {
		return ret;
	}

	// check if the NSEC3 tree is not empty
	if (zone->nsec3_nodes->th_root == NULL) {
		dbg_zone("NSEC3 tree is empty.\n");
		knot_dname_release(nsec3_name);
		return KNOT_ENSEC3CHAIN;
	}

dbg_zone_exec_verb(
	char *n = knot_dname_to_str(nsec3_name);
	dbg_zone_verb("NSEC3 node name: %s.\n", n);
	free(n);
);

	const knot_node_t *found = NULL, *prev = NULL;

	// create dummy node to use for lookup
	int exact_match = knot_zone_tree_find_less_or_equal(
		zone->nsec3_nodes, nsec3_name, &found, &prev);
	assert(exact_match >= 0);

	knot_dname_release(nsec3_name);

dbg_zone_exec_detail(
	if (found) {
		char *n = knot_dname_to_str(found->owner);
		dbg_zone_detail("Found NSEC3 node: %s.\n", n);
		free(n);
	} else {
		dbg_zone_detail("Found no NSEC3 node.\n");
	}

	if (prev) {
		assert(prev->owner);
		char *n = knot_dname_to_str(prev->owner);
		dbg_zone_detail("Found previous NSEC3 node: %s.\n", n);
		free(n);
	} else {
		dbg_zone_detail("Found no previous NSEC3 node.\n");
	}
);
	*nsec3_node = found;

	// This check cannot be used now, the function returns proper return
	// value if the node was not found
//	if (*nsec3_node == NULL) {
//		// there is no NSEC3 node even if there should be
//		return KNOT_ENSEC3CHAIN;
//	}

	if (prev == NULL) {
		// either the returned node is the root of the tree, or it is
		// the leftmost node in the tree; in both cases node was found
		// set the previous node of the found node
		assert(exact_match);
		assert(*nsec3_node != NULL);
		*nsec3_previous = knot_node_previous(*nsec3_node);
	} else {
		*nsec3_previous = prev;
	}

	dbg_zone_verb("find_nsec3_for_name() returning %d\n", exact_match);
	
	/* The previous may be from wrong NSEC3 chain. Search for previous 
	 * from the right chain. Check iterations, hash algorithm and salt 
	 * values and compare them to the ones from NSEC3PARAM.
	 */
	const knot_rrset_t *nsec3_rrset = knot_node_rrset(*nsec3_previous, 
	                                                  KNOT_RRTYPE_NSEC3);
	const knot_rdata_t *nsec3_rdata = (nsec3_rrset != NULL)
				? knot_rrset_rdata(nsec3_rrset)
				: NULL;
	const knot_node_t *original_prev = *nsec3_previous;
	
	while (nsec3_rdata != NULL
	       && !knot_zc_nsec3_parameters_match(nsec3_rdata, 
	                                          &zone->nsec3_params)) {
		/* Try other RDATA if there are some. In case of name collision
		 * the node would contain records from both NSEC3 chains.
		 */
		if ((nsec3_rdata = knot_rrset_rdata_next(
		             nsec3_rrset, nsec3_rdata)) != NULL) {
			continue;
		}
		
		/* If there is none, try previous node. */
		
		*nsec3_previous = knot_node_previous(*nsec3_previous);
		nsec3_rrset = knot_node_rrset(*nsec3_previous, 
		                              KNOT_RRTYPE_NSEC3);
		nsec3_rdata = (nsec3_rrset != NULL)
		                ? knot_rrset_rdata(nsec3_rrset)
		                : NULL;
dbg_zone_exec_detail(
		char *name = (*nsec3_previous) 
				? knot_dname_to_str(
					  knot_node_owner(*nsec3_previous))
				: "none";
		dbg_zone_detail("Previous node: %s, checking parameters...\n",
				name);
		if (*nsec3_previous) {
			free(name);
		}
);
		if (*nsec3_previous == original_prev || nsec3_rdata == NULL) {
			// cycle
			*nsec3_previous = NULL;
			break;
		}
	}

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

int knot_zone_contents_adjust(knot_zone_contents_t *zone)
{
	if (zone == NULL) {
		return KNOT_EINVAL;
	}

	// load NSEC3PARAM (needed on adjusting function)
	knot_zone_contents_load_nsec3param(zone);

	knot_zone_adjust_arg_t adjust_arg;
	adjust_arg.zone = zone;
	adjust_arg.first_node = NULL;
	adjust_arg.previous_node = NULL;
	adjust_arg.err = KNOT_EOK;

	/*
	 * First of all we must set node.prev pointers, as these are used in
	 * the search functions.
	 *
	 * We must also set flags, as these are required to set the prev
	 * pointers well.
	 */
	dbg_zone("Setting 'prev' pointers to NSEC3 nodes.\n");
	int ret = knot_zone_tree_forward_apply_inorder(zone->nsec3_nodes,
	         knot_zone_contents_adjust_nsec3_node_in_tree_ptr, &adjust_arg);
	assert(ret == KNOT_EOK);

	if (adjust_arg.err != KNOT_EOK) {
		dbg_zone("Failed to set 'prev' pointers to NSEC3 nodes: %s\n",
		         knot_strerror(adjust_arg.err));
		return adjust_arg.err;
	}

	// set the last node as previous of the first node
	if (adjust_arg.first_node) {
		knot_node_set_previous(adjust_arg.first_node,
		                       adjust_arg.previous_node);
	}
	dbg_zone("Done.\n");

	adjust_arg.first_node = NULL;
	adjust_arg.previous_node = NULL;

	dbg_zone("Setting 'prev' pointers to normal nodes.\n");
	ret = knot_zone_tree_forward_apply_inorder(zone->nodes,
	         knot_zone_contents_adjust_node_in_tree_ptr, &adjust_arg);
	assert(ret == KNOT_EOK);

	if (adjust_arg.err != KNOT_EOK) {
		dbg_zone("Failed to set 'prev' pointers to normal nodes: %s\n",
		         knot_strerror(adjust_arg.err));
		return adjust_arg.err;
	}

	// set the last node as previous of the first node
	assert(zone->apex == adjust_arg.first_node);
	knot_node_set_previous(zone->apex, adjust_arg.previous_node);
	dbg_zone("Done.\n");

	/*
	 * Adjust the NSEC3 nodes first.
	 * There are independent on the normal nodes, but the normal nodes are
	 * dependent on them.
	 */

	dbg_zone("Adjusting NSEC3 nodes.\n");
	ret = knot_zone_tree_forward_apply_inorder(zone->nsec3_nodes,
	             knot_zone_contents_adjust_nsec3_node_in_tree, &adjust_arg);
	assert(ret == KNOT_EOK);

	if (adjust_arg.err != KNOT_EOK) {
		dbg_zone("Failed to adjust NSEC3 nodes: %s\n",
		         knot_strerror(adjust_arg.err));
		return adjust_arg.err;
	}

	dbg_zone("Adjusting normal nodes.\n");
	ret = knot_zone_tree_forward_apply_inorder(zone->nodes,
	                        knot_zone_contents_adjust_node_in_tree,
	                        &adjust_arg);
	assert(ret == KNOT_EOK);

	if (adjust_arg.err != KNOT_EOK) {
		dbg_zone("Failed to adjust normal nodes: %s\n",
		         knot_strerror(adjust_arg.err));
		return adjust_arg.err;
	}

	dbg_zone("Done.\n");

	return ret;
}

/*----------------------------------------------------------------------------*/

int knot_zone_contents_check_loops(knot_zone_contents_t *zone)
{
	if (zone == NULL) {
		return KNOT_EINVAL;
	}

	dbg_zone("Checking CNAME and wildcard loops.\n");

	loop_check_data_t data;
	data.err = KNOT_EOK;
	data.zone = zone;

	assert(zone->nodes != NULL);
	knot_zone_tree_forward_apply_inorder(zone->nodes,
	                                 knot_zone_contents_check_loops_in_tree,
	                                 (void *)&data);

	if (data.err != KNOT_EOK) {
		dbg_zone("Found CNAME loop in data. Aborting transfer.\n");
		return data.err;
	}

	dbg_zone("Done\n");

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_zone_contents_load_nsec3param(knot_zone_contents_t *zone)
{
	if (zone == NULL || zone->apex == NULL) {
		return KNOT_EINVAL;
	}

	const knot_rrset_t *rrset = knot_node_rrset(zone->apex,
	                                            KNOT_RRTYPE_NSEC3PARAM);

	if (rrset != NULL) {
		int r = knot_nsec3_params_from_wire(&zone->nsec3_params, rrset);
		assert(r == KNOT_EOK);
	} else {
		memset(&zone->nsec3_params, 0, sizeof(knot_nsec3_params_t));
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_zone_contents_nsec3_enabled(const knot_zone_contents_t *zone)
{
	if (zone == NULL) {
		return KNOT_EINVAL;
	}

	return (zone->nsec3_params.algorithm != 0
	        && zone->nsec3_nodes->th_root != NULL);
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
		return KNOT_EINVAL;
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
		return KNOT_EINVAL;
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
		return KNOT_EINVAL;
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
		return KNOT_EINVAL;
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
		return KNOT_EINVAL;
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
		return KNOT_EINVAL;
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
		return KNOT_EINVAL;
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
		return KNOT_EINVAL;
	}

	/* Copy to same destination as source. */
	if (from == *to) {
		return KNOT_EINVAL;
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
	contents->flags = from->flags;

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
			dbg_zone_verb("knot_zone_contents_shallow_copy: "
			              "hash table copied\n");
			ret = KNOT_ERROR;
			goto cleanup;
		}
	}
#endif

	dbg_zone("knot_zone_contents_shallow_copy: finished OK\n");

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

int knot_zone_contents_shallow_copy2(const knot_zone_contents_t *from,
                                     knot_zone_contents_t **to)
{
	if (from == NULL || to == NULL) {
		return KNOT_EINVAL;
	}

	/* Copy to same destination as source. */
	if (from == *to) {
		return KNOT_EINVAL;
	}

	int ret = KNOT_EOK;

	knot_zone_contents_t *contents = (knot_zone_contents_t *)calloc(
	                                     1, sizeof(knot_zone_contents_t));
	if (contents == NULL) {
		ERR_ALLOC_FAILED;
		return KNOT_ENOMEM;
	}

	//contents->apex = from->apex;

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
	contents->flags = from->flags;
	// set the 'new' flag
	knot_zone_contents_set_gen_new(contents);

	contents->zone = from->zone;

	if ((ret = knot_zone_tree_deep_copy(from->nodes,
	                                    contents->nodes)) != KNOT_EOK
	    || (ret = knot_zone_tree_deep_copy(from->nsec3_nodes,
	                                  contents->nsec3_nodes)) != KNOT_EOK) {
		goto cleanup;
	}

#ifdef USE_HASH_TABLE
	if (from->table != NULL) {
		ret = ck_deep_copy(from->table, &contents->table);
		if (ret != 0) {
			dbg_zone_verb("knot_zone_contents_shallow_copy: "
			              "hash table copied\n");
			ret = KNOT_ERROR;
			goto cleanup;
		}
	}
#endif
	contents->apex = knot_node_get_new_node(from->apex);

	dbg_zone("knot_zone_contents_shallow_copy: finished OK\n");

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

/*----------------------------------------------------------------------------*/
/* Integrity check                                                            */
/*----------------------------------------------------------------------------*/

typedef struct check_data {
	const knot_zone_contents_t *contents;
	const knot_node_t *previous;
	const knot_node_t *deleg_point;
	const knot_node_t *parent;
	int children;
	int errors;
} check_data_t;

/*----------------------------------------------------------------------------*/

static void knot_zc_integrity_check_previous(const knot_node_t *node,
                                             check_data_t *check_data,
                                             const char *name)
{
	// first, check if the previous and next pointers are set properly
	if (check_data->previous != NULL) {
		char *name_prev = knot_dname_to_str(
		                        knot_node_owner(check_data->previous));

		if (knot_node_previous(node) != check_data->previous) {
			char *name2 = knot_dname_to_str(knot_node_owner(
						     knot_node_previous(node)));
			fprintf(stderr, "Wrong previous node: node: %s, "
				"previous: %s. Should be: %s.\n", name, name2,
				name_prev);
			free(name2);

			++check_data->errors;
		}

		free(name_prev);
	}
}

/*----------------------------------------------------------------------------*/

static void knot_zc_integrity_check_flags(const knot_node_t *node,
                                          check_data_t *check_data,
                                          char *name)
{
	if (node == knot_zone_contents_apex(check_data->contents)) {
		if (!knot_node_is_auth(node)) {
			fprintf(stderr, "Wrong flags: node %s, flags: %u. "
			        "Should be non-authoritative.\n", name,
			        node->flags);
			++check_data->errors;
		}
		return;
	}

	// check the flags
	if (check_data->deleg_point != NULL
	    && knot_dname_is_subdomain(knot_node_owner(node),
	                            knot_node_owner(check_data->deleg_point))) {
		// this is a non-authoritative node
		if (!knot_node_is_non_auth(node)) {
			fprintf(stderr, "Wrong flags: node %s, flags: %u. "
			        "Should be non-authoritative.\n", name,
			        node->flags);
			++check_data->errors;
		}
	} else {
		if (knot_node_rrset(node, KNOT_RRTYPE_NS) != NULL) {
			// this is a delegation point
			if (!knot_node_is_deleg_point(node)) {
				fprintf(stderr, "Wrong flags: node %s, flags: "
				        "%u. Should be deleg. point.\n", name,
				        node->flags);
				++check_data->errors;
			}
			check_data->deleg_point = node;
		} else {
			// this is an authoritative node
			if (!knot_node_is_auth(node)) {
				fprintf(stderr, "Wrong flags: node %s, flags: "
				        "%u. Should be authoritative.\n", name,
				        node->flags);
				++check_data->errors;
			}
			check_data->deleg_point = NULL;
		}

		// in this case (authoritative or deleg-point), the node should
		// be a previous of some next node only if it has some data
		if (knot_node_rrset_count(node) > 0) {
			check_data->previous = node;
		}
	}
}

/*----------------------------------------------------------------------------*/

static void knot_zc_integrity_check_parent(const knot_node_t *node,
                                           check_data_t *check_data,
                                           char *name)
{
	if (check_data->parent == NULL) {
		// this is only possible for apex
		assert(node == knot_zone_contents_apex(check_data->contents));
		check_data->parent = node;
		return;
	}

	const knot_dname_t *node_owner = knot_node_owner(node);
	const knot_dname_t *parent_owner = knot_node_owner(check_data->parent);
	char *pname = knot_dname_to_str(parent_owner);

	// if direct child
	if (knot_dname_is_subdomain(node_owner, parent_owner)
	    && knot_dname_matched_labels(node_owner, parent_owner)
	       == knot_dname_label_count(parent_owner)) {

		// check the parent pointer
		const knot_node_t *parent = knot_node_parent(node);
		if (parent != check_data->parent) {
			char *name2 = (parent != NULL)
			                ? knot_dname_to_str(
			                        knot_node_owner(parent))
			                : "none";
			fprintf(stderr, "Wrong parent: node %s, parent %s. "
			        " Should be %s\n", name, name2, pname);
			if (parent != NULL) {
				free(name2);
			}

			++check_data->errors;
		} else {
			// if parent is OK, check if the node is not a
			// wildcard child of it; in such case it should be set
			// as the wildcard child of its parent
			if (knot_dname_is_wildcard(node_owner)
			    && knot_node_wildcard_child(check_data->parent)
			       != node) {
				char *wc = (knot_node_wildcard_child(
				                 check_data->parent) == NULL)
				   ? "none"
				   : knot_dname_to_str(knot_node_owner(
				           knot_node_wildcard_child(
				                   check_data->parent)));
				fprintf(stderr, "Wrong wildcard child: node %s,"
				        " wildcard child: %s. Should be %s\n",
				        pname, wc, name);
				if (knot_node_wildcard_child(
				       check_data->parent) != NULL) {
					free(wc);
				}

				++check_data->errors;
			}
		}
	}

	free(pname);
	check_data->parent = node;
}

/*----------------------------------------------------------------------------*/

static void knot_zc_integrity_check_rrset_count(const knot_node_t *node,
                                                check_data_t *check_data,
                                                const char *name)
{
	// count RRSets
	int real_count = knot_node_count_rrsets(node);
	int count = knot_node_rrset_count(node);

	if (count != real_count) {
		fprintf(stderr, "Wrong RRSet count: node %s, count %d. "
		        "Should be %d\n", name, count, real_count);

		++check_data->errors;
	}
}

/*----------------------------------------------------------------------------*/

typedef struct find_dname_data {
	const knot_dname_t *to_find;
	const knot_dname_t *found;
} find_dname_data_t;

/*----------------------------------------------------------------------------*/

void find_in_dname_table(knot_dname_t *dname, void *data)
{
	assert(dname != NULL);
	assert(data != NULL);

	find_dname_data_t *fdata = (find_dname_data_t *)data;

	if (fdata->found != NULL) {
		return;
	}

	if (knot_dname_compare(dname, fdata->to_find) == 0) {
		fdata->found = dname;
	}
}

/*----------------------------------------------------------------------------*/

static int knot_zc_integrity_check_find_dname(const knot_zone_contents_t *zone,
                                              const knot_dname_t *to_find,
                                              const char *node_name)
{
	int ret = 0;
	
	knot_dname_t *found = knot_dname_table_find_dname(zone->dname_table, 
	                                               (knot_dname_t *)to_find);

	char *to_find_name = knot_dname_to_str(to_find);

	if (!found || found != to_find) {
		fprintf(stderr, "Dname not stored in dname table: "
		        "node %s, name %s, found some dname: %s\n", node_name,
		       to_find_name, (found != NULL) ? "yes" : "no");
		fprintf(stderr, "Dname to find: %p, found dname: %p\n",
		        found, to_find);
		ret = 1;
	}

	free(to_find_name);

	knot_dname_release(found);

	return ret;
}

/*----------------------------------------------------------------------------*/

static void knot_zc_integrity_check_owner(const knot_node_t *node,
                                          check_data_t *check_data,
                                          const char *name)
{
	// check node stored in owner
	const knot_node_t *owner_node =
	                knot_dname_node(knot_node_owner(node));
	if (owner_node != node) {
		char *name2 = (owner_node != NULL)
		                ? knot_dname_to_str(knot_node_owner(owner_node))
		                : "none";
		fprintf(stderr, "Wrong owner's node: node %s, owner's node %s"
		        "\n", name, name2);
		if (owner_node != NULL) {
			free(name2);
		}

		++check_data->errors;
	}

	// check if the owner is stored in dname table
	check_data->errors += knot_zc_integrity_check_find_dname(
	                     check_data->contents, knot_node_owner(node), name);
}

/*----------------------------------------------------------------------------*/

static void knot_zc_integrity_check_dnames_in_rrset(const knot_rrset_t *rrset,
                                                    check_data_t *check_data,
                                                    const char *name)
{
	// check owner of the RRSet
	check_data->errors += knot_zc_integrity_check_find_dname(
	                        check_data->contents,
	                        knot_rrset_owner(rrset), name);

	knot_rrtype_descriptor_t *desc = knot_rrtype_descriptor_by_type(
	                        knot_rrset_type(rrset));

	assert(desc != NULL);

	const knot_rdata_t *rdata = knot_rrset_rdata(rrset);
	while (rdata != NULL) {
		for (int i = 0; i < knot_rdata_item_count(rdata); ++i) {
			if (desc->wireformat[i]
			     == KNOT_RDATA_WF_COMPRESSED_DNAME
			    || desc->wireformat[i]
			       == KNOT_RDATA_WF_UNCOMPRESSED_DNAME
			    || desc->wireformat[i]
			       == KNOT_RDATA_WF_LITERAL_DNAME) {
				knot_rdata_item_t *item = knot_rdata_get_item(
				                        rdata, i);
				check_data->errors +=
				    knot_zc_integrity_check_find_dname(
				       check_data->contents, item->dname, name);
			}
		}
		rdata = knot_rrset_rdata_next(rrset, rdata);
	}
}

/*----------------------------------------------------------------------------*/

static void knot_zc_integrity_check_dnames(const knot_node_t *node,
                                           check_data_t *check_data,
                                           const char *name)
{
	// check all dnames in all RRSets - both owners and in RDATA
	const knot_rrset_t **rrsets = knot_node_rrsets(node);
	if (rrsets != NULL) {
		for (int i = 0; i < knot_node_rrset_count(node); ++i) {
			knot_zc_integrity_check_dnames_in_rrset(rrsets[i],
			                                      check_data, name);
		}
	}
	free(rrsets);
}

/*----------------------------------------------------------------------------*/

static void knot_zc_integrity_check_node(knot_node_t *node, void *data)
{
	assert(node != NULL);
	assert(data != NULL);

	const knot_dname_t *node_owner = knot_node_owner(node);
	char *name = knot_dname_to_str(node_owner);

	check_data_t *check_data = (check_data_t *)data;

	// check previous-next chain
	knot_zc_integrity_check_previous(node, check_data, name);

	// check node flags
	knot_zc_integrity_check_flags(node, check_data, name);

	// check if the node is child of the saved parent & children count
	// & wildcard child
	knot_zc_integrity_check_parent(node, check_data, name);

	// check RRSet count
	knot_zc_integrity_check_rrset_count(node, check_data, name);

	// check owner
	knot_zc_integrity_check_owner(node, check_data, name);

	// check dnames
	knot_zc_integrity_check_dnames(node, check_data, name);

	/*! \todo Check NSEC3 node. */

	free(name);
}

/*----------------------------------------------------------------------------*/

static void knot_zc_integrity_check_nsec3(knot_node_t *node, void *data)
{
	assert(node != NULL);
	assert(data != NULL);

	const knot_dname_t *node_owner = knot_node_owner(node);
	char *name = knot_dname_to_str(node_owner);

	check_data_t *check_data = (check_data_t *)data;

	// check previous-next chain
	knot_zc_integrity_check_previous(node, check_data, name);
	// store the node as new previous
	check_data->previous = node;

	// check if the node is child of the zone apex
	if (node->parent != check_data->parent) {
		fprintf(stderr, "NSEC3 node's parent is not apex. Node: %s.\n",
		        name);
		++check_data->errors;
	}

	// check RRSet count
	knot_zc_integrity_check_rrset_count(node, check_data, name);

	// check owner
	knot_zc_integrity_check_owner(node, check_data, name);

	// check dnames
	knot_zc_integrity_check_dnames(node, check_data, name);

	free(name);
}

/*----------------------------------------------------------------------------*/

void reset_child_count(knot_zone_tree_node_t *tree_node, void *data)
{
	assert(tree_node != NULL);
	assert(data != NULL);

	knot_node_t **apex_copy = (knot_node_t **)data;
	if (*apex_copy == NULL) {
		*apex_copy = tree_node->node;
	}

	if (tree_node->node != NULL) {
		tree_node->node->children = 0;
	}
}

/*----------------------------------------------------------------------------*/

void count_children(knot_zone_tree_node_t *tree_node, void *data)
{
	UNUSED(data);
	if (tree_node->node != NULL && tree_node->node->parent != NULL) {
		assert(tree_node->node->parent->new_node != NULL);
		// fix parent pointer
		tree_node->node->parent = tree_node->node->parent->new_node;
		++tree_node->node->parent->children;
	}
}

/*----------------------------------------------------------------------------*/

void check_child_count(knot_zone_tree_node_t *tree_node, void *data)
{
	assert(tree_node != NULL);
	assert(data != NULL);

	check_data_t *check_data = (check_data_t *)data;
	knot_node_t *node = tree_node->node;

	// find corresponding node in the given contents
	const knot_node_t *found = NULL;
	found = knot_zone_contents_find_node(check_data->contents,
	                                     knot_node_owner(node));
	assert(found != NULL);

	if (knot_node_children(node) != knot_node_children(found)) {
		char *name = knot_dname_to_str(knot_node_owner(node));
		fprintf(stderr, "Wrong children count: node (%p) %s, count %u. "
		        "Should be %u (%p)\n", found, name,
		        knot_node_children(found),
		        knot_node_children(node), node);
		free(name);

		++check_data->errors;
	}
}

/*----------------------------------------------------------------------------*/

static void reset_new_nodes(knot_zone_tree_node_t *tree_node, void *data)
{
	assert(tree_node != NULL);
	UNUSED(data);

	knot_node_t *node = tree_node->node;
	knot_node_set_new_node(node, NULL);
}

/*----------------------------------------------------------------------------*/

static void count_nsec3_nodes(knot_zone_tree_node_t *tree_node, void *data)
{
	assert(tree_node != NULL);
	assert(tree_node->node != NULL);
	assert(data != NULL);

	knot_node_t *apex = (knot_node_t *)data;
	assert(apex != NULL);
	
	apex->children += 1;
}

/*----------------------------------------------------------------------------*/

int knot_zc_integrity_check_child_count(check_data_t *data)
{
	int errors = 0;

	// do shallow copy of the node tree
	knot_zone_tree_t *nodes_copy = (knot_zone_tree_t *)
	                malloc(sizeof(knot_zone_tree_t));
	if (nodes_copy == NULL) {
		return 1;
	}

	knot_zone_tree_init(nodes_copy);

	int ret = knot_zone_tree_deep_copy(data->contents->nodes, nodes_copy);
	assert(ret == KNOT_EOK);


	// set children count of all nodes to 0
	// in the same walkthrough find the apex
	knot_node_t *apex_copy = NULL;
	knot_zone_tree_forward_apply_inorder(nodes_copy, reset_child_count,
	                                     (void *)&apex_copy);
	assert(apex_copy != NULL);

	// now count children of all nodes, presuming the parent pointers are ok
	knot_zone_tree_forward_apply_inorder(nodes_copy, count_children, NULL);

	// add count of NSEC3 nodes to the apex' children count
	fprintf(stderr, "Children count of new apex before NSEC3: %d\n",
	        data->contents->apex->new_node->children);
	knot_zone_tree_forward_apply_inorder(data->contents->nsec3_nodes,
	                                     count_nsec3_nodes,
	                                     (void *)apex_copy);


	// now compare the children counts
	// iterate over the old zone and search for nodes in the copy
	knot_zone_tree_forward_apply_inorder(nodes_copy, check_child_count,
	                                     (void *)data);

	// cleanup old zone tree - reset pointers to new node to NULL
	knot_zone_tree_forward_apply_inorder(data->contents->nodes,
	                                     reset_new_nodes, NULL);

	// destroy the shallow copy
	knot_zone_tree_deep_free(&nodes_copy);

	return errors;
}

/*----------------------------------------------------------------------------*/

int knot_zone_contents_integrity_check(const knot_zone_contents_t *contents)
{
	/*
	 * 1) Check flags of nodes.
	 *    - Those containing NS RRSets should have the 'delegation point'
	 *      flag set.
	 *    - Their descendants should be marked as non-authoritative.
	 *    - Other nodes should be marked as authoritative.
	 *
	 * In the same walkthrough check:
	 * - if nodes are properly connected by 'previous' and 'next' pointers.
	 *   Only authoritative nodes and delegation points should be.
	 * - parents - each node (except for the apex) should have a parent set
	 *   and it should be a node with owner one label shorter.
	 * - RRSet counts.
	 * - etc...
	 */

	check_data_t data;
	data.errors = 0;
	data.previous = NULL;
	data.deleg_point = NULL;
	data.parent = NULL;
	data.children = 0;
	data.contents = contents;

	int ret = knot_zone_contents_tree_apply_inorder(
	                        (knot_zone_contents_t *)contents,
	                        knot_zc_integrity_check_node, (void *)&data);
	assert(ret == KNOT_EOK);

	// if OK, we can continue with checking children count
	// (we need the parent pointers to be set well)
	if (data.errors == 0) {
		data.contents = contents;
		knot_zc_integrity_check_child_count(&data);
	}

	data.previous = NULL;
	data.children = 0;
	data.parent = contents->apex;
	ret = knot_zone_contents_nsec3_apply_inorder(
	                        (knot_zone_contents_t *)contents,
	                        knot_zc_integrity_check_nsec3, (void *)&data);
	assert(ret == KNOT_EOK);

	return data.errors;
}

