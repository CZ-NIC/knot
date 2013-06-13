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

#include <config.h>
#include <assert.h>

#include "zone/zone-contents.h"
#include "util/debug.h"
#include "libknot/rrset.h"
#include "common/base32hex.h"
#include "common/descriptor.h"
#include "common/hattrie/hat-trie.h"
#include "libknot/zone/zone-tree.h"
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
	hattrie_t *lookup_tree;
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

static void tree_apply_cb(knot_node_t **node,
                                   void *data)
{
	if (node == NULL || data == NULL) {
		return;
	}

	knot_zone_tree_func_t *f = (knot_zone_tree_func_t *)data;
	f->func(*node, f->data);
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
	knot_node_t **tnode, void *data)
{
	assert(tnode != NULL);
	if (*tnode == NULL) return; /* non-existent node */

	int free_rdata_dnames = (int)((intptr_t)data);
	knot_node_free_rrsets(*tnode, free_rdata_dnames);
	knot_node_free(tnode);
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

void knot_zone_contents_insert_dname_into_table(knot_dname_t **in_dname,
                                                hattrie_t *lookup_tree)
{
	if (lookup_tree == NULL) {
		/* = Do not check duplicates. */
		return;
	}
	assert(in_dname && *in_dname);
	/* First thing - make sure dname is not duplicated. */
	knot_dname_t *found_dname = hattrie_get_dname(lookup_tree, *in_dname);
	if (found_dname != NULL && found_dname != *in_dname) {
		/* Duplicate. */
		knot_dname_release(*in_dname);
		knot_dname_retain(found_dname);
		*in_dname = found_dname;
	} else if (found_dname == NULL) {
		/* Into the tree it goes. */
		hattrie_insert_dname(lookup_tree, *in_dname);
	} else {
		assert(found_dname == *in_dname);
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
static void knot_zone_contents_adjust_rdata_dname(knot_zone_contents_t *zone,
                                                  hattrie_t *lookup_tree,
                                                  knot_node_t *node,
                                                  knot_dname_t **in_dname)
{
//	const knot_node_t *old_dname_node = (*in_dname)->node;
	knot_zone_contents_insert_dname_into_table(in_dname, lookup_tree);
//	assert((*in_dname)->node == old_dname_node || old_dname_node == NULL);

	knot_dname_t *dname = *in_dname;
	/*
	 * The case when dname.node is already set is handled here.
	 * No use to check it later.
	 */
	if (knot_dname_node(dname) != NULL
	    || !knot_dname_is_subdomain(dname, knot_node_owner(
				      knot_zone_contents_apex(zone)))) {
		// The name's node is either already set
		// or the name does not belong to the zone
		dbg_zone_detail("Name's node either set or the name "
				"does not belong to the zone (%p).\n",
				knot_dname_node(dname));
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
                                                     hattrie_t *lookup_tree,
                                                     knot_zone_contents_t *zone,
                                                     knot_node_t *node)
{
	knot_dname_t **dn = NULL;
	while((dn = knot_rrset_get_next_dname(rrset, dn))) {
		knot_zone_contents_adjust_rdata_dname(zone,
						      lookup_tree,
						      node,
						      dn);
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
static int knot_zone_contents_adjust_rrsets(knot_node_t *node,
                                             hattrie_t *lookup_tree,
                                             knot_zone_contents_t *zone)
{
	knot_rrset_t **rrsets = knot_node_get_rrsets_no_copy(node);
	short count = knot_node_rrset_count(node);

	assert(count == 0 || rrsets != NULL);

	for (int r = 0; r < count; ++r) {
		assert(rrsets[r] != NULL);

		/* Make sure that RRSet owner is the same as node's. */
		if (node->owner != rrsets[r]->owner) {
			knot_rrset_set_owner(rrsets[r], node->owner);
		}

		dbg_zone("Adjusting next RRSet.\n");
		knot_rrset_dump(rrsets[r]);
		knot_zone_contents_adjust_rdata_in_rrset(rrsets[r],
							 lookup_tree, zone,
							 node);
		knot_rrset_t *rrsigs = rrsets[r]->rrsigs;
		if (rrsigs != NULL) {
			dbg_zone("Adjusting next RRSIGs.\n");
			knot_rrset_dump(rrsigs);
			knot_zone_contents_adjust_rdata_in_rrset(rrsigs,
							 lookup_tree, zone,
								 node);
		}

		if (rrsets[r]->type == KNOT_RRTYPE_DS) {
			int ret = knot_rrset_ds_check(rrsets[r]);
			if (ret != KNOT_EOK) {
				dbg_zone("DS RDATA check failed: %s\n", knot_strerror(ret));
				return KNOT_EMALF;
			}
		}
	}

	return KNOT_EOK;
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
static int knot_zone_contents_adjust_node(knot_node_t *node,
                                          hattrie_t *lookup_tree,
                                          knot_zone_contents_t *zone)
{
	// adjust domain names in RDATA
	int ret = knot_zone_contents_adjust_rrsets(node, lookup_tree,
						   zone);
	if (ret != KNOT_EOK) {
		return ret;
	}

//	const knot_node_t *old_dname_node = node->owner->node;
	knot_zone_contents_insert_dname_into_table(&node->owner, lookup_tree);
//	assert(node->owner->node == old_dname_node || old_dname_node == NULL);

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
	/*! \todo We need only exact matches, what if node has no nsec3 node? */
	/* This is faster, as it doesn't need ordered access. */
	knot_node_t *nsec3 = NULL;
	knot_dname_t *nsec3_name = NULL;
	ret = knot_zone_contents_nsec3_name(zone, knot_node_owner(node),
					    &nsec3_name);
	if (ret == KNOT_EOK) {
		assert(nsec3_name);
		knot_zone_tree_get(zone->nsec3_nodes, nsec3_name, &nsec3);
		knot_node_set_nsec3_node(node, nsec3);
	} else if (ret == KNOT_ENSEC3PAR) {
		knot_node_set_nsec3_node(node, NULL);
	} else {
		/* Something could be in DNAME. */
		knot_dname_free(&nsec3_name);
		return ret;
	}
	knot_dname_free(&nsec3_name);

	dbg_zone_detail("Set flags to the node: \n");
	dbg_zone_detail("Delegation point: %s\n",
			knot_node_is_deleg_point(node) ? "yes" : "no");
	dbg_zone_detail("Non-authoritative: %s\n",
			knot_node_is_non_auth(node) ? "yes" : "no");
	return KNOT_EOK;
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
		knot_node_t **tnode, void *data)
{
	assert(data != NULL);
	assert(tnode != NULL);

	knot_zone_adjust_arg_t *args = (knot_zone_adjust_arg_t *)data;
	knot_node_t *node = *tnode;

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
	 *    Do other adjusting (flags, closest enclosers, wildcard children,
	 *    etc.).
	 */
	args->err = knot_zone_contents_adjust_node(node, args->lookup_tree, zone);
}

/*----------------------------------------------------------------------------*/

static void knot_zone_contents_adjust_node_in_tree_ptr(
		knot_node_t **tnode, void *data)
{
	assert(data != NULL);
	assert(tnode != NULL);

	knot_zone_adjust_arg_t *args = (knot_zone_adjust_arg_t *)data;
	knot_node_t *node = *tnode;

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
		knot_node_t **tnode, void *data)
{
	assert(data != NULL);
	assert(tnode != NULL);
	knot_node_t *node = *tnode;

	knot_zone_adjust_arg_t *args = (knot_zone_adjust_arg_t *)data;

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
	 * We assume, that NSEC3 nodes have none DNAMEs in their RDATA and
	 * that node owners are all unique. \todo Harmful?
	 */

	knot_zone_contents_t *zone = args->zone;
	assert(zone != NULL);
}

/*----------------------------------------------------------------------------*/

static void knot_zone_contents_adjust_nsec3_node_in_tree_ptr(
		knot_node_t **tnode, void *data)
{
	assert(data != NULL);
	assert(tnode != NULL);

	knot_zone_adjust_arg_t *args = (knot_zone_adjust_arg_t *)data;
	knot_node_t *node = *tnode;

	// set previous node
	knot_node_set_previous(node, args->previous_node);

	// here is nothing to consider, all nodes are the same
	args->previous_node = node;

	if (args->first_node == NULL) {
		args->first_node = node;
	}
}

/*----------------------------------------------------------------------------*/

int knot_zone_contents_nsec3_name(const knot_zone_contents_t *zone,
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

	uint8_t *name_b32 = NULL;
	size_t size = base32hex_encode_alloc(hashed_name, hash_size,
					     &name_b32);

	if (size == 0) {
		char *n = knot_dname_to_str(name);
		dbg_zone("Error while encoding hashed name %s to base32.\n", n);
		free(n);
		free(name_b32);
		return KNOT_ECRYPTO;
	}

	assert(name_b32 != NULL);
	free(hashed_name);

dbg_zone_exec_verb(
	/* name_b32 is not 0-terminated. */
	char b32_string[hash_size + 1];
	memset(b32_string, 0, hash_size + 1);
	memcpy(b32_string, name_b32, hash_size);
	dbg_zone_verb("Base32-encoded hash: %s\n", b32_string);
);

	/* Will be returned to caller, make sure it is released after use. */
	*nsec3_name = knot_dname_new_from_str((char *)name_b32, size, NULL);

	free(name_b32);

	if (*nsec3_name == NULL) {
		dbg_zone("Error while creating domain name for hashed name.\n");
		return KNOT_ERROR;
	}
	knot_dname_to_lower(*nsec3_name);

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

static int knot_zc_nsec3_parameters_match(const knot_rrset_t *rrset,
                                          const knot_nsec3_params_t *params,
                                          size_t rdata_pos)
{
	assert(rrset != NULL && params != NULL);

	dbg_zone_detail("RDATA algo: %u, iterations: %u, salt length: %u, salt:"
			" %.*s\n",
			knot_rrset_rdata_nsec3_algorithm(rrset, rdata_pos),
			knot_rrset_rdata_nsec3_iterations(rrset, rdata_pos),
			knot_rrset_rdata_nsec3_salt_length(rrset, rdata_pos),
			knot_rrset_rdata_nsec3_salt_length(rrset, rdata_pos),
			knot_rrset_rdata_nsec3_salt(rrset, rdata_pos));
	dbg_zone_detail("NSEC3PARAM algo: %u, iterations: %u, salt length: %u, "
			"salt: %.*s\n",  params->algorithm, params->iterations,
			params->salt_length, params->salt_length, params->salt);

	return (knot_rrset_rdata_nsec3_algorithm(rrset, rdata_pos) == params->algorithm
		&& knot_rrset_rdata_nsec3_iterations(rrset, rdata_pos) == params->iterations
		&& knot_rrset_rdata_nsec3_salt_length(rrset, rdata_pos) == params->salt_length
		&& strncmp((const char *)knot_rrset_rdata_nsec3_salt(rrset, rdata_pos),
			   (const char *)params->salt, params->salt_length)
		   == 0);
}

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

knot_zone_contents_t *knot_zone_contents_new(knot_node_t *apex,
                                             struct knot_zone *zone)
{
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
	contents->nodes = knot_zone_tree_create();
	if (contents->nodes == NULL) {
		ERR_ALLOC_FAILED;
		goto cleanup;
	}

	dbg_zone_verb("Creating tree for NSEC3 nodes.\n");
	contents->nsec3_nodes = knot_zone_tree_create();
	if (contents->nsec3_nodes == NULL) {
		ERR_ALLOC_FAILED;
		goto cleanup;
	}

	/* Initialize NSEC3 params */
	dbg_zone_verb("Initializing NSEC3 parameters.\n");
	contents->nsec3_params.algorithm = 0;
	contents->nsec3_params.flags = 0;
	contents->nsec3_params.iterations = 0;
	contents->nsec3_params.salt_length = 0;
	contents->nsec3_params.salt = NULL;

	dbg_zone_verb("Inserting apex into the zone tree.\n");
	if (knot_zone_tree_insert(contents->nodes, apex) != KNOT_EOK) {
		dbg_zone("Failed to insert apex to the zone tree.\n");
		goto cleanup;
	}

	return contents;

cleanup:
	dbg_zone_verb("Cleaning up.\n");
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
                                  uint8_t flags)
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
			//TODO possible leak
//			ret = knot_zone_contents_solve_node_dnames(zone,
//								   next_node);
//			if (ret != KNOT_EOK) {
//				knot_node_free(&next_node);
//				knot_dname_release(chopped);
//			}

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
                                 knot_rrset_dupl_handling_t dupl)
{
	if (zone == NULL || rrset == NULL || zone->apex == NULL
	    || zone->apex->owner == NULL || node == NULL) {
		return KNOT_EINVAL;
	}

dbg_zone_exec_detail(
	char *name = knot_dname_to_str(knot_rrset_owner(rrset));
	dbg_zone_detail("Adding RRSet to zone contents: %s, type %d\n",
			name, knot_rrset_type(rrset));
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
		rc = knot_node_add_rrset(*node, rrset);
	} else {
		rc = knot_node_add_rrset_no_merge(*node, rrset);
	}

	if (rc < 0) {
		dbg_zone("Failed to add RRSet to node.\n");
		return rc;
	}

	int ret = rc;

	dbg_zone_detail("RRSet OK (%d).\n", ret);
	return ret;
}

/*----------------------------------------------------------------------------*/

int knot_zone_contents_add_rrsigs(knot_zone_contents_t *zone,
                                  knot_rrset_t *rrsigs,
                                  knot_rrset_t **rrset,
                                  knot_node_t **node,
                                  knot_rrset_dupl_handling_t dupl)
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
		    = (knot_rrset_rdata_rrsig_type_covered(rrsigs) == KNOT_RRTYPE_NSEC3)
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
		dbg_zone_detail("Finding RRSet for type %d\n",
				knot_rrset_rdata_rrsig_type_covered(rrsigs));
		*rrset = knot_node_get_rrset(
			     *node, knot_rrset_rdata_rrsig_type_covered(rrsigs));
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

	dbg_zone_detail("RRSIGs OK\n");
	return ret;
}

/*----------------------------------------------------------------------------*/

int knot_zone_contents_add_nsec3_node(knot_zone_contents_t *zone,
                                        knot_node_t *node, int create_parents,
                                        uint8_t flags)
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
	ret = knot_zone_tree_insert(zone->nsec3_nodes, node);
	if (ret != KNOT_EOK) {
		dbg_zone("Failed to insert node into NSEC3 tree: %s.\n",
			 knot_strerror(ret));
		return ret;
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
                                         knot_rrset_dupl_handling_t dupl)
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
	int rc;

	/*! \todo REMOVE RRSET */
	if (dupl == KNOT_RRSET_DUPL_MERGE) {
		rc = knot_node_add_rrset(*node, rrset);
	} else {
		rc = knot_node_add_rrset_no_merge(*node, rrset);
	}

	if (rc < 0) {
		return rc;
	}

	int ret = rc;

	dbg_zone_detail("NSEC3 OK\n");
	return ret;
}

/*----------------------------------------------------------------------------*/

int knot_zone_contents_remove_node(knot_zone_contents_t *contents,
	const knot_node_t *node, knot_node_t **removed_tree)
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
	const knot_node_t *node, knot_node_t **removed)
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
	if (knot_zone_tree_weight(zone->nsec3_nodes) == 0) {
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
	assert(nsec3_rrset);
	const knot_node_t *original_prev = *nsec3_previous;

	int match = 0;

	while (nsec3_rrset && !match) {
		for (uint16_t i = 0;
		     i < knot_rrset_rdata_rr_count(nsec3_rrset) && !match;
		     i++) {
			if (knot_zc_nsec3_parameters_match(nsec3_rrset,
							    &zone->nsec3_params,
							    i)) {
				/* Matching NSEC3PARAM match at position nr.: i. */
				match = 1;
			}
		}

		if (match) {
			break;
		}

		/* This RRSET was not a match, try the one from previous node. */
		*nsec3_previous = knot_node_previous(*nsec3_previous);
		nsec3_rrset = knot_node_rrset(*nsec3_previous,
					      KNOT_RRTYPE_NSEC3);
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
		if (*nsec3_previous == original_prev || nsec3_rrset == NULL) {
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

int knot_zone_contents_adjust(knot_zone_contents_t *zone,
                              knot_node_t **first_nsec3_node,
                              knot_node_t **last_nsec3_node, int dupl_check)
{
	if (zone == NULL) {
		return KNOT_EINVAL;
	}

	/* Heal zone indexes. */
	hattrie_build_index(zone->nodes);
	hattrie_build_index(zone->nsec3_nodes);

	// load NSEC3PARAM (needed on adjusting function)
	knot_zone_contents_load_nsec3param(zone);

	hattrie_t *lookup_tree = NULL;
	if (dupl_check) {
		lookup_tree = hattrie_create();
		if (lookup_tree == NULL) {
			dbg_zone("Failed to create out of zone lookup structure.\n");
			return KNOT_ERROR;
		}
	}

	knot_zone_adjust_arg_t adjust_arg;
	adjust_arg.zone = zone;
	adjust_arg.first_node = NULL;
	adjust_arg.previous_node = NULL;
	adjust_arg.lookup_tree = lookup_tree;
	adjust_arg.err = KNOT_EOK;

	/*
	 * First of all we must set node.prev pointers, as these are used in
	 * the search functions.
	 */
	dbg_zone("Setting 'prev' pointers to NSEC3 nodes.\n");
	int ret = knot_zone_tree_apply_inorder(zone->nsec3_nodes,
		 knot_zone_contents_adjust_nsec3_node_in_tree_ptr, &adjust_arg);
	assert(ret == KNOT_EOK);

	if (adjust_arg.err != KNOT_EOK) {
		dbg_zone("Failed to set 'prev' pointers to NSEC3 nodes: %s\n",
			 knot_strerror(adjust_arg.err));
		hattrie_free(lookup_tree);
		return adjust_arg.err;
	}

	// set the last node as previous of the first node
	if (adjust_arg.first_node) {
		knot_node_set_previous(adjust_arg.first_node,
				       adjust_arg.previous_node);
	}
	if (first_nsec3_node) {
		*first_nsec3_node = adjust_arg.first_node;
	}
	if (last_nsec3_node) {
		*last_nsec3_node = adjust_arg.previous_node;
	}
	dbg_zone("Done.\n");

	adjust_arg.first_node = NULL;
	adjust_arg.previous_node = NULL;

	dbg_zone("Setting 'prev' pointers to normal nodes.\n");
	ret = knot_zone_tree_apply_inorder(zone->nodes,
		 knot_zone_contents_adjust_node_in_tree_ptr, &adjust_arg);
	assert(ret == KNOT_EOK);

	if (adjust_arg.err != KNOT_EOK) {
		dbg_zone("Failed to set 'prev' pointers to normal nodes: %s\n",
			 knot_strerror(adjust_arg.err));
		hattrie_free(lookup_tree);
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
	ret = knot_zone_tree_apply_inorder(zone->nsec3_nodes,
		     knot_zone_contents_adjust_nsec3_node_in_tree, &adjust_arg);
	assert(ret == KNOT_EOK);

	if (adjust_arg.err != KNOT_EOK) {
		dbg_zone("Failed to adjust NSEC3 nodes: %s\n",
			 knot_strerror(adjust_arg.err));
		hattrie_free(lookup_tree);
		return adjust_arg.err;
	}

	dbg_zone("Adjusting normal nodes.\n");
	ret = knot_zone_tree_apply_inorder(zone->nodes,
				knot_zone_contents_adjust_node_in_tree,
				&adjust_arg);
	assert(ret == KNOT_EOK);

	if (adjust_arg.err != KNOT_EOK) {
		dbg_zone("Failed to adjust normal nodes: %s\n",
			 knot_strerror(adjust_arg.err));
		hattrie_free(lookup_tree);
		return adjust_arg.err;
	}

	dbg_zone("Done.\n");

	hattrie_free(lookup_tree);

	return ret;
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
		if (r != KNOT_EOK) {
			dbg_zone("Failed to load NSEC3PARAM (%s).\n",
			         knot_strerror(r));
			return r;
		}
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
		&& knot_zone_tree_weight(zone->nsec3_nodes) != 0);
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

	return knot_zone_tree_apply_inorder(zone->nodes,
						    tree_apply_cb, &f);
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

	return knot_zone_tree_apply_recursive(zone->nodes,
						  tree_apply_cb, &f);
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

	return knot_zone_tree_apply_inorder(
			zone->nsec3_nodes, tree_apply_cb, &f);
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

	return knot_zone_tree_apply_recursive(
			zone->nsec3_nodes, tree_apply_cb, &f);
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

	contents->node_count = from->node_count;
	contents->flags = from->flags;

	contents->zone = from->zone;

	/* Initialize NSEC3 params */
	memcpy(&contents->nsec3_params, &from->nsec3_params,
	       sizeof(knot_nsec3_params_t));

	if ((ret = knot_zone_tree_shallow_copy(from->nodes,
					 &contents->nodes)) != KNOT_EOK
	    || (ret = knot_zone_tree_shallow_copy(from->nsec3_nodes,
					&contents->nsec3_nodes)) != KNOT_EOK) {
		goto cleanup;
	}

	dbg_zone("knot_zone_contents_shallow_copy: finished OK\n");

	*to = contents;
	return KNOT_EOK;

cleanup:
	knot_zone_tree_free(&contents->nodes);
	knot_zone_tree_free(&contents->nsec3_nodes);
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

	contents->node_count = from->node_count;
	contents->flags = from->flags;
	// set the 'new' flag
	knot_zone_contents_set_gen_new(contents);

	contents->zone = from->zone;

	if ((ret = knot_zone_tree_deep_copy(from->nodes,
					    &contents->nodes)) != KNOT_EOK
	    || (ret = knot_zone_tree_deep_copy(from->nsec3_nodes,
					  &contents->nsec3_nodes)) != KNOT_EOK) {
		goto cleanup;
	}

	contents->apex = knot_node_get_new_node(from->apex);

	dbg_zone("knot_zone_contents_shallow_copy: finished OK\n");

	*to = contents;
	return KNOT_EOK;

cleanup:
	knot_zone_tree_free(&contents->nodes);
	knot_zone_tree_free(&contents->nsec3_nodes);
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

	knot_nsec3_params_free(&(*contents)->nsec3_params);

	free(*contents);
	*contents = NULL;
}

/*----------------------------------------------------------------------------*/

void knot_zone_contents_deep_free(knot_zone_contents_t **contents)
{
	if (contents == NULL || *contents == NULL) {
		return;
	}

	if ((*contents) != NULL) {
		/* has to go through zone twice, rdata may contain references to
		   node owners earlier in the zone which may be already freed */
		/* NSEC3 tree is deleted first as it may contain references to
		   the normal tree. */

		knot_zone_tree_apply_recursive(
			(*contents)->nsec3_nodes,
			knot_zone_contents_destroy_node_rrsets_from_tree,
			(void*)1);

		knot_zone_tree_apply_recursive(
			(*contents)->nodes,
			knot_zone_contents_destroy_node_rrsets_from_tree,
			(void*)1);

		// free the zone tree, but only the structure
		// (nodes are already destroyed)
		dbg_zone("Destroying zone tree.\n");
		knot_zone_tree_free(&(*contents)->nodes);
		dbg_zone("Destroying NSEC3 zone tree.\n");
		knot_zone_tree_free(&(*contents)->nsec3_nodes);

		knot_nsec3_params_free(&(*contents)->nsec3_params);
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
				   ? strdup("none")
				   : knot_dname_to_str(knot_node_owner(
					   knot_node_wildcard_child(
						   check_data->parent)));
				fprintf(stderr, "Wrong wildcard child: node %s,"
					" wildcard child: %s. Should be %s\n",
					pname, wc, name);
				if (knot_node_wildcard_child(
				       check_data->parent) != NULL) {
				}
				free(wc);

				++check_data->errors;
			}
		}
	}

	free(pname);
	check_data->parent = node;
}

/*----------------------------------------------------------------------------*/

typedef struct find_dname_data {
	const knot_dname_t *to_find;
	const knot_dname_t *found;
} find_dname_data_t;

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

	// check owner
	knot_zc_integrity_check_owner(node, check_data, name);

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

	// check owner
	knot_zc_integrity_check_owner(node, check_data, name);

	free(name);
}

/*----------------------------------------------------------------------------*/

void reset_child_count(knot_node_t **tnode, void *data)
{
	assert(tnode != NULL);
	assert(data != NULL);

	knot_node_t *node = *tnode;
	knot_node_t **apex_copy = (knot_node_t **)data;
	if (*apex_copy == NULL) {
		*apex_copy = node;
	}

	if (tnode != NULL) {
		node->children = 0;
	}
}

/*----------------------------------------------------------------------------*/

void count_children(knot_node_t **tnode, void *data)
{
	UNUSED(data);
	knot_node_t *node = *tnode;
	if (node != NULL && node->parent != NULL) {
		assert(node->parent->new_node != NULL);
		// fix parent pointer
		node->parent = node->parent->new_node;
		++node->parent->children;
	}
}

/*----------------------------------------------------------------------------*/

void check_child_count(knot_node_t **tnode, void *data)
{
	assert(tnode != NULL);
	assert(data != NULL);

	check_data_t *check_data = (check_data_t *)data;
	knot_node_t *node = *tnode;

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

static void reset_new_nodes(knot_node_t **tnode, void *data)
{
	assert(tnode != NULL);
	UNUSED(data);

	knot_node_t *node = *tnode;
	knot_node_set_new_node(node, NULL);
}

/*----------------------------------------------------------------------------*/

static void count_nsec3_nodes(knot_node_t **tnode, void *data)
{
	assert(tnode != NULL);
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
	knot_zone_tree_t *nodes_copy = NULL;

	int ret = knot_zone_tree_deep_copy(data->contents->nodes, &nodes_copy);
	assert(ret == KNOT_EOK);
	if (nodes_copy == NULL) {
		return 1;
	}

	// set children count of all nodes to 0
	// in the same walkthrough find the apex
	knot_node_t *apex_copy = NULL;
	knot_zone_tree_apply_inorder(nodes_copy, reset_child_count,
					     (void *)&apex_copy);
	assert(apex_copy != NULL);

	// now count children of all nodes, presuming the parent pointers are ok
	knot_zone_tree_apply_inorder(nodes_copy, count_children, NULL);

	// add count of NSEC3 nodes to the apex' children count
	fprintf(stderr, "Children count of new apex before NSEC3: %d\n",
		data->contents->apex->new_node->children);
	knot_zone_tree_apply_inorder(data->contents->nsec3_nodes,
					     count_nsec3_nodes,
					     (void *)apex_copy);


	// now compare the children counts
	// iterate over the old zone and search for nodes in the copy
	knot_zone_tree_apply_inorder(nodes_copy, check_child_count,
					     (void *)data);

	// cleanup old zone tree - reset pointers to new node to NULL
	knot_zone_tree_apply_inorder(data->contents->nodes,
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

struct dname_lookup_data {
	const knot_dname_t *dname;
	const knot_dname_t *found_dname;
	int stopped;
};

static void find_dname_in_rdata(knot_node_t **tnode, void *data)
{
	struct dname_lookup_data *in_data = (struct dname_lookup_data *)data;
	if (in_data->stopped) {
		return;
	}

	/* For all RRSets in node. */
	const knot_rrset_t **rrsets = knot_node_rrsets_no_copy(*tnode);
	if (rrsets == NULL) {
		return;
	}

	for (uint16_t i = 0; i < (*tnode)->rrset_count; i++) {
		knot_dname_t **dname = NULL;
		while ((dname = knot_rrset_get_next_dname(rrsets[i], dname))) {
			if (*dname == in_data->dname) {
				in_data->found_dname = *dname;
				in_data->stopped = 1;
				return;
			} else if (knot_dname_compare(*dname,
						      in_data->dname) == 0) {
				in_data->found_dname = *dname;
				in_data->stopped = 1;
				return;
			}
		}
	}

	assert(in_data->stopped == 0);
}

const knot_dname_t *knot_zone_contents_find_dname_in_rdata(
	const knot_zone_contents_t *zone,
	const knot_dname_t *dname)
{
	struct dname_lookup_data data;
	data.stopped = 0;
	data.dname = dname;
	data.found_dname = NULL;
	knot_zone_tree_apply_inorder(zone->nodes,
					     find_dname_in_rdata, &data);
	if (data.stopped) {
		/* Dname found. */
		return data.found_dname;
	} else {
		assert(data.found_dname == NULL);
		return NULL;
	}
}

unsigned knot_zone_serial(const knot_zone_contents_t *zone)
{
	if (!zone) return 0;
	const knot_rrset_t *soa = NULL;
	soa = knot_node_rrset(knot_zone_contents_apex(zone), KNOT_RRTYPE_SOA);
	return knot_rrset_rdata_soa_serial(soa);
}
