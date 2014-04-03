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

#include "knot/zone/zone-contents.h"
#include "common/debug.h"
#include "libknot/rrset.h"
#include "common/base32hex.h"
#include "common/descriptor.h"
#include "common/hattrie/hat-trie.h"
#include "knot/dnssec/zone-nsec.h"
#include "knot/dnssec/zone-sign.h"
#include "knot/zone/zone-tree.h"
#include "libknot/packet/wire.h"
#include "libknot/consts.h"
#include "libknot/rdata.h"

/*----------------------------------------------------------------------------*/
/* Non-API functions                                                          */
/*----------------------------------------------------------------------------*/

typedef struct {
	knot_zone_contents_apply_cb_t func;
	void *data;
} knot_zone_tree_func_t;

typedef struct {
	knot_node_t *first_node;
	knot_zone_contents_t *zone;
	knot_node_t *previous_node;
} knot_zone_adjust_arg_t;

/*----------------------------------------------------------------------------*/

const uint8_t KNOT_ZONE_FLAGS_GEN_OLD  = 0;            /* xxxxxx00 */
const uint8_t KNOT_ZONE_FLAGS_GEN_NEW  = 1 << 0;       /* xxxxxx01 */
const uint8_t KNOT_ZONE_FLAGS_GEN_FIN  = 1 << 1;       /* xxxxxx10 */
const uint8_t KNOT_ZONE_FLAGS_GEN_MASK = 3;            /* 00000011 */

/*----------------------------------------------------------------------------*/

static int tree_apply_cb(knot_node_t **node, void *data)
{
	if (node == NULL || data == NULL) {
		return KNOT_EINVAL;
	}

	knot_zone_tree_func_t *f = (knot_zone_tree_func_t *)data;
	return f->func(*node, f->data);
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
 * \retval KNOT_EOUTOFZONE if the node does not belong to the zone.
 */
static int knot_zone_contents_check_node(
	const knot_zone_contents_t *contents, const knot_node_t *node)
{
	if (contents == NULL || node == NULL) {
		return KNOT_EINVAL;
	}

	// assert or just check??
	assert(contents->apex != NULL);

	if (!knot_dname_is_sub(node->owner,
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
		return KNOT_EOUTOFZONE;
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
static int knot_zone_contents_destroy_node_rrsets_from_tree(
	knot_node_t **tnode, void *data)
{
	UNUSED(data);
	assert(tnode != NULL);
	if (*tnode != NULL) {
		knot_node_free_rrsets(*tnode);
		knot_node_free(tnode);
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int knot_zone_contents_nsec3_name(const knot_zone_contents_t *zone,
                                         const knot_dname_t *name,
                                         knot_dname_t **nsec3_name)
{
	assert(nsec3_name != NULL);
	*nsec3_name = NULL;

	const knot_nsec3_params_t *nsec3_params =
		knot_zone_contents_nsec3params(zone);

	if (nsec3_params == NULL) {
		return KNOT_ENSEC3PAR;
	}

	*nsec3_name = knot_create_nsec3_owner(name, zone->apex->owner,
	                                      nsec3_params);
	if (*nsec3_name == NULL) {
		return KNOT_ERROR;
	}

	return KNOT_EOK;
}

/*! \brief Link pointers to additional nodes for this RRSet. */
static int discover_additionals(knot_rrset_t *rr, knot_zone_contents_t *zone)
{
	const knot_node_t *node = NULL, *encloser = NULL, *prev = NULL;
	const knot_dname_t *dname = NULL;

	/* Free old additional nodes. */
	if (rr->additional != NULL) {
		free(rr->additional);
	}

	/* Create new additional nodes. */
	uint16_t rdcount = knot_rrset_rr_count(rr);
	rr->additional = malloc(rdcount * sizeof(knot_node_t*));
	if (rr->additional == NULL) {
		return KNOT_ENOMEM;
	}

	for (uint16_t i = 0; i < rdcount; i++) {

		/* Try to find node for the dname in the RDATA. */
		dname = knot_rdata_name(rr, i);
		knot_zone_contents_find_dname(zone, dname, &node, &encloser, &prev);
		if (node == NULL && encloser
		    && knot_node_has_wildcard_child(encloser)) {
			/* Find wildcard child in the zone. */
			node = knot_zone_contents_find_wildcard_child(zone,
			                                              encloser);
			assert(node != NULL);
		}

		rr->additional[i] = (knot_node_t *)node;
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int adjust_pointers(knot_node_t **tnode, void *data)
{
	assert(data != NULL);
	assert(tnode != NULL);
	knot_zone_adjust_arg_t *args = (knot_zone_adjust_arg_t *)data;
	knot_node_t *node = *tnode;

	// remember first node

	if (args->first_node == NULL) {
		args->first_node = node;
	}

	// clear flags, so no relicts remain
	node->flags = 0;

	// check if this node is not a wildcard child of its parent

	if (knot_dname_is_wildcard(knot_node_owner(node))) {
		assert(knot_node_parent(node) != NULL);
		knot_node_set_wildcard_child(knot_node_get_parent(node));
	}

	// set flags (delegation point, non-authoritative)

	if (knot_node_parent(node)
	    && (knot_node_is_deleg_point(knot_node_parent(node))
		|| knot_node_is_non_auth(knot_node_parent(node)))
	) {
		knot_node_set_non_auth(node);
	} else if (knot_node_rrset(node, KNOT_RRTYPE_NS) != NULL
		   && node != args->zone->apex) {
		knot_node_set_deleg_point(node);
	} else {
		knot_node_set_auth(node);
	}

	// set pointer to previous node

	knot_node_set_previous(node, args->previous_node);

	// update remembered previous pointer only if authoritative

	if (!knot_node_is_non_auth(node) && knot_node_rrset_count(node) > 0) {
		args->previous_node = node;
	}

	return KNOT_EOK;
}

static int adjust_nsec3_pointers(knot_node_t **tnode, void *data)
{
	assert(data != NULL);
	assert(tnode != NULL);
	knot_zone_adjust_arg_t *args = (knot_zone_adjust_arg_t *)data;
	knot_node_t *node = *tnode;
	// Connect to NSEC3 node (only if NSEC3 tree is not empty)
	knot_node_t *nsec3 = NULL;
	knot_dname_t *nsec3_name = NULL;
	int ret = knot_zone_contents_nsec3_name(args->zone,
	                                        knot_node_owner(node),
	                                        &nsec3_name);
	if (ret == KNOT_EOK) {
		assert(nsec3_name);
		knot_zone_tree_get(args->zone->nsec3_nodes, nsec3_name, &nsec3);
		knot_node_set_nsec3_node(node, nsec3);
	} else if (ret == KNOT_ENSEC3PAR) {
		knot_node_set_nsec3_node(node, NULL);
		ret = KNOT_EOK;
	}

	knot_dname_free(&nsec3_name);
	return ret;
}

/*!
 * \brief Adjust normal (non NSEC3) node.
 *
 * Set:
 * - pointer to wildcard childs in parent nodes if applicable
 * - flags (delegation point, non-authoritative)
 * - pointer to previous node
 * - parent pointers
 *
 * \param tnode  Zone node to adjust.
 * \param data   Adjusting parameters (knot_zone_adjust_arg_t *).
 */
static int knot_zone_contents_adjust_normal_node(knot_node_t **tnode,
                                                 void *data)
{
	assert(data != NULL);
	assert(tnode != NULL && *tnode);
	// Do cheap operations first
	int ret = adjust_pointers(tnode, data);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Connect nodes to their NSEC3 nodes
	return adjust_nsec3_pointers(tnode, data);
}

/*----------------------------------------------------------------------------*/

/*!
 * \brief Adjust NSEC3 node.
 *
 * Set:
 * - pointer to previous node
 * - pointer to node stored in owner dname
 *
 * \param tnode  Zone node to adjust.
 * \param data   Adjusting parameters (knot_zone_adjust_arg_t *).
 */
static int knot_zone_contents_adjust_nsec3_node(knot_node_t **tnode,
                                                void *data)
{
	assert(data != NULL);
	assert(tnode != NULL);

	knot_zone_adjust_arg_t *args = (knot_zone_adjust_arg_t *)data;
	knot_node_t *node = *tnode;

	// remember first node

	if (args->first_node == NULL) {
		args->first_node = node;
	}

	// set previous node

	knot_node_set_previous(node, args->previous_node);
	args->previous_node = node;

	return KNOT_EOK;
}

/*! \brief Discover additional records for affected nodes. */
static int adjust_additional(knot_node_t **tnode, void *data)
{
	assert(data != NULL);
	assert(tnode != NULL);

	int ret = KNOT_EOK;
	knot_zone_adjust_arg_t *args = (knot_zone_adjust_arg_t *)data;
	knot_node_t *node = *tnode;
	knot_rrset_t **rrset = node->rrset_tree;

	/* Lookup additional records for specific nodes. */
	for(uint16_t i = 0; i < node->rrset_count; ++i) {
		if (rrset_additional_needed(rrset[i]->type)) {
			ret = discover_additionals(rrset[i], args->zone);
			if (ret != KNOT_EOK) {
				break;
			}
		}
	}

	return ret;
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
			knot_rdata_nsec3_algorithm(rrset, rdata_pos),
			knot_rdata_nsec3_iterations(rrset, rdata_pos),
			knot_rdata_nsec3_salt_length(rrset, rdata_pos),
			knot_rdata_nsec3_salt_length(rrset, rdata_pos),
			knot_rdata_nsec3_salt(rrset, rdata_pos));
	dbg_zone_detail("NSEC3PARAM algo: %u, iterations: %u, salt length: %u, "
			"salt: %.*s\n",  params->algorithm, params->iterations,
			params->salt_length, params->salt_length, params->salt);

	return (knot_rdata_nsec3_algorithm(rrset, rdata_pos) == params->algorithm
		&& knot_rdata_nsec3_iterations(rrset, rdata_pos) == params->iterations
		&& knot_rdata_nsec3_salt_length(rrset, rdata_pos) == params->salt_length
		&& strncmp((const char *)knot_rdata_nsec3_salt(rrset, rdata_pos),
			   (const char *)params->salt, params->salt_length)
		   == 0);
}

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

knot_zone_contents_t *knot_zone_contents_new(const knot_dname_t *apex_name)
{
	dbg_zone("%s(%p)\n", __func__, apex_name);
	if (apex_name == NULL) {
		return NULL;
	}

	knot_zone_contents_t *contents = malloc(sizeof(knot_zone_contents_t));
	if (contents == NULL) {
		return NULL;
	}

	memset(contents, 0, sizeof(knot_zone_contents_t));
	contents->node_count = 1;
	contents->apex = knot_node_new(apex_name, NULL, 0);
	if (contents->apex == NULL) {
		goto cleanup;
	}

	contents->nodes = knot_zone_tree_create();
	if (contents->nodes == NULL) {
		goto cleanup;
	}

	contents->nsec3_nodes = knot_zone_tree_create();
	if (contents->nsec3_nodes == NULL) {
		goto cleanup;
	}

	if (knot_zone_tree_insert(contents->nodes, contents->apex) != KNOT_EOK) {
		goto cleanup;
	}

	return contents;

cleanup:
	dbg_zone("%s: failure to initialize contents %p\n", __func__, contents);
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

	++zone->node_count;

	if (!create_parents) {
		return KNOT_EOK;
	}

	dbg_zone_detail("Creating parents of the node.\n");

	/* No parents for root domain. */
	if (*node->owner == '\0')
		return KNOT_EOK;

	knot_node_t *next_node = NULL;
	const uint8_t *parent = knot_wire_next_label(knot_node_owner(node), NULL);

	if (knot_dname_cmp(knot_node_owner(zone->apex), parent) == 0) {
		dbg_zone_detail("Zone apex is the parent.\n");
		knot_node_set_parent(node, zone->apex);

		// check if the node is not wildcard child of the parent
		if (knot_dname_is_wildcard(knot_node_owner(node))) {
			knot_node_set_wildcard_child(zone->apex);
		}
	} else {
		while (parent != NULL &&
		       !(next_node = knot_zone_contents_get_node(zone, parent))) {

			/* Create a new node. */
			dbg_zone_detail("Creating new node.\n");
			next_node = knot_node_new(parent, NULL, flags);
			if (next_node == NULL) {
				return KNOT_ENOMEM;
			}

			/* Insert node to a tree. */
			dbg_zone_detail("Inserting new node to zone tree.\n");
			assert(knot_zone_contents_find_node(zone, parent) == NULL);
			ret = knot_zone_tree_insert(zone->nodes, next_node);
			if (ret != KNOT_EOK) {
				knot_node_free(&next_node);
				return ret;
			}

			/* Update node pointers. */
			knot_node_set_parent(node, next_node);
			if (knot_dname_is_wildcard(knot_node_owner(node))) {
				knot_node_set_wildcard_child(next_node);
			}

			++zone->node_count;

			dbg_zone_detail("Next parent.\n");
			node = next_node;
			parent = knot_wire_next_label(parent, NULL);
		}

		// set the found parent (in the zone) as the parent of the last
		// inserted node
		assert(knot_node_parent(node) == NULL);
		knot_node_set_parent(node, next_node);

		dbg_zone_detail("Created all parents.\n");
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_zone_contents_create_node(knot_zone_contents_t *contents,
                                   const knot_rrset_t *rr,
                                   knot_node_t **node)
{
	if (contents == NULL || rr == NULL || node == NULL) {
		return KNOT_EINVAL;
	}

	*node = knot_node_new(rr->owner, NULL, 0);
	if (*node == NULL) {
		return KNOT_ENOMEM;
	}

	/* Add to the proper tree. */
	int ret = KNOT_EOK;
	if (knot_rrset_is_nsec3rel(rr)) {
		ret = knot_zone_contents_add_nsec3_node(contents, *node, 1, 0);
	} else {
		ret = knot_zone_contents_add_node(contents, *node, 1, 0);
	}

	if (ret != KNOT_EOK) {
		dbg_xfrin("Failed to add new node to zone contents.\n");
		knot_node_free(node);
		return ret;
	}

	return ret;
}

/*----------------------------------------------------------------------------*/

static int insert_rr(knot_zone_contents_t *z, knot_rrset_t *rr, knot_node_t **n,
                     knot_rrset_t **rrset, bool nsec3)
{
	if (z == NULL || rr == NULL || n == NULL || rrset == NULL) {
		return KNOT_EINVAL;
	}

	// check if the RRSet belongs to the zone
	if (!knot_dname_is_equal(rr->owner, z->apex->owner)
	    && !knot_dname_is_sub(rr->owner, z->apex->owner)) {
		return KNOT_EOUTOFZONE;
	}

	int ret = KNOT_EOK;
	if (*n == NULL) {
		*n = nsec3 ? knot_zone_contents_get_nsec3_node(z, rr->owner) :
		             knot_zone_contents_get_node(z, rr->owner);
		if (*n == NULL) {
			// Create new, insert
			*n = knot_node_new(rr->owner, NULL, 0);
			if (*n == NULL) {
				return KNOT_ENOMEM;
			}
			ret = nsec3 ? knot_zone_contents_add_nsec3_node(z, *n, true, 0) :
			              knot_zone_contents_add_node(z, *n, true, 0);
			if (ret != KNOT_EOK) {
				knot_node_free(n);
			}
		}
	}

	return knot_node_add_rrset(*n, rr, rrset);
}

static bool to_nsec3_tree(const knot_rrset_t *rr)
{
	return knot_rrset_is_nsec3rel(rr);
}

int knot_zone_contents_add_rr(knot_zone_contents_t *z,
                              knot_rrset_t *rr, knot_node_t **n,
                              knot_rrset_t **rrset)
{
	return insert_rr(z, rr, n, rrset, to_nsec3_tree(rr));
}

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
	if (!knot_dname_is_equal(rrset->owner, zone->apex->owner)
	    && !knot_dname_is_sub(rrset->owner, zone->apex->owner)) {
		return KNOT_EOUTOFZONE;
	}

	if ((*node) == NULL
	    && (*node = knot_zone_contents_get_node(zone,
	                                            rrset->owner)) == NULL) {
		return KNOT_ENONODE;
	}

	assert(*node != NULL);

	// add all domain names from the RRSet to domain name table
	int rc;

	/*! \todo REMOVE RRSET */
	if (dupl == KNOT_RRSET_DUPL_MERGE) {
		rc = knot_node_add_rrset(*node, rrset, NULL);
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

	// cannot be wildcard child, so nothing to be done

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_zone_contents_remove_node(knot_zone_contents_t *contents,
                                   const knot_dname_t *owner)
{
	if (contents == NULL || owner == NULL) {
		return KNOT_EINVAL;
	}

dbg_zone_exec_verb(
	char *name = knot_dname_to_str(owner);
	dbg_zone_verb("Removing zone node: %s\n", name);
	free(name);
);
	knot_node_t *removed_node = NULL;
	int ret = knot_zone_tree_remove(contents->nodes, owner, &removed_node);
	if (ret != KNOT_EOK) {
		return KNOT_ENONODE;
	}
	assert(removed_node);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_zone_contents_remove_nsec3_node(knot_zone_contents_t *contents,
	const knot_dname_t *owner)
{
	if (contents == NULL || owner == NULL) {
		return KNOT_EINVAL;
	}

	// remove the node from the zone tree
	knot_node_t *removed_node = NULL;
	int ret = knot_zone_tree_remove(contents->nsec3_nodes, owner,
	                                &removed_node);
	if (ret != KNOT_EOK) {
		return KNOT_ENONODE;
	}
	assert(removed_node);

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
		return KNOT_EOUTOFZONE;
	}

	/* This function was quite out of date. The find_in_tree() function
	 * may return NULL in the 'found' field, so we cannot search for the
	 * closest encloser from this node.
	 */

	if (exact_match) {
		*closest_encloser = *node;
	} else {
		if (!knot_dname_is_sub(name, zone->apex->owner)) {
			*node = NULL;
			*closest_encloser = NULL;
			return KNOT_EOUTOFZONE;
		}

		*closest_encloser = *previous;
		assert(*closest_encloser != NULL);

		int matched_labels = knot_dname_matched_labels(
				knot_node_owner((*closest_encloser)), name);
		while (matched_labels < knot_dname_labels(
				knot_node_owner((*closest_encloser)), NULL)) {
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
	       ? ZONE_NAME_FOUND
	       : ZONE_NAME_NOT_FOUND;
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
	return knot_zone_contents_get_previous_nsec3(zone, name);
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
		knot_dname_free(&nsec3_name);
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

	knot_dname_free(&nsec3_name);

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
		     i < knot_rrset_rr_count(nsec3_rrset) && !match;
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
	       ? ZONE_NAME_FOUND
	       : ZONE_NAME_NOT_FOUND;
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

const knot_node_t *knot_zone_contents_find_wildcard_child(
                const knot_zone_contents_t *contents, const knot_node_t *parent)
{
	if (contents == NULL || parent == NULL
	    || knot_node_owner(parent) == NULL) {
		return NULL;
	}

	knot_dname_t *wildcard_name = knot_dname_from_str("*");
	wildcard_name = knot_dname_cat(wildcard_name, knot_node_owner(parent));
	const knot_node_t *node = knot_zone_contents_find_node(contents,
	                                                       wildcard_name);
	knot_dname_free(&wildcard_name);
	return node;
}

/*----------------------------------------------------------------------------*/

static int knot_zone_contents_adjust_nodes(knot_zone_tree_t *nodes,
                                           knot_zone_adjust_arg_t *adjust_arg,
                                           knot_zone_tree_apply_cb_t callback)
{
	assert(nodes);
	assert(adjust_arg);
	assert(callback);

	adjust_arg->first_node = NULL;
	adjust_arg->previous_node = NULL;

	hattrie_build_index(nodes);
	int result = knot_zone_tree_apply_inorder(nodes, callback, adjust_arg);

	knot_node_set_previous(adjust_arg->first_node,
	                       adjust_arg->previous_node);

	return result;
}

/*----------------------------------------------------------------------------*/

static int knot_zone_contents_adjust_nsec3_tree(knot_zone_contents_t *contents)
{
	if (contents->nsec3_nodes == NULL) {
		return KNOT_EOK;
	}
	// adjusting parameters
	knot_zone_adjust_arg_t adjust_arg = { .first_node = NULL,
	                                      .previous_node = NULL,
	                                      .zone = contents };
	return knot_zone_contents_adjust_nodes(contents->nsec3_nodes,
	                                       &adjust_arg,
	                                       knot_zone_contents_adjust_nsec3_node);
}

/*----------------------------------------------------------------------------*/

int knot_zone_contents_adjust_pointers(knot_zone_contents_t *contents)
{
	int ret = knot_zone_contents_load_nsec3param(contents);
	if (ret != KNOT_EOK) {
		log_zone_error("Failed to load NSEC3 params: %s\n",
		               knot_strerror(ret));
		return ret;
	}

	knot_node_set_apex(contents->apex);

	// adjusting parameters
	knot_zone_adjust_arg_t adjust_arg = { .first_node = NULL,
	                                      .previous_node = NULL,
	                                      .zone = contents };
	ret =  knot_zone_contents_adjust_nodes(contents->nodes, &adjust_arg,
	                                       adjust_pointers);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = knot_zone_contents_adjust_nsec3_tree(contents);
	if (ret != KNOT_EOK) {
		return ret;
	}

	return knot_zone_contents_adjust_nodes(contents->nodes, &adjust_arg,
	                                       adjust_additional);
}

/*----------------------------------------------------------------------------*/

int knot_zone_contents_adjust_nsec3_pointers(knot_zone_contents_t *contents)
{
	if (contents->nsec3_nodes == NULL) {
		return KNOT_EOK;
	}
	// adjusting parameters
	knot_zone_adjust_arg_t adjust_arg = { .first_node = NULL,
	                                      .previous_node = NULL,
	                                      .zone = contents };
	return knot_zone_contents_adjust_nodes(contents->nodes, &adjust_arg,
	                                       adjust_nsec3_pointers);
}

/*----------------------------------------------------------------------------*/

int knot_zone_contents_adjust_full(knot_zone_contents_t *zone,
                                   knot_node_t **first_nsec3_node,
                                   knot_node_t **last_nsec3_node)
{
	if (zone == NULL) {
		return KNOT_EINVAL;
	}

	int result = knot_zone_contents_load_nsec3param(zone);
	if (result != KNOT_EOK) {
		log_zone_error("Failed to load NSEC3 params: %s\n",
		               knot_strerror(result));
		return result;
	}

	knot_node_set_apex(zone->apex);

	// adjusting parameters

	knot_zone_adjust_arg_t adjust_arg = { 0 };
	adjust_arg.zone = zone;

	// adjust NSEC3 nodes

	result = knot_zone_contents_adjust_nodes(zone->nsec3_nodes, &adjust_arg,
	                                 knot_zone_contents_adjust_nsec3_node);
	if (result != KNOT_EOK) {
		return result;
	}

	// optional output for NSEC3 nodes

	if (first_nsec3_node) {
		*first_nsec3_node = adjust_arg.first_node;
	}

	if (last_nsec3_node) {
		*last_nsec3_node = adjust_arg.previous_node;
	}

	// adjust normal nodes

	result = knot_zone_contents_adjust_nodes(zone->nodes, &adjust_arg,
	                                 knot_zone_contents_adjust_normal_node);
	if (result != KNOT_EOK) {
		return result;
	}

	assert(zone->apex == adjust_arg.first_node);

	/* Discover additional records.
	 * \note This MUST be done after node adjusting because it needs to
	 *       do full lookup to see through wildcards. */

	return knot_zone_contents_adjust_nodes(zone->nodes, &adjust_arg,
	                                       adjust_additional);
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

const knot_nsec3_params_t *knot_zone_contents_nsec3params(
	const knot_zone_contents_t *zone)
{
	if (zone == NULL) {
		return NULL;
	}

	if (knot_is_nsec3_enabled(zone)) {
		return &zone->nsec3_params;
	} else {
		return NULL;
	}
}

/*----------------------------------------------------------------------------*/

int knot_zone_contents_tree_apply_inorder(knot_zone_contents_t *zone,
                                        knot_zone_contents_apply_cb_t function,
                                        void *data)
{
	if (zone == NULL) {
		return KNOT_EINVAL;
	}

	knot_zone_tree_func_t f;
	f.func = function;
	f.data = data;

	return knot_zone_tree_apply_inorder(zone->nodes, tree_apply_cb, &f);
}

/*----------------------------------------------------------------------------*/

int knot_zone_contents_nsec3_apply_inorder(knot_zone_contents_t *zone,
                                        knot_zone_contents_apply_cb_t function,
                                        void *data)
{
	if (zone == NULL) {
		return KNOT_EINVAL;
	}

	knot_zone_tree_func_t f;
	f.func = function;
	f.data = data;

	return knot_zone_tree_apply_inorder(zone->nsec3_nodes,
	                                    tree_apply_cb, &f);
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

	//contents->apex = from->apex;

	contents->node_count = from->node_count;
	contents->flags = from->flags;
	// set the 'new' flag
	knot_zone_contents_set_gen_new(contents);

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
	dbg_zone("Destroying zone tree.\n");
	knot_zone_tree_free(&(*contents)->nodes);
	dbg_zone("Destroying NSEC3 zone tree.\n");
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
		// Delete NSEC3 tree
		knot_zone_tree_apply(
			(*contents)->nsec3_nodes,
			knot_zone_contents_destroy_node_rrsets_from_tree,
			(void*)1);

		// Delete normal tree
		knot_zone_tree_apply(
			(*contents)->nodes,
			knot_zone_contents_destroy_node_rrsets_from_tree,
			(void*)1);
	}

	knot_zone_contents_free(contents);
}

/*----------------------------------------------------------------------------*/

uint32_t knot_zone_serial(const knot_zone_contents_t *zone)
{
	if (!zone) return 0;
	const knot_rrset_t *soa = NULL;
	soa = knot_node_rrset(knot_zone_contents_apex(zone), KNOT_RRTYPE_SOA);
	return knot_rdata_soa_serial(soa);
}

bool knot_zone_contents_is_signed(const knot_zone_contents_t *zone)
{
	return knot_node_rrtype_is_signed(zone->apex, KNOT_RRTYPE_SOA);
}
