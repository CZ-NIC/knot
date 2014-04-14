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

#include "libknot/zone/zone-contents.h"
#include "libknot/util/debug.h"
#include "libknot/rrset.h"
#include "common/base32hex.h"
#include "common/descriptor.h"
#include "common/hattrie/hat-trie.h"
#include "libknot/dnssec/zone-nsec.h"
#include "libknot/zone/zone-tree.h"
#include "libknot/util/wire.h"
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
const uint8_t KNOT_ZONE_FLAGS_ANY_MASK = 4;            /* 00000100 */
const uint8_t KNOT_ZONE_FLAGS_ANY      = 4;            /* 00000100 */

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

	*nsec3_name = create_nsec3_owner(name, zone->apex->owner, nsec3_params);
	if (*nsec3_name == NULL) {
		return KNOT_ERROR;
	}

	return KNOT_EOK;
}


/*----------------------------------------------------------------------------*/

/*!
 * \brief Adjust normal (non NSEC3) node.
 *
 * Set:
 * - reusable DNAMEs in RDATA
 * - pointer to node stored in owner dname
 * - pointer to wildcard childs in parent nodes if applicable
 * - flags (delegation point, non-authoritative)
 * - pointer to previous node
 *
 * \param tnode  Zone node to adjust.
 * \param data   Adjusting parameters (knot_zone_adjust_arg_t *).
 */
static int knot_zone_contents_adjust_normal_node(knot_node_t **tnode,
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

	// check if this node is not a wildcard child of its parent

	if (knot_dname_is_wildcard(knot_node_owner(node))) {
		assert(knot_node_parent(node) != NULL);
		knot_node_set_wildcard_child(knot_node_get_parent(node), node);
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
		&& memcmp(knot_rdata_nsec3_salt(rrset, rdata_pos), params->salt,
		          params->salt_length) == 0);
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
	if (contents == NULL) {
		return;
	}

	contents->flags |= KNOT_ZONE_FLAGS_ANY;
}

/*----------------------------------------------------------------------------*/

void knot_zone_contents_enable_any(knot_zone_contents_t *contents)
{
	if (contents == NULL) {
		return;
	}

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
			knot_node_set_wildcard_child(zone->apex, node);
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
				knot_node_set_wildcard_child(next_node, node);
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
	    && knot_dname_cmp(knot_rrset_owner(*rrset),
				    zone->apex->owner) != 0
	    && !knot_dname_is_sub(knot_rrset_owner(*rrset),
					  zone->apex->owner)) {
		return KNOT_EOUTOFZONE;
	}

	// check if the RRSIGs belong to the RRSet
	if (*rrset != NULL
	    && (knot_dname_cmp(knot_rrset_owner(rrsigs),
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
		    = (knot_rdata_rrsig_type_covered(rrsigs, 0)
		       == KNOT_RRTYPE_NSEC3)
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
				knot_rdata_rrsig_type_covered(rrsigs, 0));
		*rrset = knot_node_get_rrset(
			     *node, knot_rdata_rrsig_type_covered(rrsigs, 0));
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
	if (knot_dname_cmp(knot_rrset_owner(rrset),
				 zone->apex->owner) != 0
	    && !knot_dname_is_sub(knot_rrset_owner(rrset),
					  zone->apex->owner)) {
		return KNOT_EOUTOFZONE;
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

	if (knot_dname_cmp(name, zone->apex->owner) == 0) {
		*node = zone->apex;
		*closest_encloser = *node;
		return KNOT_ZONE_NAME_FOUND;
	}

	if (!knot_dname_is_sub(name, zone->apex->owner)) {
		*node = NULL;
		*closest_encloser = NULL;
		return KNOT_EOUTOFZONE;
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
		return KNOT_EOUTOFZONE;
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

int knot_zone_contents_adjust(knot_zone_contents_t *zone,
                              knot_node_t **first_nsec3_node,
                              knot_node_t **last_nsec3_node, int dupl_check)
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
	knot_node_set_apex(zone->apex);

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

	if (rrset != NULL && rrset->rdata_count > 0) {
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
	    && knot_dname_is_sub(knot_node_owner(node),
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
	if (knot_dname_is_sub(node_owner, parent_owner)
	    && knot_dname_matched_labels(node_owner, parent_owner)
	       == knot_dname_labels(parent_owner, NULL)) {

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

static int knot_zc_integrity_check_node(knot_node_t *node, void *data)
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

	/*! \todo Check NSEC3 node. */

	free(name);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int knot_zc_integrity_check_nsec3(knot_node_t *node, void *data)
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

	free(name);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int reset_child_count(knot_node_t **tnode, void *data)
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

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int count_children(knot_node_t **tnode, void *data)
{
	UNUSED(data);

	knot_node_t *node = *tnode;
	if (node != NULL && node->parent != NULL) {
		assert(node->parent->new_node != NULL);
		// fix parent pointer
		node->parent = node->parent->new_node;
		++node->parent->children;
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int check_child_count(knot_node_t **tnode, void *data)
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

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int reset_new_nodes(knot_node_t **tnode, void *data)
{
	assert(tnode != NULL);
	UNUSED(data);

	knot_node_t *node = *tnode;
	knot_node_set_new_node(node, NULL);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int count_nsec3_nodes(knot_node_t **tnode, void *data)
{
	assert(tnode != NULL);
	assert(data != NULL);

	knot_node_t *apex = (knot_node_t *)data;
	assert(apex != NULL);

	apex->children += 1;

	return KNOT_EOK;
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
	} else {
		hattrie_build_index(nodes_copy);
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

	if (contents == NULL) {
		log_zone_warning("Zone to be integrity-checked does "
		                 "not exist. Skipping...\n");
		return 1;
	}

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

uint32_t knot_zone_serial(const knot_zone_contents_t *zone)
{
	if (!zone) return 0;
	const knot_rrset_t *soa = NULL;
	soa = knot_node_rrset(knot_zone_contents_apex(zone), KNOT_RRTYPE_SOA);
	return knot_rdata_soa_serial(soa);
}

bool knot_zone_contents_is_signed(const knot_zone_contents_t *zone)
{
	const knot_rrset_t *soa = NULL;
	if (zone->apex) {
		/* Returns true if SOA has a RRSIG (basic check). */
		soa = knot_node_rrset(zone->apex, KNOT_RRTYPE_SOA);
		return soa && soa->rrsigs;
	}
	return false;
}
