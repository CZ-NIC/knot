/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "libdnssec/error.h"
#include "knot/zone/contents.h"
#include "knot/common/log.h"
#include "knot/dnssec/zone-nsec.h"
#include "libknot/libknot.h"
#include "contrib/qp-trie/trie.h"
#include "contrib/macros.h"

typedef struct {
	zone_contents_apply_cb_t func;
	void *data;
} zone_tree_func_t;

typedef struct {
	zone_node_t *first_node;
	zone_contents_t *zone;
	zone_node_t *previous_node;
} zone_adjust_arg_t;

static int tree_apply_cb(zone_node_t **node, void *data)
{
	if (node == NULL || data == NULL) {
		return KNOT_EINVAL;
	}

	zone_tree_func_t *f = (zone_tree_func_t *)data;
	return f->func(*node, f->data);
}

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
static int check_node(const zone_contents_t *contents, const zone_node_t *node)
{
	assert(contents);
	assert(contents->apex != NULL);
	assert(node);

	if (knot_dname_in_bailiwick(node->owner, contents->apex->owner) <= 0) {
		return KNOT_EOUTOFZONE;
	}

	return KNOT_EOK;
}

/*!
 * \brief Destroys all RRSets in a node.
 *
 * This function is designed to be used in the tree-iterating functions.
 *
 * \param node Node to destroy RRSets from.
 * \param data Unused parameter.
 */
static int destroy_node_rrsets_from_tree(zone_node_t **node, void *data)
{
	assert(node);
	UNUSED(data);

	if (*node != NULL) {
		node_free_rrsets(*node, NULL);
		node_free(*node, NULL);
	}

	return KNOT_EOK;
}

static int create_nsec3_name(uint8_t *out, size_t out_size,
                             const zone_contents_t *zone,
                             const knot_dname_t *name)
{
	assert(out);
	assert(zone);
	assert(name);

	if (!knot_is_nsec3_enabled(zone)) {
		return KNOT_ENSEC3PAR;
	}

	return knot_create_nsec3_owner(out, out_size, name, zone->apex->owner,
	                               &zone->nsec3_params);
}

/*! \brief Link pointers to additional nodes for this RRSet. */
static int discover_additionals(const knot_dname_t *owner, struct rr_data *rr_data,
                                zone_contents_t *zone)
{
	assert(rr_data != NULL);

	/* Drop possible previous additional nodes. */
	additional_clear(rr_data->additional);
	rr_data->additional = NULL;

	const knot_rdataset_t *rrs = &rr_data->rrs;
	uint16_t rdcount = rrs->count;

	uint16_t mandatory_count = 0;
	uint16_t others_count = 0;
	glue_t mandatory[rdcount];
	glue_t others[rdcount];

	/* Scan new additional nodes. */
	for (uint16_t i = 0; i < rdcount; i++) {
		knot_rdata_t *rdata = knot_rdataset_at(rrs, i);
		const knot_dname_t *dname = knot_rdata_name(rdata, rr_data->type);
		const zone_node_t *node = NULL, *encloser = NULL, *prev = NULL;

		/* Try to find node for the dname in the RDATA. */
		zone_contents_find_dname(zone, dname, &node, &encloser, &prev);
		if (node == NULL && encloser != NULL
		    && (encloser->flags & NODE_FLAGS_WILDCARD_CHILD)) {
			/* Find wildcard child in the zone. */
			node = zone_contents_find_wildcard_child(zone, encloser);
			assert(node != NULL);
		}

		if (node == NULL) {
			continue;
		}

		glue_t *glue;
		if ((node->flags & (NODE_FLAGS_DELEG | NODE_FLAGS_NONAUTH)) &&
		    rr_data->type == KNOT_RRTYPE_NS &&
		    knot_dname_in_bailiwick(node->owner, owner) >= 0) {
			glue = &mandatory[mandatory_count++];
			glue->optional = false;
		} else {
			glue = &others[others_count++];
			glue->optional = true;
		}
		glue->node = node;
		glue->ns_pos = i;
	}

	/* Store sorted additionals by the type, mandatory first. */
	size_t total_count = mandatory_count + others_count;
	if (total_count > 0) {
		rr_data->additional = malloc(sizeof(additional_t));
		if (rr_data->additional == NULL) {
			return KNOT_ENOMEM;
		}
		rr_data->additional->count = total_count;

		size_t size = total_count * sizeof(glue_t);
		rr_data->additional->glues = malloc(size);
		if (rr_data->additional->glues == NULL) {
			free(rr_data->additional);
			return KNOT_ENOMEM;
		}

		size_t mandatory_size = mandatory_count * sizeof(glue_t);
		memcpy(rr_data->additional->glues, mandatory, mandatory_size);
		memcpy(rr_data->additional->glues + mandatory_count, others,
		       size - mandatory_size);
	}

	return KNOT_EOK;
}

static int adjust_pointers(zone_node_t **tnode, void *data)
{
	assert(tnode != NULL);
	assert(data != NULL);

	zone_adjust_arg_t *args = (zone_adjust_arg_t *)data;
	zone_node_t *node = *tnode;

	// remember first node
	if (args->first_node == NULL) {
		args->first_node = node;
	}

	// clear Removed NSEC flag so that no relicts remain
	node->flags &= ~NODE_FLAGS_REMOVED_NSEC;

	// check if this node is not a wildcard child of its parent
	if (knot_dname_is_wildcard(node->owner)) {
		assert(node->parent != NULL);
		node->parent->flags |= NODE_FLAGS_WILDCARD_CHILD;
	}

	// set flags (delegation point, non-authoritative)
	if (node->parent &&
	    (node->parent->flags & NODE_FLAGS_DELEG ||
	     node->parent->flags & NODE_FLAGS_NONAUTH)) {
		node->flags |= NODE_FLAGS_NONAUTH;
	} else if (node_rrtype_exists(node, KNOT_RRTYPE_NS) && node != args->zone->apex) {
		node->flags |= NODE_FLAGS_DELEG;
	} else {
		// Default.
		node->flags = NODE_FLAGS_AUTH;
	}

	// set pointer to previous node
	node->prev = args->previous_node;

	// update remembered previous pointer only if authoritative
	if (!(node->flags & NODE_FLAGS_NONAUTH) && node->rrset_count > 0) {
		args->previous_node = node;
	}

	return KNOT_EOK;
}

static int adjust_nsec3_pointers(zone_node_t **tnode, void *data)
{
	assert(data != NULL);
	assert(tnode != NULL);

	zone_adjust_arg_t *args = (zone_adjust_arg_t *)data;
	zone_node_t *node = *tnode;
	const zone_node_t *ignored;

	// Connect to NSEC3 node (only if NSEC3 tree is not empty)
	node->nsec3_wildcard_prev = NULL;
	uint8_t nsec3_name[KNOT_DNAME_MAXLEN];
	int ret = create_nsec3_name(nsec3_name, sizeof(nsec3_name), args->zone,
	                            node->owner);
	if (ret == KNOT_EOK) {
		node->nsec3_node = zone_tree_get(args->zone->nsec3_nodes, nsec3_name);

		// Connect to NSEC3 node proving nonexistence of wildcard.
		size_t wildcard_size = knot_dname_size(node->owner) + 2;
		if (wildcard_size <= KNOT_DNAME_MAXLEN) {
			assert(wildcard_size > 2);
			knot_dname_t wildcard[wildcard_size];
			memcpy(wildcard, "\x01""*", 2);
			memcpy(wildcard + 2, node->owner, wildcard_size - 2);
			ret = zone_contents_find_nsec3_for_name(args->zone, wildcard, &ignored,
			                                        (const zone_node_t **)&node->nsec3_wildcard_prev);
			if (ret == ZONE_NAME_FOUND) {
				node->nsec3_wildcard_prev = NULL;
				ret = KNOT_EOK;
			}
		}
	} else if (ret == KNOT_ENSEC3PAR) {
		node->nsec3_node = NULL;
		ret = KNOT_EOK;
	}

	return ret;
}

static int measure_size(zone_node_t *node, void *data){

	size_t *size = data;
	int rrset_count = node->rrset_count;
	for (int i = 0; i < rrset_count; i++) {
		knot_rrset_t rrset = node_rrset_at(node, i);
		*size += knot_rrset_size(&rrset);
	}
	return KNOT_EOK;
}

static bool nsec3_params_match(const knot_rdataset_t *rrs,
                               const dnssec_nsec3_params_t *params,
                               size_t rdata_pos)
{
	assert(rrs != NULL);
	assert(params != NULL);

	knot_rdata_t *rdata = knot_rdataset_at(rrs, rdata_pos);

	return (knot_nsec3_alg(rdata) == params->algorithm
	        && knot_nsec3_iters(rdata) == params->iterations
	        && knot_nsec3_salt_len(rdata) == params->salt.size
	        && memcmp(knot_nsec3_salt(rdata), params->salt.data,
	                  params->salt.size) == 0);
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
 * \param data   Adjusting parameters (zone_adjust_arg_t *).
 */
static int adjust_normal_node(zone_node_t **tnode, void *data)
{
	assert(tnode != NULL && *tnode);
	assert(data != NULL);

	// Do cheap operations first
	int ret = adjust_pointers(tnode, data);
	if (ret != KNOT_EOK) {
		return ret;
	}

	measure_size(*tnode, &((zone_adjust_arg_t *)data)->zone->size);

	// Connect nodes to their NSEC3 nodes
	return adjust_nsec3_pointers(tnode, data);
}

/*!
 * \brief Adjust NSEC3 node.
 *
 * Set:
 * - pointer to previous node
 * - pointer to node stored in owner dname
 *
 * \param tnode  Zone node to adjust.
 * \param data   Adjusting parameters (zone_adjust_arg_t *).
 */
static int adjust_nsec3_node(zone_node_t **tnode, void *data)
{
	assert(data != NULL);
	assert(tnode != NULL);

	zone_adjust_arg_t *args = (zone_adjust_arg_t *)data;
	zone_node_t *node = *tnode;

	// remember first node
	if (args->first_node == NULL) {
		args->first_node = node;
	}

	// set previous node
	node->prev = args->previous_node;
	args->previous_node = node;

	measure_size(*tnode, &args->zone->size);

	// check if this node belongs to correct chain
	const knot_rdataset_t *nsec3_rrs = node_rdataset(node, KNOT_RRTYPE_NSEC3);
	for (uint16_t i = 0; nsec3_rrs != NULL && i < nsec3_rrs->count; i++) {
		if (nsec3_params_match(nsec3_rrs, &args->zone->nsec3_params, i)) {
			node->flags |= NODE_FLAGS_IN_NSEC3_CHAIN;
		}
	}

	return KNOT_EOK;
}

/*! \brief Discover additional records for affected nodes. */
static int adjust_additional(zone_node_t **tnode, void *data)
{
	assert(data != NULL);
	assert(tnode != NULL);

	zone_adjust_arg_t *args = (zone_adjust_arg_t *)data;
	zone_node_t *node = *tnode;

	/* Lookup additional records for specific nodes. */
	for(uint16_t i = 0; i < node->rrset_count; ++i) {
		struct rr_data *rr_data = &node->rrs[i];
		if (knot_rrtype_additional_needed(rr_data->type)) {
			int ret = discover_additionals(node->owner, rr_data, args->zone);
			if (ret != KNOT_EOK) {
				return ret;
			}
		}
	}

	return KNOT_EOK;
}

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
 * \retval true if the domain name was found. In such case \a node holds the
 *              zone node with \a name as its owner. \a previous is set
 *              properly.
 * \retval false if the domain name was not found. \a node may hold any (or none)
 *               node. \a previous is set properly.
 */
static bool find_in_tree(zone_tree_t *tree, const knot_dname_t *name,
                         zone_node_t **node, zone_node_t **previous)
{
	assert(tree != NULL);
	assert(name != NULL);
	assert(node != NULL);
	assert(previous != NULL);

	zone_node_t *found = NULL, *prev = NULL;

	int match = zone_tree_get_less_or_equal(tree, name, &found, &prev);
	if (match < 0) {
		assert(0);
		return false;
	}

	*node = found;
	*previous = prev;

	return match > 0;
}

zone_contents_t *zone_contents_new(const knot_dname_t *apex_name)
{
	if (apex_name == NULL) {
		return NULL;
	}

	zone_contents_t *contents = malloc(sizeof(zone_contents_t));
	if (contents == NULL) {
		return NULL;
	}

	memset(contents, 0, sizeof(zone_contents_t));
	contents->apex = node_new(apex_name, NULL);
	if (contents->apex == NULL) {
		goto cleanup;
	}

	contents->nodes = zone_tree_create();
	if (contents->nodes == NULL) {
		goto cleanup;
	}

	if (zone_tree_insert(contents->nodes, contents->apex) != KNOT_EOK) {
		goto cleanup;
	}

	return contents;

cleanup:
	free(contents->nodes);
	free(contents->nsec3_nodes);
	free(contents);
	return NULL;
}

static zone_node_t *get_node(const zone_contents_t *zone, const knot_dname_t *name)
{
	assert(zone);
	assert(name);

	return zone_tree_get(zone->nodes, name);
}

static int add_node(zone_contents_t *zone, zone_node_t *node, bool create_parents)
{
	if (zone == NULL || node == NULL) {
		return KNOT_EINVAL;
	}

	int ret = check_node(zone, node);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = zone_tree_insert(zone->nodes, node);
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (!create_parents) {
		return KNOT_EOK;
	}

	/* No parents for root domain. */
	if (*node->owner == '\0') {
		return KNOT_EOK;
	}

	zone_node_t *next_node = NULL;
	const uint8_t *parent = knot_wire_next_label(node->owner, NULL);

	if (knot_dname_is_equal(zone->apex->owner, parent)) {
		node_set_parent(node, zone->apex);

		// check if the node is not wildcard child of the parent
		if (knot_dname_is_wildcard(node->owner)) {
			zone->apex->flags |= NODE_FLAGS_WILDCARD_CHILD;
		}
	} else {
		while (parent != NULL && !(next_node = get_node(zone, parent))) {

			/* Create a new node. */
			next_node = node_new(parent, NULL);
			if (next_node == NULL) {
				return KNOT_ENOMEM;
			}

			/* Insert node to a tree. */
			ret = zone_tree_insert(zone->nodes, next_node);
			if (ret != KNOT_EOK) {
				node_free(next_node, NULL);
				return ret;
			}

			/* Update node pointers. */
			node_set_parent(node, next_node);
			if (knot_dname_is_wildcard(node->owner)) {
				next_node->flags |= NODE_FLAGS_WILDCARD_CHILD;
			}

			node = next_node;
			parent = knot_wire_next_label(parent, NULL);
		}

		// set the found parent (in the zone) as the parent of the last
		// inserted node
		assert(node->parent == NULL);
		node_set_parent(node, next_node);
	}

	return KNOT_EOK;
}

static int add_nsec3_node(zone_contents_t *zone, zone_node_t *node)
{
	if (zone == NULL || node == NULL) {
		return KNOT_EINVAL;
	}

	int ret = check_node(zone, node);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Create NSEC3 tree if not exists. */
	if (zone->nsec3_nodes == NULL) {
		zone->nsec3_nodes = zone_tree_create();
		if (zone->nsec3_nodes == NULL) {
			return KNOT_ENOMEM;
		}
	}

	// how to know if this is successful??
	ret = zone_tree_insert(zone->nsec3_nodes, node);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// no parents to be created, the only parent is the zone apex
	// set the apex as the parent of the node
	node_set_parent(node, zone->apex);

	// cannot be wildcard child, so nothing to be done

	return KNOT_EOK;
}

static zone_node_t *get_nsec3_node(const zone_contents_t *zone,
                                   const knot_dname_t *name)
{
	assert(zone);
	assert(name);

	return zone_tree_get(zone->nsec3_nodes, name);
}

static int insert_rr(zone_contents_t *z, const knot_rrset_t *rr,
                     zone_node_t **n, bool nsec3)
{
	if (knot_rrset_empty(rr)) {
		return KNOT_EINVAL;
	}

	// check if the RRSet belongs to the zone
	if (knot_dname_in_bailiwick(rr->owner, z->apex->owner) < 0) {
		return KNOT_EOUTOFZONE;
	}

	if (*n == NULL) {
		*n = nsec3 ? get_nsec3_node(z, rr->owner) : get_node(z, rr->owner);
		if (*n == NULL) {
			// Create new, insert
			*n = node_new(rr->owner, NULL);
			if (*n == NULL) {
				return KNOT_ENOMEM;
			}
			int ret = nsec3 ? add_nsec3_node(z, *n) : add_node(z, *n, true);
			if (ret != KNOT_EOK) {
				node_free(*n, NULL);
				*n = NULL;
			}
		}
	}

	return node_add_rrset(*n, rr, NULL);
}

static int remove_rr(zone_contents_t *z, const knot_rrset_t *rr,
                     zone_node_t **n, bool nsec3)
{
	if (knot_rrset_empty(rr)) {
		return KNOT_EINVAL;
	}

	// check if the RRSet belongs to the zone
	if (knot_dname_in_bailiwick(rr->owner, z->apex->owner) < 0) {
		return KNOT_EOUTOFZONE;
	}

	zone_node_t *node;
	if (*n == NULL) {
		node = nsec3 ? get_nsec3_node(z, rr->owner) : get_node(z, rr->owner);
		if (node == NULL) {
			return KNOT_ENONODE;
		}
	} else {
		node = *n;
	}

	knot_rdataset_t *node_rrs = node_rdataset(node, rr->type);
	// Subtract changeset RRS from node RRS.
	int ret = knot_rdataset_subtract(node_rrs, &rr->rrs, NULL);
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (node_rrs->count == 0) {
		// RRSet is empty now, remove it from node, all data freed.
		node_remove_rdataset(node, rr->type);
		// If node is empty now, delete it from zone tree.
		if (node->rrset_count == 0 && node != z->apex) {
			zone_tree_delete_empty(nsec3 ? z->nsec3_nodes : z->nodes, node);
		}
	}

	*n = node;
	return KNOT_EOK;
}

static int recreate_normal_tree(const zone_contents_t *z, zone_contents_t *out)
{
	out->nodes = trie_create(NULL);
	if (out->nodes == NULL) {
		return KNOT_ENOMEM;
	}

	// Insert APEX first.
	zone_node_t *apex_cpy = node_shallow_copy(z->apex, NULL);
	if (apex_cpy == NULL) {
		return KNOT_ENOMEM;
	}

	// Normal additions need apex ... so we need to insert directly.
	int ret = zone_tree_insert(out->nodes, apex_cpy);
	if (ret != KNOT_EOK) {
		node_free(apex_cpy, NULL);
		return ret;
	}

	out->apex = apex_cpy;

	trie_it_t *itt = trie_it_begin(z->nodes);
	if (itt == NULL) {
		return KNOT_ENOMEM;
	}

	while (!trie_it_finished(itt)) {
		const zone_node_t *to_cpy = (zone_node_t *)*trie_it_val(itt);
		if (to_cpy == z->apex) {
			// Inserted already.
			trie_it_next(itt);
			continue;
		}
		zone_node_t *to_add = node_shallow_copy(to_cpy, NULL);
		if (to_add == NULL) {
			trie_it_free(itt);
			return KNOT_ENOMEM;
		}

		int ret = add_node(out, to_add, true);
		if (ret != KNOT_EOK) {
			node_free(to_add, NULL);
			trie_it_free(itt);
			return ret;
		}
		trie_it_next(itt);
	}

	trie_it_free(itt);

	return KNOT_EOK;
}

static int recreate_nsec3_tree(const zone_contents_t *z, zone_contents_t *out)
{
	out->nsec3_nodes = trie_create(NULL);
	if (out->nsec3_nodes == NULL) {
		return KNOT_ENOMEM;
	}

	trie_it_t *itt = trie_it_begin(z->nsec3_nodes);
	if (itt == NULL) {
		return KNOT_ENOMEM;
	}
	while (!trie_it_finished(itt)) {
		const zone_node_t *to_cpy = (zone_node_t *)*trie_it_val(itt);
		zone_node_t *to_add = node_shallow_copy(to_cpy, NULL);
		if (to_add == NULL) {
			trie_it_free(itt);
			return KNOT_ENOMEM;
		}

		int ret = add_nsec3_node(out, to_add);
		if (ret != KNOT_EOK) {
			trie_it_free(itt);
			node_free(to_add, NULL);
			return ret;
		}

		trie_it_next(itt);
	}

	trie_it_free(itt);

	return KNOT_EOK;
}

// Public API

int zone_contents_add_rr(zone_contents_t *z, const knot_rrset_t *rr,
                         zone_node_t **n)
{
	if (z == NULL || rr == NULL || n == NULL) {
		return KNOT_EINVAL;
	}

	return insert_rr(z, rr, n, knot_rrset_is_nsec3rel(rr));
}

int zone_contents_remove_rr(zone_contents_t *z, const knot_rrset_t *rr,
                            zone_node_t **n)
{
	if (z == NULL || rr == NULL || n == NULL) {
		return KNOT_EINVAL;
	}

	return remove_rr(z, rr, n, knot_rrset_is_nsec3rel(rr));
}

zone_node_t *zone_contents_get_node_for_rr(zone_contents_t *zone, const knot_rrset_t *rrset)
{
	if (zone == NULL || rrset == NULL) {
		return NULL;
	}

	const bool nsec3 = knot_rrset_is_nsec3rel(rrset);
	zone_node_t *node = nsec3 ? get_nsec3_node(zone, rrset->owner) :
	                            get_node(zone, rrset->owner);
	if (node == NULL) {
		node = node_new(rrset->owner, NULL);
		int ret = nsec3 ? add_nsec3_node(zone, node) : add_node(zone, node, true);
		if (ret != KNOT_EOK) {
			node_free(node, NULL);
			return NULL;
		}

		return node;
	} else {
		return node;
	}
}

const zone_node_t *zone_contents_find_node(const zone_contents_t *zone, const knot_dname_t *name)
{
	if (zone == NULL || name == NULL) {
		return NULL;
	}

	return get_node(zone, name);
}

zone_node_t *zone_contents_find_node_for_rr(zone_contents_t *contents, const knot_rrset_t *rrset)
{
	if (contents == NULL || rrset == NULL) {
		return NULL;
	}

	const bool nsec3 = knot_rrset_is_nsec3rel(rrset);
	return nsec3 ? get_nsec3_node(contents, rrset->owner) :
	               get_node(contents, rrset->owner);
}

int zone_contents_find_dname(const zone_contents_t *zone,
                             const knot_dname_t *name,
                             const zone_node_t **match,
                             const zone_node_t **closest,
                             const zone_node_t **previous)
{
	if (!zone || !name || !match || !closest || !previous) {
		return KNOT_EINVAL;
	}

	if (knot_dname_in_bailiwick(name, zone->apex->owner) < 0) {
		return KNOT_EOUTOFZONE;
	}

	zone_node_t *node = NULL;
	zone_node_t *prev = NULL;

	int found = zone_tree_get_less_or_equal(zone->nodes, name, &node, &prev);
	if (found < 0) {
		// error
		return found;
	} else if (found == 1) {
		// exact match

		assert(node && prev);

		*match = node;
		*closest = node;
		*previous = prev;

		return ZONE_NAME_FOUND;
	} else {
		// closest match

		assert(!node && prev);

		node = prev;
		size_t matched_labels = knot_dname_matched_labels(node->owner, name);
		while (matched_labels < knot_dname_labels(node->owner, NULL)) {
			node = node->parent;
			assert(node);
		}

		*match = NULL;
		*closest = node;
		*previous = prev;

		return ZONE_NAME_NOT_FOUND;
	}
}

const zone_node_t *zone_contents_find_nsec3_node(const zone_contents_t *zone,
                                                 const knot_dname_t *name)
{
	if (zone == NULL || name == NULL) {
		return NULL;
	}

	return get_nsec3_node(zone, name);
}

int zone_contents_find_nsec3_for_name(const zone_contents_t *zone,
                                      const knot_dname_t *name,
                                      const zone_node_t **nsec3_node,
                                      const zone_node_t **nsec3_previous)
{
	if (zone == NULL || name == NULL || nsec3_node == NULL ||
	    nsec3_previous == NULL) {
		return KNOT_EINVAL;
	}

	// check if the NSEC3 tree is not empty
	if (zone_tree_is_empty(zone->nsec3_nodes)) {
		return KNOT_ENSEC3CHAIN;
	}

	uint8_t nsec3_name[KNOT_DNAME_MAXLEN];
	int ret = create_nsec3_name(nsec3_name, sizeof(nsec3_name), zone, name);
	if (ret != KNOT_EOK) {
		return ret;
	}

	zone_node_t *found = NULL, *prev = NULL;
	bool match = find_in_tree(zone->nsec3_nodes, nsec3_name, &found, &prev);

	*nsec3_node = found;

	if (prev == NULL) {
		// either the returned node is the root of the tree, or it is
		// the leftmost node in the tree; in both cases node was found
		// set the previous node of the found node
		assert(match);
		assert(*nsec3_node != NULL);
		*nsec3_previous = (*nsec3_node)->prev;
	} else {
		*nsec3_previous = prev;
	}

	// The previous may be from wrong NSEC3 chain. Search for previous from the right chain.
	const zone_node_t *original_prev = *nsec3_previous;
	while (!((*nsec3_previous)->flags & NODE_FLAGS_IN_NSEC3_CHAIN)) {
		*nsec3_previous = (*nsec3_previous)->prev;
		if (*nsec3_previous == original_prev || *nsec3_previous == NULL) {
			// cycle
			*nsec3_previous = NULL;
			break;
		}
	}

	return (match ? ZONE_NAME_FOUND : ZONE_NAME_NOT_FOUND);
}

const zone_node_t *zone_contents_find_wildcard_child(const zone_contents_t *contents,
                                                     const zone_node_t *parent)
{
	if (contents == NULL || parent == NULL || parent->owner == NULL) {
		return NULL;
	}

	knot_dname_t wildcard[KNOT_DNAME_MAXLEN] = { 0x01, '*' };
	knot_dname_to_wire(wildcard + 2, parent->owner, KNOT_DNAME_MAXLEN - 2);

	return zone_contents_find_node(contents, wildcard);
}

static int adjust_nodes(zone_tree_t *nodes, zone_adjust_arg_t *adjust_arg,
                        zone_tree_apply_cb_t callback)
{
	assert(adjust_arg);
	assert(callback);

	if (zone_tree_is_empty(nodes)) {
		return KNOT_EOK;
	}

	adjust_arg->first_node = NULL;
	adjust_arg->previous_node = NULL;

	int ret = zone_tree_apply(nodes, callback, adjust_arg);

	if (adjust_arg->first_node) {
		adjust_arg->first_node->prev = adjust_arg->previous_node;
	}

	return ret;
}

static int load_nsec3param(zone_contents_t *contents)
{
	assert(contents);
	assert(contents->apex);

	const knot_rdataset_t *rrs = NULL;
	rrs = node_rdataset(contents->apex, KNOT_RRTYPE_NSEC3PARAM);
	if (rrs == NULL) {
		dnssec_nsec3_params_free(&contents->nsec3_params);
		return KNOT_EOK;
	}

	if (rrs->count < 1) {
		return KNOT_EINVAL;
	}

	dnssec_binary_t rdata = {
		.size = rrs->rdata->len,
		.data = rrs->rdata->data,
	};

	dnssec_nsec3_params_t new_params = { 0 };
	int r = dnssec_nsec3_params_from_rdata(&new_params, &rdata);
	if (r != DNSSEC_EOK) {
		return KNOT_EMALF;
	}

	dnssec_nsec3_params_free(&contents->nsec3_params);
	contents->nsec3_params = new_params;
	return KNOT_EOK;
}

static int contents_adjust(zone_contents_t *contents, bool normal)
{
	if (contents == NULL || contents->apex == NULL) {
		return KNOT_EINVAL;
	}

	int ret = load_nsec3param(contents);
	if (ret != KNOT_EOK) {
		log_zone_error(contents->apex->owner,
		               "failed to load NSEC3 parameters (%s)",
		               knot_strerror(ret));
		return ret;
	}

	zone_adjust_arg_t arg = {
		.zone = contents
	};

	contents->size = 0;
	contents->dnssec = node_rrtype_is_signed(contents->apex, KNOT_RRTYPE_SOA);

	// NSEC3 nodes must be adjusted first, because we already need the NSEC3 chain
	// to be closed before we adjust NSEC3 pointers in adjust_normal_node
	ret = adjust_nodes(contents->nsec3_nodes, &arg, adjust_nsec3_node);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = adjust_nodes(contents->nodes, &arg,
	                   normal ? adjust_normal_node : adjust_pointers);
	if (ret != KNOT_EOK) {
		return ret;
	}

	return adjust_nodes(contents->nodes, &arg, adjust_additional);
}

int zone_contents_adjust_pointers(zone_contents_t *contents)
{
	return contents_adjust(contents, false);
}

int zone_contents_adjust_full(zone_contents_t *contents)
{
	return contents_adjust(contents, true);
}

int zone_contents_apply(zone_contents_t *contents,
                        zone_contents_apply_cb_t function, void *data)
{
	if (contents == NULL) {
		return KNOT_EINVAL;
	}

	zone_tree_func_t f = {
		.func = function,
		.data = data
	};

	return zone_tree_apply(contents->nodes, tree_apply_cb, &f);
}

int zone_contents_nsec3_apply(zone_contents_t *contents,
                              zone_contents_apply_cb_t function, void *data)
{
	if (contents == NULL) {
		return KNOT_EINVAL;
	}

	zone_tree_func_t f = {
		.func = function,
		.data = data
	};

	return zone_tree_apply(contents->nsec3_nodes, tree_apply_cb, &f);
}

int zone_contents_shallow_copy(const zone_contents_t *from, zone_contents_t **to)
{
	if (from == NULL || to == NULL) {
		return KNOT_EINVAL;
	}

	/* Copy to same destination as source. */
	if (from == *to) {
		return KNOT_EINVAL;
	}

	zone_contents_t *contents = calloc(1, sizeof(zone_contents_t));
	if (contents == NULL) {
		return KNOT_ENOMEM;
	}

	int ret = recreate_normal_tree(from, contents);
	if (ret != KNOT_EOK) {
		zone_tree_free(&contents->nodes);
		free(contents);
		return ret;
	}

	if (from->nsec3_nodes) {
		ret = recreate_nsec3_tree(from, contents);
		if (ret != KNOT_EOK) {
			zone_tree_free(&contents->nodes);
			zone_tree_free(&contents->nsec3_nodes);
			free(contents);
			return ret;
		}
	} else {
		contents->nsec3_nodes = NULL;
	}

	*to = contents;
	return KNOT_EOK;
}

void zone_contents_free(zone_contents_t *contents)
{
	if (contents == NULL) {
		return;
	}

	// free the zone tree, but only the structure
	zone_tree_free(&contents->nodes);
	zone_tree_free(&contents->nsec3_nodes);

	dnssec_nsec3_params_free(&contents->nsec3_params);

	free(contents);
}

void zone_contents_deep_free(zone_contents_t *contents)
{
	if (contents == NULL) {
		return;
	}

	if (contents != NULL) {
		// Delete NSEC3 tree.
		(void)zone_tree_apply(contents->nsec3_nodes,
		                      destroy_node_rrsets_from_tree, NULL);

		// Delete the normal tree.
		(void)zone_tree_apply(contents->nodes,
		                      destroy_node_rrsets_from_tree, NULL);
	}

	zone_contents_free(contents);
}

uint32_t zone_contents_serial(const zone_contents_t *zone)
{
	if (zone == NULL) {
		return 0;
	}

	const knot_rdataset_t *soa = node_rdataset(zone->apex, KNOT_RRTYPE_SOA);
	if (soa == NULL) {
		return 0;
	}

	return knot_soa_serial(soa->rdata);
}

void zone_contents_set_soa_serial(zone_contents_t *zone, uint32_t new_serial)
{
	knot_rdataset_t *soa;
	if (zone != NULL && (soa = node_rdataset(zone->apex, KNOT_RRTYPE_SOA)) != NULL) {
		knot_soa_serial_set(soa->rdata, new_serial);
	}
}

bool zone_contents_is_empty(const zone_contents_t *zone)
{
	if (zone == NULL) {
		return true;
	}

	bool apex_empty = (zone->apex == NULL || zone->apex->rrset_count == 0);
	bool no_non_apex = (zone_tree_count(zone->nodes) <= (zone->apex != NULL ? 1 : 0));
	bool no_nsec3 = zone_tree_is_empty(zone->nsec3_nodes);

	return (apex_empty && no_non_apex && no_nsec3);
}

size_t zone_contents_measure_size(zone_contents_t *zone)
{
	zone->size = 0;
	zone_contents_apply(zone, measure_size, &zone->size);
	return zone->size;
}
