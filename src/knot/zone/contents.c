/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <assert.h>

#include "libdnssec/error.h"
#include "knot/zone/adjust.h"
#include "knot/zone/contents.h"
#include "knot/common/log.h"
#include "knot/dnssec/zone-nsec.h"
#include "libknot/libknot.h"
#include "contrib/qp-trie/trie.h"
#include "contrib/macros.h"

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
 * \param node Node to destroy RRSets from.
 * \param data Unused parameter.
 */
static int destroy_node_rrsets_from_tree(zone_node_t *node, void *data)
{
	UNUSED(data);

	if (node != NULL) {
		binode_unify(node, true, false, false, NULL);
		node_free_rrsets(node, NULL);
		node_free(node, NULL);
	}

	return KNOT_EOK;
}

static int measure_size(zone_node_t *node, void *data){

	node_size(node, data);
	return KNOT_EOK;
}

static int measure_max_ttl(zone_node_t *node, void *data){

	node_max_ttl(node, data);
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

zone_contents_t *zone_contents_new(const knot_dname_t *apex_name, bool use_binodes)
{
	if (apex_name == NULL) {
		return NULL;
	}

	zone_contents_t *contents = malloc(sizeof(zone_contents_t));
	if (contents == NULL) {
		return NULL;
	}

	memset(contents, 0, sizeof(zone_contents_t));
	contents->apex = node_new(apex_name, use_binodes, NULL);
	if (contents->apex == NULL) {
		goto cleanup;
	}

	contents->nodes = zone_tree_create(use_binodes);
	if (contents->nodes == NULL) {
		goto cleanup;
	}

	if (zone_tree_insert(contents->nodes, &contents->apex) != KNOT_EOK) {
		goto cleanup;
	}

	return contents;

cleanup:
	free(contents->nodes);
	free(contents->nsec3_nodes);
	free(contents);
	return NULL;
}

bool zone_contents_use_binodes(const zone_contents_t *c)
{
	return (c->nodes->flags & ZONE_TREE_USE_BINODES);
}

static zone_node_t *get_node(const zone_contents_t *zone, const knot_dname_t *name)
{
	assert(zone);
	assert(name);

	return zone_tree_get(zone->nodes, name);
}

static int add_node(zone_contents_t *zone, zone_node_t **anode, bool create_parents)
{
	if (zone == NULL || anode == NULL || *anode == NULL) {
		return KNOT_EINVAL;
	}

	int ret = check_node(zone, *anode);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = zone_tree_insert(zone->nodes, anode);
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (!create_parents) {
		return KNOT_EOK;
	}

	zone_node_t *node = *anode;

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
			next_node = node_new(parent, zone_contents_use_binodes(zone), NULL);
			if (next_node == NULL) {
				return KNOT_ENOMEM;
			}

			/* Insert node to a tree. */
			ret = zone_tree_insert(zone->nodes, &next_node);
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

static int add_nsec3_node(zone_contents_t *zone, zone_node_t **node)
{
	if (zone == NULL || node == NULL || *node == NULL) {
		return KNOT_EINVAL;
	}

	int ret = check_node(zone, *node);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Create NSEC3 tree if not exists. */
	if (zone->nsec3_nodes == NULL) {
		zone->nsec3_nodes = zone_tree_create(zone_contents_use_binodes(zone));
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
	node_set_parent(*node, zone->apex);

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
			*n = node_new(rr->owner, zone_contents_use_binodes(z), NULL);
			if (*n == NULL) {
				return KNOT_ENOMEM;
			}
			int ret = nsec3 ? add_nsec3_node(z, n) : add_node(z, n, true);
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
			zone_tree_delete_empty(nsec3 ? z->nsec3_nodes : z->nodes, node, true);
		}
	}

	*n = node;
	return KNOT_EOK;
}

static int recreate_normal_tree(const zone_contents_t *z, zone_contents_t *out)
{
	out->nodes = zone_tree_dup(z->nodes);
	out->apex = binode_node(z->apex, (out->nodes->flags & ZONE_TREE_BINO_SECOND));
	return KNOT_EOK;

	out->nodes = zone_tree_shallow_copy(z->nodes);
	if (out->nodes == NULL) {
		return KNOT_ENOMEM;
	}

	// everything done, now just update "parent" and "apex" pointers
	out->apex = NULL;
	zone_tree_it_t it = { 0 };
	if (zone_tree_it_begin(out->nodes, &it) != KNOT_EOK) {
		return KNOT_ENOMEM;
	}
	while (!zone_tree_it_finished(&it)) {
		zone_node_t *to_fix = zone_tree_it_val(&it);
		if (out->apex == NULL && knot_dname_cmp(to_fix->owner, z->apex->owner) == 0) {
			out->apex = to_fix;
		} else {
			const knot_dname_t *parname = knot_wire_next_label(to_fix->owner, NULL);
			zone_node_t *parent = get_node(out, parname);
			assert(parent != NULL);
			node_set_parent(to_fix, parent);
		}
		zone_tree_it_next(&it);
	}
	zone_tree_it_free(&it);
	assert(out->apex != NULL);

	return KNOT_EOK;
}

static int recreate_nsec3_tree(const zone_contents_t *z, zone_contents_t *out)
{
	out->nsec3_nodes = zone_tree_dup(z->nsec3_nodes);
	return KNOT_EOK;

	out->nsec3_nodes = zone_tree_shallow_copy(z->nsec3_nodes);
	if (out->nsec3_nodes == NULL) {
		return KNOT_ENOMEM;
	}

	zone_tree_it_t it = { 0 };
	if (zone_tree_it_begin(z->nsec3_nodes, &it) != KNOT_EOK) {
		return KNOT_ENOMEM;
	}
	while (!zone_tree_it_finished(&it)) {
		zone_node_t *to_fix = zone_tree_it_val(&it);
		to_fix->parent = out->apex;
		zone_tree_it_next(&it);
	}
	zone_tree_it_free(&it);
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
		node = node_new(rrset->owner, zone_contents_use_binodes(zone), NULL);
		int ret = nsec3 ? add_nsec3_node(zone, &node) : add_node(zone, &node, true);
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
	if (!zone || !name || !match || !closest) {
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
	} else if (found == 1 && previous != NULL) {
		// exact match

		assert(node && prev);

		*match = node;
		*closest = node;
		*previous = prev;

		return ZONE_NAME_FOUND;
	} else if (found == 1 && previous == NULL) {
		// exact match, zone not adjusted yet

		assert(node);
		*match = node;
		*closest = node;

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
		if (previous != NULL) {
			*previous = prev;
		}

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
	if (!knot_is_nsec3_enabled(zone)) {
		return KNOT_ENSEC3PAR;
	}

	uint8_t nsec3_name[KNOT_DNAME_MAXLEN];
	int ret = knot_create_nsec3_owner(nsec3_name, sizeof(nsec3_name),
	                                  name, zone->apex->owner, &zone->nsec3_params);
	if (ret != KNOT_EOK) {
		return ret;
	}

	return zone_contents_find_nsec3(zone, nsec3_name, nsec3_node, nsec3_previous);
}

int zone_contents_find_nsec3(const zone_contents_t *zone,
                             const knot_dname_t *nsec3_name,
                             const zone_node_t **nsec3_node,
                             const zone_node_t **nsec3_previous)
{
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

bool zone_contents_find_node_or_wildcard(const zone_contents_t *contents,
                                         const knot_dname_t *find,
                                         const zone_node_t **found)
{
	const zone_node_t *encloser = NULL;
	zone_contents_find_dname(contents, find, found, &encloser, NULL);
	if (*found == NULL && encloser != NULL && (encloser->flags & NODE_FLAGS_WILDCARD_CHILD)) {
		*found = zone_contents_find_wildcard_child(contents, encloser);
		assert(*found != NULL);
	}
	return (*found != NULL);
}

int zone_contents_apply(zone_contents_t *contents,
                        zone_tree_apply_cb_t function, void *data)
{
	if (contents == NULL) {
		return KNOT_EINVAL;
	}
	return zone_tree_apply(contents->nodes, function, data);
}

int zone_contents_nsec3_apply(zone_contents_t *contents,
                              zone_tree_apply_cb_t function, void *data)
{
	if (contents == NULL) {
		return KNOT_EINVAL;
	}
	return zone_tree_apply(contents->nsec3_nodes, function, data);
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

uint32_t zone_contents_max_ttl(zone_contents_t *zone)
{
	zone->max_ttl = 0;
	zone_contents_apply(zone, measure_max_ttl, &zone->size);
	return zone->max_ttl;
}
