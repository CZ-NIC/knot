/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include "knot/zone/adds_tree.h"
#include "knot/zone/adjust.h"
#include "knot/zone/contents.h"
#include "knot/common/log.h"
#include "knot/dnssec/zone-nsec.h"
#include "libknot/libknot.h"
#include "contrib/qp-trie/trie.h"

/*!
 * \brief Destroys all RRSets in a node.
 *
 * \param node Node to destroy RRSets from.
 * \param data Unused parameter.
 */
static int destroy_node_rrsets_from_tree(zone_node_t *node, _unused_ void *data)
{
	if (node != NULL) {
		binode_unify(node, false, NULL);
		node_free_rrsets(node, NULL);
		node_free(node, NULL);
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

/*!
 * \brief Create a node suitable for inserting into this contents.
 */
static zone_node_t *node_new_for_contents(const knot_dname_t *owner, const zone_contents_t *contents)
{
	assert(contents->nsec3_nodes == NULL || contents->nsec3_nodes->flags == contents->nodes->flags);
	return node_new_for_tree(owner, contents->nodes, NULL);
}

static zone_node_t *get_node(const zone_contents_t *zone, const knot_dname_t *name)
{
	assert(zone);
	assert(name);

	return zone_tree_get(zone->nodes, name);
}

static zone_node_t *get_nsec3_node(const zone_contents_t *zone,
                                   const knot_dname_t *name)
{
	assert(zone);
	assert(name);

	return zone_tree_get(zone->nsec3_nodes, name);
}

static int insert_rr(zone_contents_t *z, const knot_rrset_t *rr, zone_node_t **n)
{
	if (knot_rrset_empty(rr)) {
		return KNOT_EINVAL;
	}

	if (*n == NULL) {
		int ret = zone_tree_add_node(zone_contents_tree_for_rr(z, rr), z->apex, rr->owner,
		                             (zone_tree_new_node_cb_t)node_new_for_contents, z, n);
		if (ret != KNOT_EOK) {
			return ret;
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

	int ret = node_remove_rrset(node, rr, NULL);
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (node->rrset_count == 0 && node->children == 0 && node != z->apex) {
		zone_tree_del_node(nsec3 ? z->nsec3_nodes : z->nodes, node, true);
	}

	*n = node;
	return KNOT_EOK;
}

// Public API

zone_contents_t *zone_contents_new(const knot_dname_t *apex_name, bool use_binodes)
{
	if (apex_name == NULL) {
		return NULL;
	}

	zone_contents_t *contents = calloc(1, sizeof(*contents));
	if (contents == NULL) {
		return NULL;
	}

	contents->nodes = zone_tree_create(use_binodes);
	if (contents->nodes == NULL) {
		goto cleanup;
	}

	contents->apex = node_new_for_contents(apex_name, contents);
	if (contents->apex == NULL) {
		goto cleanup;
	}

	if (zone_tree_insert(contents->nodes, &contents->apex) != KNOT_EOK) {
		goto cleanup;
	}
	contents->apex->flags |= NODE_FLAGS_APEX;
	contents->max_ttl = UINT32_MAX;

	return contents;

cleanup:
	node_free(contents->apex, NULL);
	free(contents->nodes);
	free(contents);
	return NULL;
}

zone_tree_t *zone_contents_tree_for_rr(zone_contents_t *contents, const knot_rrset_t *rr)
{
	bool nsec3rel = knot_rrset_is_nsec3rel(rr);

	if (nsec3rel && contents->nsec3_nodes == NULL) {
		contents->nsec3_nodes = zone_tree_create((contents->nodes->flags & ZONE_TREE_USE_BINODES));
		if (contents->nsec3_nodes == NULL) {
			return NULL;
		}
		contents->nsec3_nodes->flags = contents->nodes->flags;
	}

	return nsec3rel ? contents->nsec3_nodes : contents->nodes;
}

int zone_contents_add_rr(zone_contents_t *z, const knot_rrset_t *rr, zone_node_t **n)
{
	if (rr == NULL || n == NULL) {
		return KNOT_EINVAL;
	}

	if (z == NULL) {
		return KNOT_EEMPTYZONE;
	}

	return insert_rr(z, rr, n);
}

int zone_contents_remove_rr(zone_contents_t *z, const knot_rrset_t *rr, zone_node_t **n)
{
	if (rr == NULL || n == NULL) {
		return KNOT_EINVAL;
	}

	if (z == NULL) {
		return KNOT_EEMPTYZONE;
	}

	return remove_rr(z, rr, n, knot_rrset_is_nsec3rel(rr));
}

const zone_node_t *zone_contents_find_node(const zone_contents_t *zone, const knot_dname_t *name)
{
	if (zone == NULL || name == NULL) {
		return NULL;
	}

	return get_node(zone, name);
}

const zone_node_t *zone_contents_node_or_nsec3(const zone_contents_t *zone, const knot_dname_t *name)
{
	if (zone == NULL || name == NULL) {
		return NULL;
	}

	const zone_node_t *node = get_node(zone, name);
	if (node == NULL) {
		node = get_nsec3_node(zone, name);
	}
	return node;
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
	if (name == NULL || match == NULL || closest == NULL) {
		return KNOT_EINVAL;
	}

	if (zone == NULL) {
		return KNOT_EEMPTYZONE;
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
			node = node_parent(node);
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
	if (name == NULL || nsec3_node == NULL || nsec3_previous == NULL) {
		return KNOT_EINVAL;
	}

	if (zone == NULL) {
		return KNOT_EEMPTYZONE;
	}

	// check if the NSEC3 tree is not empty
	if (zone_tree_is_empty(zone->nsec3_nodes)) {
		return KNOT_ENSEC3CHAIN;
	}
	if (!knot_is_nsec3_enabled(zone)) {
		return KNOT_ENSEC3PAR;
	}

	knot_dname_storage_t nsec3_name;
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
		*nsec3_previous = node_prev(*nsec3_node);
		assert(*nsec3_previous != NULL);
	} else {
		*nsec3_previous = prev;
	}

	// The previous may be from wrong NSEC3 chain. Search for previous from the right chain.
	const zone_node_t *original_prev = *nsec3_previous;
	while (!((*nsec3_previous)->flags & NODE_FLAGS_IN_NSEC3_CHAIN)) {
		*nsec3_previous = node_prev(*nsec3_previous);
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

	knot_dname_storage_t wildcard = "\x01""*";
	knot_dname_to_wire(wildcard + 2, parent->owner, sizeof(wildcard) - 2);

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
		return KNOT_EEMPTYZONE;
	}
	return zone_tree_apply(contents->nodes, function, data);
}

int zone_contents_nsec3_apply(zone_contents_t *contents,
                              zone_tree_apply_cb_t function, void *data)
{
	if (contents == NULL) {
		return KNOT_EEMPTYZONE;
	}
	return zone_tree_apply(contents->nsec3_nodes, function, data);
}

int zone_contents_cow(zone_contents_t *from, zone_contents_t **to)
{
	if (to == NULL) {
		return KNOT_EINVAL;
	}

	if (from == NULL) {
		return KNOT_EEMPTYZONE;
	}

	/* Copy to same destination as source. */
	if (from == *to) {
		return KNOT_EINVAL;
	}

	zone_contents_t *contents = calloc(1, sizeof(zone_contents_t));
	if (contents == NULL) {
		return KNOT_ENOMEM;
	}

	contents->nodes = zone_tree_cow(from->nodes);
	if (contents->nodes == NULL) {
		free(contents);
		return KNOT_ENOMEM;
	}
	contents->apex = zone_tree_fix_get(from->apex, contents->nodes);

	if (from->nsec3_nodes) {
		contents->nsec3_nodes = zone_tree_cow(from->nsec3_nodes);
		if (contents->nsec3_nodes == NULL) {
			trie_cow_rollback(contents->nodes->cow, NULL, NULL);
			free(contents->nodes);
			free(contents);
			return KNOT_ENOMEM;
		}
	}
	contents->adds_tree = from->adds_tree;
	from->adds_tree = NULL;
	contents->size = from->size;
	contents->max_ttl = from->max_ttl;

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
	additionals_tree_free(contents->adds_tree);

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

int zone_contents_load_nsec3param(zone_contents_t *contents)
{
	if (contents == NULL) {
		return KNOT_EEMPTYZONE;
	}

	if (contents->apex == NULL) {
		return KNOT_EINVAL;
	}

	const knot_rdataset_t *rrs = NULL;
	rrs = node_rdataset(contents->apex, KNOT_RRTYPE_NSEC3PARAM);
	if (rrs == NULL) {
		dnssec_nsec3_params_free(&contents->nsec3_params);
		return KNOT_EOK;
	}

	if (rrs->count != 1) {
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
