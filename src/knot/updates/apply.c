/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "knot/common/log.h"
#include "knot/updates/apply.h"
#include "libknot/libknot.h"
#include "contrib/macros.h"
#include "contrib/mempattern.h"

/* --------------------------- Update cleanup ------------------------------- */

/*!
 * \brief Post update cleanup: frees data that are in the tree that will not
 *        be used (old tree if success, new tree if failure).
 *          Freed data:
 *           - actual data inside knot_rrs_t. (the rest is part of the node)
 */
static void rrs_list_clear(list_t *l, knot_mm_t *mm)
{
	ptrnode_t *n;
	node_t *nxt;
	WALK_LIST_DELSAFE(n, nxt, *l) {
		mm_free(mm, (void *)n->d);
		mm_free(mm, n);
	};
}

/*! \brief Frees additional data from single node */
static int free_additional(zone_node_t **node, void *data)
{
	UNUSED(data);
	if ((*node)->flags & NODE_FLAGS_NONAUTH) {
		// non-auth nodes have no additionals.
		return KNOT_EOK;
	}

	for (uint16_t i = 0; i < (*node)->rrset_count; ++i) {
		struct rr_data *data = &(*node)->rrs[i];
		if (data->additional) {
			free(data->additional);
			data->additional = NULL;
		}
	}

	return KNOT_EOK;
}

/* ------------------------- Empty node cleanup ----------------------------- */

/*! \brief Clears wildcard child if set in parent node. */
static void fix_wildcard_child(zone_node_t *node, const knot_dname_t *owner)
{
	if ((node->flags & NODE_FLAGS_WILDCARD_CHILD)
	    && knot_dname_is_wildcard(owner)) {
		node->flags &= ~NODE_FLAGS_WILDCARD_CHILD;
	}
}

/*! \todo move this to new zone API - zone should do this automatically. */
/*! \brief Deletes possibly empty node and all its empty parents recursively. */
static void delete_empty_node(zone_tree_t *tree, zone_node_t *node)
{
	if (node->rrset_count == 0 && node->children == 0) {
		zone_node_t *parent_node = node->parent;
		if (parent_node) {
			fix_wildcard_child(parent_node, node->owner);
			parent_node->children--;
			// Recurse using the parent node
			delete_empty_node(tree, parent_node);
		}

		// Delete node
		zone_node_t *removed_node = NULL;
		zone_tree_remove(tree, node->owner, &removed_node);
		UNUSED(removed_node);
		node_free(&node, NULL);
	}
}

/* -------------------- Changeset application helpers ----------------------- */

/*! \brief Replaces rdataset of given type with a copy. */
static int replace_rdataset_with_copy(zone_node_t *node, uint16_t type)
{
	// Find data to copy.
	struct rr_data *data = NULL;
	for (uint16_t i = 0; i < node->rrset_count; ++i) {
		if (node->rrs[i].type == type) {
			data = &node->rrs[i];
			break;
		}
	}
	assert(data);

	// Create new data.
	knot_rdataset_t *rrs = &data->rrs;
	void *copy = malloc(knot_rdataset_size(rrs));
	if (copy == NULL) {
		return KNOT_ENOMEM;
	}

	memcpy(copy, rrs->data, knot_rdataset_size(rrs));

	// Store new data into node RRS.
	rrs->data = copy;

	return KNOT_EOK;
}

/*! \brief Stores RR data for update cleanup. */
static void clear_new_rrs(zone_node_t *node, uint16_t type)
{
	knot_rdataset_t *new_rrs = node_rdataset(node, type);
	if (new_rrs) {
		knot_rdataset_clear(new_rrs, NULL);
	}
}

/*! \brief Stores RR data for update cleanup. */
static int add_old_data(changeset_t *chset, knot_rdata_t *old_data)
{
	if (ptrlist_add(&chset->old_data, old_data, NULL) == NULL) {
		return KNOT_ENOMEM;
	}

	return KNOT_EOK;
}

/*! \brief Stores RR data for update rollback. */
static int add_new_data(changeset_t *chset, knot_rdata_t *new_data)
{
	if (ptrlist_add(&chset->new_data, new_data, NULL) == NULL) {
		return KNOT_ENOMEM;
	}

	return KNOT_EOK;
}

/*! \brief Returns true if given RR is present in node and can be removed. */
static bool can_remove(const zone_node_t *node, const knot_rrset_t *rr)
{
	if (node == NULL) {
		// Node does not exist, cannot remove anything.
		return false;
	}
	const knot_rdataset_t *node_rrs = node_rdataset(node, rr->type);
	if (node_rrs == NULL) {
		// Node does not have this type at all.
		return false;
	}

	const bool compare_ttls = false;
	for (uint16_t i = 0; i < rr->rrs.rr_count; ++i) {
		knot_rdata_t *rr_cmp = knot_rdataset_at(&rr->rrs, i);
		if (knot_rdataset_member(node_rrs, rr_cmp, compare_ttls)) {
			// At least one RR matches.
			return true;
		}
	}

	// Node does have the type, but no RRs match.
	return false;
}

/*! \todo part of the new zone API. */
static bool rrset_is_nsec3rel(const knot_rrset_t *rr)
{
	if (rr == NULL) {
		return false;
	}

	/* Is NSEC3 or non-empty RRSIG covering NSEC3. */
	return ((rr->type == KNOT_RRTYPE_NSEC3)
	        || (rr->type == KNOT_RRTYPE_RRSIG
	            && knot_rrsig_type_covered(&rr->rrs, 0)
	            == KNOT_RRTYPE_NSEC3));
}

/*! \brief Removes single RR from zone contents. */
static int remove_rr(zone_tree_t *tree, zone_node_t *node,
                     const knot_rrset_t *rr, changeset_t *chset)
{
	knot_rrset_t removed_rrset = node_rrset(node, rr->type);
	knot_rdata_t *old_data = removed_rrset.rrs.data;
	int ret = replace_rdataset_with_copy(node, rr->type);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Store old data for cleanup.
	ret = add_old_data(chset, old_data);
	if (ret != KNOT_EOK) {
		clear_new_rrs(node, rr->type);
		return ret;
	}

	knot_rdataset_t *changed_rrs = node_rdataset(node, rr->type);
	// Subtract changeset RRS from node RRS.
	ret = knot_rdataset_subtract(changed_rrs, &rr->rrs, NULL);
	if (ret != KNOT_EOK) {
		clear_new_rrs(node, rr->type);
		return ret;
	}

	if (changed_rrs->rr_count > 0) {
		// Subtraction left some data in RRSet, store it for rollback.
		ret = add_new_data(chset, changed_rrs->data);
		if (ret != KNOT_EOK) {
			knot_rdataset_clear(changed_rrs, NULL);
			return ret;
		}
	} else {
		// RRSet is empty now, remove it from node, all data freed.
		node_remove_rdataset(node, rr->type);
		// If node is empty now, delete it from zone tree.
		if (node->rrset_count == 0) {
			delete_empty_node(tree, node);
		}
	}

	return KNOT_EOK;
}

/*! \brief Removes all RRs from changeset from zone contents. */
static int apply_remove(zone_contents_t *contents, changeset_t *chset)
{
	changeset_iter_t itt;
	changeset_iter_rem(&itt, chset, false);

	knot_rrset_t rr = changeset_iter_next(&itt);
	while (!knot_rrset_empty(&rr)) {
		// Find node for this owner
		zone_node_t *node = zone_contents_find_node_for_rr(contents, &rr);
		if (!can_remove(node, &rr)) {
			// Nothing to remove from, skip.
			rr = changeset_iter_next(&itt);
			continue;
		}

		zone_tree_t *tree = rrset_is_nsec3rel(&rr) ?
		                    contents->nsec3_nodes : contents->nodes;
		int ret = remove_rr(tree, node, &rr, chset);
		if (ret != KNOT_EOK) {
			changeset_iter_clear(&itt);
			return ret;
		}

		rr = changeset_iter_next(&itt);
	}
	changeset_iter_clear(&itt);

	return KNOT_EOK;
}

/*! \brief Adds a single RR into zone contents. */
static int add_rr(const zone_contents_t *zone, zone_node_t *node,
                  const knot_rrset_t *rr, changeset_t *chset)
{
	knot_rrset_t changed_rrset = node_rrset(node, rr->type);
	if (!knot_rrset_empty(&changed_rrset)) {
		// Modifying existing RRSet.
		knot_rdata_t *old_data = changed_rrset.rrs.data;
		int ret = replace_rdataset_with_copy(node, rr->type);
		if (ret != KNOT_EOK) {
			return ret;
		}

		// Store old RRS for cleanup.
		ret = add_old_data(chset, old_data);
		if (ret != KNOT_EOK) {
			clear_new_rrs(node, rr->type);
			return ret;
		}
	}

	// Insert new RR to RRSet, data will be copied.
	int ret = node_add_rrset(node, rr, NULL);
	if (ret == KNOT_EOK || ret == KNOT_ETTL) {
		// RR added, store for possible rollback.
		knot_rdataset_t *rrs = node_rdataset(node, rr->type);
		int data_ret = add_new_data(chset, rrs->data);
		if (data_ret != KNOT_EOK) {
			knot_rdataset_clear(rrs, NULL);
			return data_ret;
		}

		if (ret == KNOT_ETTL) {
			log_zone_notice(zone->apex->owner,
			                "rrset (type %u) TTL mismatch, updated to %u",
			                rr->type, knot_rrset_ttl(rr));
			return KNOT_EOK;
		}
	}

	return ret;
}

/*! \brief Adds all RRs from changeset into zone contents. */
static int apply_add(zone_contents_t *contents, changeset_t *chset)
{
	changeset_iter_t itt;
	changeset_iter_add(&itt, chset, false);

	knot_rrset_t rr = changeset_iter_next(&itt);
	while(!knot_rrset_empty(&rr)) {
		// Get or create node with this owner
		zone_node_t *node = zone_contents_get_node_for_rr(contents, &rr);
		if (node == NULL) {
			changeset_iter_clear(&itt);
			return KNOT_ENOMEM;
		}

		int ret = add_rr(contents, node, &rr, chset);
		if (ret != KNOT_EOK) {
			changeset_iter_clear(&itt);
			return ret;
		}
		rr = changeset_iter_next(&itt);
	}
	changeset_iter_clear(&itt);

	return KNOT_EOK;
}

/*! \brief Replace old SOA with a new one. */
static int apply_replace_soa(zone_contents_t *contents, changeset_t *chset)
{
	assert(chset->soa_from && chset->soa_to);
	int ret = remove_rr(contents->nodes, contents->apex, chset->soa_from, chset);
	if (ret != KNOT_EOK) {
		return ret;
	}

	assert(!node_rrtype_exists(contents->apex, KNOT_RRTYPE_SOA));

	return add_rr(contents, contents->apex, chset->soa_to, chset);
}

/*! \brief Apply single change to zone contents structure. */
static int apply_single(zone_contents_t *contents, changeset_t *chset)
{
	/*
	 * Applies one changeset to the zone. Checks if the changeset may be
	 * applied (i.e. the origin SOA (soa_from) has the same serial as
	 * SOA in the zone apex.
	 */

	// check if serial matches
	const knot_rdataset_t *soa = node_rdataset(contents->apex, KNOT_RRTYPE_SOA);
	if (soa == NULL || knot_soa_serial(soa) != knot_soa_serial(&chset->soa_from->rrs)) {
		return KNOT_EINVAL;
	}

	int ret = apply_remove(contents, chset);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = apply_add(contents, chset);
	if (ret != KNOT_EOK) {
		return ret;
	}

	return apply_replace_soa(contents, chset);
}

/* --------------------- Zone copy and finalization ------------------------- */

/*! \brief Creates a shallow zone contents copy. */
static int prepare_zone_copy(zone_contents_t *old_contents,
                             zone_contents_t **new_contents)
{
	if (old_contents == NULL || new_contents == NULL) {
		return KNOT_EINVAL;
	}

	/*
	 * Create a shallow copy of the zone, so that the structures may be
	 * updated.
	 *
	 * This will create new zone contents structures (normal nodes' tree,
	 * NSEC3 tree), and copy all nodes.
	 * The data in the nodes (RRSets) remain the same though.
	 */
	zone_contents_t *contents_copy = NULL;
	int ret = zone_contents_shallow_copy(old_contents, &contents_copy);
	if (ret != KNOT_EOK) {
		return ret;
	}

	*new_contents = contents_copy;

	return KNOT_EOK;
}

/*! \brief Removes empty nodes from updated zone a does zone adjusting. */
static int finalize_updated_zone(zone_contents_t *contents_copy,
                                 bool set_nsec3_names)
{
	if (contents_copy == NULL) {
		return KNOT_EINVAL;
	}

	if (set_nsec3_names) {
		return zone_contents_adjust_full(contents_copy, NULL, NULL);
	} else {
		return zone_contents_adjust_pointers(contents_copy);
	}
}

/* ------------------------------- API -------------------------------------- */

int apply_changesets(zone_t *zone, list_t *chsets, zone_contents_t **new_contents)
{
	if (zone == NULL || chsets == NULL || EMPTY_LIST(*chsets) || new_contents == NULL) {
		return KNOT_EINVAL;
	}

	zone_contents_t *old_contents = zone->contents;
	if (!old_contents) {
		return KNOT_EINVAL;
	}

	zone_contents_t *contents_copy = NULL;
	int ret = prepare_zone_copy(old_contents, &contents_copy);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/*
	 * Apply the changesets.
	 */
	changeset_t *set = NULL;
	WALK_LIST(set, *chsets) {
		ret = apply_single(contents_copy, set);
		if (ret != KNOT_EOK) {
			updates_rollback(chsets);
			update_free_zone(&contents_copy);
			return ret;
		}
	}

	assert(contents_copy->apex != NULL);

	ret = finalize_updated_zone(contents_copy, true);
	if (ret != KNOT_EOK) {
		updates_rollback(chsets);
		update_free_zone(&contents_copy);
		return ret;
	}

	*new_contents = contents_copy;

	return KNOT_EOK;
}

int apply_changeset(zone_t *zone, changeset_t *change, zone_contents_t **new_contents)
{
	if (zone == NULL || change == NULL || new_contents == NULL) {
		return KNOT_EINVAL;
	}

	zone_contents_t *old_contents = zone->contents;
	if (!old_contents) {
		return KNOT_EINVAL;
	}

	zone_contents_t *contents_copy = NULL;
	int ret = prepare_zone_copy(old_contents, &contents_copy);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = apply_single(contents_copy, change);
	if (ret != KNOT_EOK) {
		update_rollback(change);
		update_free_zone(&contents_copy);
		return ret;
	}

	ret = finalize_updated_zone(contents_copy, true);
	if (ret != KNOT_EOK) {
		update_rollback(change);
		update_free_zone(&contents_copy);
		return ret;
	}

	*new_contents = contents_copy;

	return KNOT_EOK;
}

int apply_changesets_directly(zone_contents_t *contents, list_t *chsets)
{
	if (contents == NULL || chsets == NULL) {
		return KNOT_EINVAL;
	}

	changeset_t *set = NULL;
	WALK_LIST(set, *chsets) {
		int ret = apply_single(contents, set);
		if (ret != KNOT_EOK) {
			updates_cleanup(chsets);
			return ret;
		}
	}

	int ret = finalize_updated_zone(contents, true);
	if (ret != KNOT_EOK) {
		updates_cleanup(chsets);
	}

	return ret;
}

int apply_changeset_directly(zone_contents_t *contents, changeset_t *ch)
{
	if (contents == NULL || ch == NULL) {
		return KNOT_EINVAL;
	}

	int ret = apply_single(contents, ch);
	if (ret != KNOT_EOK) {
		update_cleanup(ch);
		return ret;
	}

	ret = finalize_updated_zone(contents, true);
	if (ret != KNOT_EOK) {
		update_cleanup(ch);
		return ret;
	}

	return KNOT_EOK;
}

void update_cleanup(changeset_t *change)
{
	if (change) {
		// Delete old RR data
		rrs_list_clear(&change->old_data, NULL);
		init_list(&change->old_data);
		// Keep new RR data
		ptrlist_free(&change->new_data, NULL);
		init_list(&change->new_data);
	}
}

void updates_cleanup(list_t *chgs)
{
	if (chgs == NULL || EMPTY_LIST(*chgs)) {
		return;
	}

	changeset_t *change = NULL;
	WALK_LIST(change, *chgs) {
		update_cleanup(change);
	};
}

void update_rollback(changeset_t *change)
{
	if (change) {
		// Delete new RR data
		rrs_list_clear(&change->new_data, NULL);
		init_list(&change->new_data);
		// Keep old RR data
		ptrlist_free(&change->old_data, NULL);
		init_list(&change->old_data);
	}
}

void updates_rollback(list_t *chgs)
{
	if (chgs != NULL && !EMPTY_LIST(*chgs)) {
		changeset_t *change = NULL;
		WALK_LIST(change, *chgs) {
			update_rollback(change);
		}
	}
}

void update_free_zone(zone_contents_t **contents)
{
	zone_tree_apply((*contents)->nodes, free_additional, NULL);
	zone_tree_deep_free(&(*contents)->nodes);
	zone_tree_deep_free(&(*contents)->nsec3_nodes);

	knot_nsec3param_free(&(*contents)->nsec3_params);

	free(*contents);
	*contents = NULL;
}
