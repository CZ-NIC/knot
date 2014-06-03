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

#include "knot/updates/apply.h"

#include "common/debug.h"
#include "libknot/packet/pkt.h"
#include "libknot/processing/process.h"
#include "libknot/dname.h"
#include "knot/zone/zone.h"
#include "libknot/common.h"
#include "knot/updates/changesets.h"
#include "knot/zone/zonefile.h"
#include "common/lists.h"
#include "common/descriptor.h"
#include "libknot/util/utils.h"
#include "libknot/rrtype/soa.h"

/* --------------------------- Update cleanup ------------------------------- */

/*!
 * \brief Post update cleanup: frees data that are in the tree that will not
 *        be used (old tree if success, new tree if failure).
 *          Freed data:
 *           - actual data inside knot_rrs_t. (the rest is part of the node)
 */
static void rrs_list_clear(list_t *l, mm_ctx_t *mm)
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

/*! \brief Removes single RR from zone contents. */
static int remove_rr(zone_node_t *node, const knot_rrset_t *rr,
                     changeset_t *chset)
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
	}

	return KNOT_EOK;
}

/*! \brief Removes all RRs from changeset from zone contents. */
static int apply_remove(zone_contents_t *contents, changeset_t *chset)
{
	knot_rr_ln_t *rr_node = NULL;
	WALK_LIST(rr_node, chset->remove) {
		const knot_rrset_t *rr = rr_node->rr;

		// Find node for this owner
		zone_node_t *node = zone_contents_find_node_for_rr(contents, rr);
		if (!can_remove(node, rr)) {
			// Nothing to remove from, skip.
			continue;
		}

		int ret = remove_rr(node, rr, chset);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

/*! \brief Adds a single RR into zone contents. */
static int add_rr(zone_node_t *node, const knot_rrset_t *rr,
                  changeset_t *chset, bool master)
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
	int ret = node_add_rrset(node, rr);
	if (ret == KNOT_EOK || ret == KNOT_ETTL) {
		// RR added, store for possible rollback.
		knot_rdataset_t *rrs = node_rdataset(node, rr->type);
		int data_ret = add_new_data(chset, rrs->data);
		if (data_ret != KNOT_EOK) {
			knot_rdataset_clear(rrs, NULL);
			return data_ret;
		}

		if (ret == KNOT_ETTL) {
			// Handle possible TTL errors.
			log_ttl_error(node, rr);
			if (!master) {
				// TTL errors fatal only for master.
				return KNOT_EOK;
			}
		}
	}

	return ret;
}

/*! \brief Adds all RRs from changeset into zone contents. */
static int apply_add(zone_contents_t *contents, changeset_t *chset,
                     bool master)
{
	knot_rr_ln_t *rr_node = NULL;
	WALK_LIST(rr_node, chset->add) {
		knot_rrset_t *rr = rr_node->rr;

		// Get or create node with this owner
		zone_node_t *node = zone_contents_get_node_for_rr(contents, rr);
		if (node == NULL) {
			return KNOT_ENOMEM;
		}

		int ret = add_rr(node, rr, chset, master);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

/*! \brief Replace old SOA with a new one. */
static int apply_replace_soa(zone_contents_t *contents, changeset_t *chset)
{
	assert(chset->soa_from);
	int ret = remove_rr(contents->apex, chset->soa_from, chset);
	if (ret != KNOT_EOK) {
		return ret;
	}

	assert(!node_rrtype_exists(contents->apex, KNOT_RRTYPE_SOA));

	return add_rr(contents->apex, chset->soa_to, chset, false);
}

/*! \brief Apply single change to zone contents structure. */
static int apply_changeset(zone_contents_t *contents, changeset_t *chset,
                           bool master)
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

	ret = apply_add(contents, chset, master);
	if (ret != KNOT_EOK) {
		return ret;
	}

	return apply_replace_soa(contents, chset);
}

/* ------------------------- Empty node cleanup ----------------------------- */

/*! \brief Mark empty nodes in updated tree. */
static int mark_empty(zone_node_t **node_p, void *data)
{
	assert(node_p && *node_p);
	zone_node_t *node = *node_p;
	list_t *l = (list_t *)data;
	assert(data);
	if (node->rrset_count == 0 && node->children == 0 &&
	    !(node->flags & NODE_FLAGS_EMPTY)) {
		/*!
		 * Mark this node and all parent nodes that have 0 RRSets and
		 * no children for removal.
		 */
		if (ptrlist_add(l, node, NULL) == NULL) {
			return KNOT_ENOMEM;
		}
		node->flags |= NODE_FLAGS_EMPTY;
		if (node->parent) {
			if ((node->parent->flags & NODE_FLAGS_WILDCARD_CHILD)
			    && knot_dname_is_wildcard(node->owner)) {
				node->parent->flags &= ~NODE_FLAGS_WILDCARD_CHILD;
			}
			node->parent->children--;
			// Recurse using the parent node
			return mark_empty(&node->parent, data);
		}
	}

	return KNOT_EOK;
}

static int remove_empty_tree_nodes(zone_tree_t *tree)
{
	list_t l;
	init_list(&l);
	// walk through the zone and select nodes to be removed
	int ret = zone_tree_apply(tree, mark_empty, &l);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ptrnode_t *n = NULL;
	node_t *nxt = NULL;
	WALK_LIST_DELSAFE(n, nxt, l) {
		zone_node_t *node = (zone_node_t *)n->d;
		int ret = zone_tree_remove(tree, node->owner, &node);
		if (ret != KNOT_EOK) {
			return ret;
		}
		node_free(&node);
		free(n);
	}

	return KNOT_EOK;
}

/*! \brief Removes node that were previously marked as empty. */
static int remove_empty_nodes(zone_contents_t *z)
{
	int ret = remove_empty_tree_nodes(z->nodes);
	if (ret != KNOT_EOK) {
		return ret;
	}

	return remove_empty_tree_nodes(z->nsec3_nodes);
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

	int ret = remove_empty_nodes(contents_copy);
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (set_nsec3_names) {
		ret = zone_contents_adjust_full(contents_copy, NULL, NULL);
	} else {
		ret = zone_contents_adjust_pointers(contents_copy);
	}
	if (ret != KNOT_EOK) {
		return ret;
	}

	return KNOT_EOK;
}

/* ------------------------------- API -------------------------------------- */

int apply_changesets(zone_t *zone, changesets_t *chsets,
                     zone_contents_t **new_contents)
{
	if (zone == NULL || changesets_empty(chsets) || new_contents == NULL) {
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
	const bool master = (zone_master(zone) == NULL);
	WALK_LIST(set, chsets->sets) {
		ret = apply_changeset(contents_copy, set, master);
		if (ret != KNOT_EOK) {
			update_rollback(chsets, &contents_copy);
			return ret;
		}
	}

	assert(contents_copy->apex != NULL);

	ret = finalize_updated_zone(contents_copy, true);
	if (ret != KNOT_EOK) {
		update_rollback(chsets, &contents_copy);
		return ret;
	}

	*new_contents = contents_copy;

	return KNOT_EOK;
}

int apply_changesets_directly(zone_contents_t *contents, changesets_t *chsets)
{
	if (contents == NULL || chsets == NULL) {
		return KNOT_EINVAL;
	}

	changeset_t *set = NULL;
	WALK_LIST(set, chsets->sets) {
		const bool master = true; // Only DNSSEC changesets are applied directly.
		int ret = apply_changeset(contents, set, master);
		if (ret != KNOT_EOK) {
			update_cleanup(chsets);
			return ret;
		}
	}

	int ret = finalize_updated_zone(contents, true);

	/*
	 * HACK: Cleanup for successful update is used for both success and fail
	 * when modifying the zone directly, will fix in new zone API.
	 */
	update_cleanup(chsets);
	return ret;
}

void update_cleanup(changesets_t *chgs)
{
	if (chgs == NULL) {
		return;
	}

	changeset_t *change = NULL;
	WALK_LIST(change, chgs->sets) {
		// Delete old RR data
		rrs_list_clear(&change->old_data, NULL);
		init_list(&change->old_data);
		// Keep new RR data
		ptrlist_free(&change->new_data, NULL);
		init_list(&change->new_data);
	};
}

void update_rollback(changesets_t *chgs, zone_contents_t **new_contents)
{
	if (chgs != NULL) {
		changeset_t *change = NULL;
		WALK_LIST(change, chgs->sets) {
			// Delete new RR data
			rrs_list_clear(&change->new_data, NULL);
			init_list(&change->new_data);
			// Keep old RR data
			ptrlist_free(&change->old_data, NULL);
			init_list(&change->old_data);
		};
	}
	if (new_contents) {
		update_free_old_zone(new_contents);
	}
}

void update_free_old_zone(zone_contents_t **contents)
{
	/*
	 * Free the zone tree, but only the structure
	 * (nodes are already destroyed) and free additional arrays.
	 */
	zone_tree_apply((*contents)->nodes, free_additional, NULL);
	zone_tree_deep_free(&(*contents)->nodes);
	zone_tree_deep_free(&(*contents)->nsec3_nodes);

	knot_nsec3param_free(&(*contents)->nsec3_params);

	free(*contents);
	*contents = NULL;
}

