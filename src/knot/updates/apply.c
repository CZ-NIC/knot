/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
		additional_clear(data->additional);
		data->additional = NULL;
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

/*! \brief Frees RR dataset. For use when a copy was made. */
static void clear_new_rrs(zone_node_t *node, uint16_t type)
{
	knot_rdataset_t *new_rrs = node_rdataset(node, type);
	if (new_rrs) {
		knot_rdataset_clear(new_rrs, NULL);
	}
}

/*! \brief Stores RR data for update cleanup. */
static int add_old_data(apply_ctx_t *ctx, knot_rdata_t *old_data)
{
	if (ptrlist_add(&ctx->old_data, old_data, NULL) == NULL) {
		return KNOT_ENOMEM;
	}

	return KNOT_EOK;
}

/*! \brief Stores RR data for update rollback. */
static int add_new_data(apply_ctx_t *ctx, knot_rdata_t *new_data)
{
	if (ptrlist_add(&ctx->new_data, new_data, NULL) == NULL) {
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

/*! \brief Removes all RRs from changeset from zone contents. */
static int apply_remove(apply_ctx_t *ctx, changeset_t *chset)
{
	changeset_iter_t itt;
	changeset_iter_rem(&itt, chset);

	knot_rrset_t rr = changeset_iter_next(&itt);
	while (!knot_rrset_empty(&rr)) {
		int ret = apply_remove_rr(ctx, &rr);
		if (ret != KNOT_EOK) {
			changeset_iter_clear(&itt);
			return ret;
		}

		rr = changeset_iter_next(&itt);
	}
	changeset_iter_clear(&itt);

	return KNOT_EOK;
}

/*! \brief Adds all RRs from changeset into zone contents. */
static int apply_add(apply_ctx_t *ctx, changeset_t *chset)
{
	changeset_iter_t itt;
	changeset_iter_add(&itt, chset);

	knot_rrset_t rr = changeset_iter_next(&itt);
	while(!knot_rrset_empty(&rr)) {
		int ret = apply_add_rr(ctx, &rr);
		if (ret != KNOT_EOK) {
			changeset_iter_clear(&itt);
			return ret;
		}
		rr = changeset_iter_next(&itt);
	}
	changeset_iter_clear(&itt);

	return KNOT_EOK;
}

/*! \brief Apply single change to zone contents structure. */
static int apply_single(apply_ctx_t *ctx, changeset_t *chset)
{
	/*
	 * Applies one changeset to the zone. Checks if the changeset may be
	 * applied (i.e. the origin SOA (soa_from) has the same serial as
	 * SOA in the zone apex.
	 */

	zone_contents_t *contents = ctx->contents;

	// check if serial matches
	const knot_rdataset_t *soa = node_rdataset(contents->apex, KNOT_RRTYPE_SOA);
	if (soa == NULL || knot_soa_serial(soa) != knot_soa_serial(&chset->soa_from->rrs)) {
		return KNOT_EINVAL;
	}

	int ret = apply_remove(ctx, chset);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = apply_add(ctx, chset);
	if (ret != KNOT_EOK) {
		return ret;
	}

	return apply_replace_soa(ctx, chset);
}

/* ------------------------------- API -------------------------------------- */

void apply_init_ctx(apply_ctx_t *ctx, zone_contents_t *contents, uint32_t flags)
{
	assert(ctx);

	ctx->contents = contents;

	init_list(&ctx->old_data);
	init_list(&ctx->new_data);

	ctx->flags = flags;
}

int apply_prepare_zone_copy(zone_contents_t *old_contents,
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

int apply_add_rr(apply_ctx_t *ctx, const knot_rrset_t *rr)
{
	zone_contents_t *contents = ctx->contents;

	// Get or create node with this owner
	zone_node_t *node = zone_contents_get_node_for_rr(contents, rr);
	if (node == NULL) {
		return KNOT_ENOMEM;
	}

	knot_rrset_t changed_rrset = node_rrset(node, rr->type);
	if (!knot_rrset_empty(&changed_rrset)) {
		// Modifying existing RRSet.
		knot_rdata_t *old_data = changed_rrset.rrs.data;
		int ret = replace_rdataset_with_copy(node, rr->type);
		if (ret != KNOT_EOK) {
			return ret;
		}

		// Store old RRS for cleanup.
		ret = add_old_data(ctx, old_data);
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
		int data_ret = add_new_data(ctx, rrs->data);
		if (data_ret != KNOT_EOK) {
			knot_rdataset_clear(rrs, NULL);
			return data_ret;
		}

		if (ret == KNOT_ETTL) {
			log_zone_notice(contents->apex->owner,
			                "rrset (type %u) TTL mismatch, updated to %u",
			                rr->type, knot_rrset_ttl(rr));
			return KNOT_EOK;
		}
	}

	return ret;
}

int apply_remove_rr(apply_ctx_t *ctx, const knot_rrset_t *rr)
{
	zone_contents_t *contents = ctx->contents;

	// Find node for this owner
	zone_node_t *node = zone_contents_find_node_for_rr(contents, rr);
	if (!can_remove(node, rr)) {
		// Cannot be removed, either no node or nonexistent RR
		if (ctx->flags & APPLY_STRICT) {
			// Don't ignore missing RR if strict. Required for IXFR.
			return KNOT_ENORECORD;
		}
		return KNOT_EOK;
	}

	zone_tree_t *tree = knot_rrset_is_nsec3rel(rr) ?
	                    contents->nsec3_nodes : contents->nodes;

	knot_rrset_t removed_rrset = node_rrset(node, rr->type);
	knot_rdata_t *old_data = removed_rrset.rrs.data;
	int ret = replace_rdataset_with_copy(node, rr->type);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Store old data for cleanup.
	ret = add_old_data(ctx, old_data);
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
		ret = add_new_data(ctx, changed_rrs->data);
		if (ret != KNOT_EOK) {
			knot_rdataset_clear(changed_rrs, NULL);
			return ret;
		}
	} else {
		// RRSet is empty now, remove it from node, all data freed.
		node_remove_rdataset(node, rr->type);
		// If node is empty now, delete it from zone tree.
		if (node->rrset_count == 0 && node != contents->apex) {
			zone_tree_delete_empty_node(tree, node);
		}
	}

	return KNOT_EOK;
}

int apply_replace_soa(apply_ctx_t *ctx, changeset_t *chset)
{
	zone_contents_t *contents = ctx->contents;

	if (!knot_dname_is_equal(chset->soa_to->owner, contents->apex->owner)) {
		return KNOT_EDENIED;
	}

	assert(chset->soa_from && chset->soa_to);
	int ret = apply_remove_rr(ctx, chset->soa_from);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Check for SOA with proper serial but different rdata.
	if (node_rrtype_exists(contents->apex, KNOT_RRTYPE_SOA)) {
		return KNOT_ESOAINVAL;
	}

	return apply_add_rr(ctx, chset->soa_to);
}

int apply_prepare_to_sign(apply_ctx_t *ctx)
{
	return zone_contents_adjust_pointers(ctx->contents);
}

int apply_changesets(apply_ctx_t *ctx, zone_t *zone, list_t *chsets,
                     zone_contents_t **new_contents)
{
	if (ctx == NULL || zone == NULL || chsets == NULL ||
	    EMPTY_LIST(*chsets) || new_contents == NULL) {
		return KNOT_EINVAL;
	}

	zone_contents_t *old_contents = zone->contents;
	if (!old_contents) {
		return KNOT_EINVAL;
	}

	zone_contents_t *contents_copy = NULL;
	int ret = apply_prepare_zone_copy(old_contents, &contents_copy);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ctx->contents = contents_copy;

	changeset_t *set = NULL;
	WALK_LIST(set, *chsets) {
		ret = apply_single(ctx, set);
		if (ret != KNOT_EOK) {
			update_rollback(ctx);
			update_free_zone(&ctx->contents);
			return ret;
		}
	}

	assert(contents_copy->apex != NULL);

	ret = zone_contents_adjust_full(contents_copy);
	if (ret != KNOT_EOK) {
		update_rollback(ctx);
		update_free_zone(&ctx->contents);
		return ret;
	}

	*new_contents = contents_copy;

	return KNOT_EOK;
}

int apply_changeset(apply_ctx_t *ctx, zone_t *zone, changeset_t *ch,
                    zone_contents_t **new_contents)
{
	if (ctx == NULL || zone == NULL || ch == NULL || new_contents == NULL) {
		return KNOT_EINVAL;
	}

	zone_contents_t *old_contents = zone->contents;
	if (!old_contents) {
		return KNOT_EINVAL;
	}

	zone_contents_t *contents_copy = NULL;
	int ret = apply_prepare_zone_copy(old_contents, &contents_copy);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ctx->contents = contents_copy;

	ret = apply_single(ctx, ch);
	if (ret != KNOT_EOK) {
		update_rollback(ctx);
		update_free_zone(&ctx->contents);
		return ret;
	}

	ret = zone_contents_adjust_full(contents_copy);
	if (ret != KNOT_EOK) {
		update_rollback(ctx);
		update_free_zone(&ctx->contents);
		return ret;
	}

	*new_contents = contents_copy;

	return KNOT_EOK;
}

int apply_changesets_directly(apply_ctx_t *ctx, list_t *chsets)
{
	if (ctx == NULL || ctx->contents == NULL || chsets == NULL) {
		return KNOT_EINVAL;
	}

	changeset_t *set = NULL;
	WALK_LIST(set, *chsets) {
		int ret = apply_single(ctx, set);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return zone_contents_adjust_full(ctx->contents);
}

int apply_changeset_directly(apply_ctx_t *ctx, changeset_t *ch)
{
	if (ctx == NULL || ctx->contents == NULL || ch == NULL) {
		return KNOT_EINVAL;
	}

	int ret = apply_single(ctx, ch);
	if (ret != KNOT_EOK) {
		update_rollback(ctx);
		return ret;
	}

	ret = zone_contents_adjust_full(ctx->contents);
	if (ret != KNOT_EOK) {
		update_rollback(ctx);
		return ret;
	}

	return KNOT_EOK;
}

int apply_finalize(apply_ctx_t *ctx)
{
	return zone_contents_adjust_full(ctx->contents);
}

void update_cleanup(apply_ctx_t *ctx)
{
	if (ctx == NULL) {
		return;
	}

	// Delete old RR data
	rrs_list_clear(&ctx->old_data, NULL);
	init_list(&ctx->old_data);
	// Keep new RR data
	ptrlist_free(&ctx->new_data, NULL);
	init_list(&ctx->new_data);
}

void update_rollback(apply_ctx_t *ctx)
{
	if (ctx == NULL) {
		return;
	}

	// Delete new RR data
	rrs_list_clear(&ctx->new_data, NULL);
	init_list(&ctx->new_data);
	// Keep old RR data
	ptrlist_free(&ctx->old_data, NULL);
	init_list(&ctx->old_data);
}

void update_free_zone(zone_contents_t **contents)
{
	if (contents == NULL || *contents == NULL) {
		return;
	}

	zone_tree_apply((*contents)->nodes, free_additional, NULL);
	zone_tree_deep_free(&(*contents)->nodes);
	zone_tree_deep_free(&(*contents)->nsec3_nodes);

	dnssec_nsec3_params_free(&(*contents)->nsec3_params);

	free(*contents);
	*contents = NULL;
}
