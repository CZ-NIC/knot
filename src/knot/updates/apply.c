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

#include "knot/common/log.h"
#include "knot/updates/apply.h"
#include "libknot/libknot.h"
#include "contrib/macros.h"
#include "contrib/mempattern.h"

/*! \brief Replaces rdataset of given type with a copy. */
static int replace_rdataset_with_copy(zone_node_t *node, uint16_t type)
{
	int ret = binode_prepare_change(node, NULL);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Find data to copy.
	struct rr_data *data = NULL;
	for (uint16_t i = 0; i < node->rrset_count; ++i) {
		if (node->rrs[i].type == type) {
			data = &node->rrs[i];
			break;
		}
	}
	if (data == NULL) {
		return KNOT_EOK;
	}

	// Create new data.
	knot_rdataset_t *rrs = &data->rrs;
	void *copy = malloc(knot_rdataset_size(rrs));
	if (copy == NULL) {
		return KNOT_ENOMEM;
	}

	memcpy(copy, rrs->rdata, knot_rdataset_size(rrs));

	// Store new data into node RRS.
	rrs->rdata = copy;

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

/*! \brief Returns true if given RR is present in node and can be removed. */
static bool can_remove(const zone_node_t *node, const knot_rrset_t *rrset)
{
	if (node == NULL) {
		// Node does not exist, cannot remove anything.
		return false;
	}
	const knot_rdataset_t *node_rrs = node_rdataset(node, rrset->type);
	if (node_rrs == NULL) {
		// Node does not have this type at all.
		return false;
	}

	knot_rdata_t *rr_cmp = rrset->rrs.rdata;
	for (uint16_t i = 0; i < rrset->rrs.count; ++i) {
		if (!knot_rdataset_member(node_rrs, rr_cmp)) {
			// At least one RR doesnt' match.
			return false;
		}
		rr_cmp = knot_rdataset_next(rr_cmp);
	}

	return true;
}

static bool can_add(const zone_node_t *node, const knot_rrset_t *rrset)
{
	if (node == NULL) {
		return true;
	}
	const knot_rdataset_t *node_rrs = node_rdataset(node, rrset->type);
	if (node_rrs == NULL) {
		return true;
	}

	knot_rdata_t *rr_cmp = rrset->rrs.rdata;
	for (uint16_t i = 0; i < rrset->rrs.count; ++i) {
		if (knot_rdataset_member(node_rrs, rr_cmp)) {
			return false;
		}
		rr_cmp = knot_rdataset_next(rr_cmp);
	}

	return true;
}

int apply_init_ctx(apply_ctx_t *ctx, zone_contents_t *contents, uint32_t flags)
{
	if (ctx == NULL) {
		return KNOT_EINVAL;
	}

	ctx->contents = contents;

	ctx->node_ptrs = zone_tree_create(true);
	if (ctx->node_ptrs == NULL) {
		return KNOT_ENOMEM;
	}
	ctx->node_ptrs->flags = contents->nodes->flags;

	ctx->nsec3_ptrs = zone_tree_create(true);
	if (ctx->nsec3_ptrs == NULL) {
		zone_tree_free(&ctx->node_ptrs);
		return KNOT_ENOMEM;
	}
	ctx->nsec3_ptrs->flags = contents->nodes->flags;

	ctx->adjust_ptrs = zone_tree_create(true);
	if (ctx->adjust_ptrs == NULL) {
		zone_tree_free(&ctx->nsec3_ptrs);
		zone_tree_free(&ctx->node_ptrs);
		return KNOT_ENOMEM;
	}
	ctx->adjust_ptrs->flags = contents->nodes->flags;

	ctx->flags = flags;

	return KNOT_EOK;
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

static zone_node_t *add_node_cb(const knot_dname_t *owner, void *ctx)
{
	zone_tree_t *tree = ctx;
	zone_node_t *node = zone_tree_get(tree, owner);
	if (node == NULL) {
		node = node_new(owner, (tree->flags & ZONE_TREE_USE_BINODES),
		                (tree->flags & ZONE_TREE_BINO_SECOND), NULL);
	} else {
		node->flags &= ~NODE_FLAGS_DELETED;
	}
	return node;
}

int apply_add_rr(apply_ctx_t *ctx, const knot_rrset_t *rr)
{
	zone_contents_t *contents = ctx->contents;
	bool nsec3rel = knot_rrset_is_nsec3rel(rr);
	zone_tree_t *ptrs = nsec3rel ? ctx->nsec3_ptrs : ctx->node_ptrs;
	zone_tree_t *tree = zone_contents_tree_for_rr(contents, rr);
	if (tree == NULL) {
		return KNOT_ENOMEM;
	}

	// Get or create node with this owner, search changes first
	zone_node_t *node = NULL;
	int ret = zone_tree_add_node(tree, contents->apex, rr->owner, add_node_cb, ptrs, &node);
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (!can_add(node, rr)) {
		if (ctx->flags & APPLY_STRICT) {
			return KNOT_EISRECORD;
		}
		return KNOT_EOK;
	}

	ret = zone_tree_insert_with_parents(ptrs, node, nsec3rel);
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (binode_rdata_shared(node, rr->type)) {
		// Modifying existing RRSet.
		ret = replace_rdataset_with_copy(node, rr->type);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	// Insert new RR to RRSet, data will be copied.
	ret = node_add_rrset(node, rr, NULL);
	if (ret == KNOT_ETTL) {
		char buff[KNOT_DNAME_TXT_MAXLEN + 1];
		char *owner = knot_dname_to_str(buff, rr->owner, sizeof(buff));
		if (owner == NULL) {
			owner = "";
		}
		char type[16] = { '\0' };
		knot_rrtype_to_string(rr->type, type, sizeof(type));
		log_zone_notice(contents->apex->owner,
		                "TTL mismatch, owner %s, type %s, "
		                "TTL set to %u", owner, type, rr->ttl);
		return KNOT_EOK;
	}
	return ret;
}

int apply_remove_rr(apply_ctx_t *ctx, const knot_rrset_t *rr)
{
	zone_contents_t *contents = ctx->contents;
	bool nsec3rel = knot_rrset_is_nsec3rel(rr);
	zone_tree_t *ptrs = nsec3rel ? ctx->nsec3_ptrs : ctx->node_ptrs;
	zone_tree_t *tree = zone_contents_tree_for_rr(contents, rr);
	if (tree == NULL) {
		return KNOT_ENOMEM;
	}

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

	int ret = zone_tree_insert_with_parents(ptrs, node, nsec3rel);
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (binode_rdata_shared(node, rr->type)) {
		ret = replace_rdataset_with_copy(node, rr->type);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	node->flags &= ~NODE_FLAGS_RRSIGS_VALID;

	knot_rdataset_t *changed_rrs = node_rdataset(node, rr->type);
	// Subtract changeset RRS from node RRS.
	ret = knot_rdataset_subtract(changed_rrs, &rr->rrs, NULL);
	if (ret != KNOT_EOK) {
		clear_new_rrs(node, rr->type);
		return ret;
	}

	if (changed_rrs->count == 0) {
		// RRSet is empty now, remove it from node, all data freed, except additionals.
		node_remove_rdataset(node, rr->type);
		// If node is empty now, delete it from zone tree.
		if (node->rrset_count == 0 && node->children == 0 && node != contents->apex) {
			zone_tree_del_node(tree, node, false);
		}
	}

	return KNOT_EOK;
}

int apply_replace_soa(apply_ctx_t *ctx, const knot_rrset_t *rr)
{
	zone_contents_t *contents = ctx->contents;

	if (!knot_dname_is_equal(rr->owner, contents->apex->owner)) {
		return KNOT_EDENIED;
	}

	knot_rrset_t old_soa = node_rrset(contents->apex, KNOT_RRTYPE_SOA);

	int ret = apply_remove_rr(ctx, &old_soa);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Check for SOA with proper serial but different rdata.
	if (node_rrtype_exists(contents->apex, KNOT_RRTYPE_SOA)) {
		return KNOT_ESOAINVAL;
	}

	return apply_add_rr(ctx, rr);
}

void update_cleanup(apply_ctx_t *ctx)
{
	if (ctx == NULL) {
		return;
	}

	if (ctx->flags & APPLY_UNIFY_FULL) {
		zone_trees_unify_binodes(ctx->contents->nodes, ctx->contents->nsec3_nodes, true);
	} else {
		zone_trees_unify_binodes(ctx->adjust_ptrs, NULL, false); // beware there might be duplicities in ctx->adjust_ptrs and ctx->node_ptrs, so we don't free here
		zone_trees_unify_binodes(ctx->node_ptrs, ctx->nsec3_ptrs, true);
	}

	zone_tree_free(&ctx->node_ptrs);
	zone_tree_free(&ctx->nsec3_ptrs);
	zone_tree_free(&ctx->adjust_ptrs);

	if (ctx->cow_mutex != NULL) {
		knot_sem_post(ctx->cow_mutex);
	}
}

void update_rollback(apply_ctx_t *ctx)
{
	if (ctx == NULL) {
		return;
	}

	if (ctx->node_ptrs != NULL) {
		ctx->node_ptrs->flags ^= ZONE_TREE_BINO_SECOND;
	}
	if (ctx->nsec3_ptrs != NULL) {
		ctx->nsec3_ptrs->flags ^= ZONE_TREE_BINO_SECOND;
	}
	zone_trees_unify_binodes(ctx->node_ptrs, ctx->nsec3_ptrs, true);

	zone_tree_free(&ctx->node_ptrs);
	zone_tree_free(&ctx->nsec3_ptrs);
	zone_tree_free(&ctx->adjust_ptrs);

	trie_cow_rollback(ctx->contents->nodes->cow, NULL, NULL);
	ctx->contents->nodes->cow = NULL;
	if (ctx->contents->nsec3_nodes != NULL) {
		trie_cow_rollback(ctx->contents->nsec3_nodes->cow, NULL, NULL);
		ctx->contents->nsec3_nodes->cow = NULL;
	}

	free(ctx->contents->nodes);
	free(ctx->contents->nsec3_nodes);

	dnssec_nsec3_params_free(&ctx->contents->nsec3_params);

	free(ctx->contents);
}

void update_free_zone(zone_contents_t *contents)
{
	if (contents == NULL) {
		return;
	}

	trie_cow_commit(contents->nodes->cow, NULL, NULL);
	contents->nodes->cow = NULL;
	if (contents->nsec3_nodes != NULL) {
		trie_cow_commit(contents->nsec3_nodes->cow, NULL, NULL);
		contents->nsec3_nodes->cow = NULL;
	}

	free(contents->nodes);
	free(contents->nsec3_nodes);

	dnssec_nsec3_params_free(&contents->nsec3_params);

	free(contents);
}
