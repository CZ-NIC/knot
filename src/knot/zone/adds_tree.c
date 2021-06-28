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
#include <stdlib.h>

#include "knot/zone/adds_tree.h"

#include "libknot/dynarray.h"
#include "libknot/error.h"
#include "libknot/rrtype/rdname.h"

knot_dynarray_declare(nodeptr, zone_node_t *, DYNARRAY_VISIBILITY_STATIC, 2)
knot_dynarray_define(nodeptr, zone_node_t *, DYNARRAY_VISIBILITY_STATIC)

typedef struct {
	nodeptr_dynarray_t array;
	bool deduplicated;
} a_t_node_t;

static int free_a_t_node(trie_val_t *val, void *null)
{
	assert(null == NULL);
	a_t_node_t *nodes = *(a_t_node_t **)val;
	nodeptr_dynarray_free(&nodes->array);
	free(nodes);
	return 0;
}

void additionals_tree_free(additionals_tree_t *a_t)
{
	if (a_t != NULL) {
		trie_apply(a_t, free_a_t_node, NULL);
		trie_free(a_t);
	}
}

int zone_node_additionals_foreach(const zone_node_t *node, const knot_dname_t *zone_apex,
                                  zone_node_additionals_cb_t cb, void *ctx)
{
	int ret = KNOT_EOK;
	for (int i = 0; ret == KNOT_EOK && i < node->rrset_count; i++) {
		struct rr_data *rr_data = &node->rrs[i];
		if (!knot_rrtype_additional_needed(rr_data->type)) {
			continue;
		}
		knot_rdata_t *rdata = knot_rdataset_at(&rr_data->rrs, 0);
		for (int j = 0; ret == KNOT_EOK && j < rr_data->rrs.count; j++) {
			const knot_dname_t *name = knot_rdata_name(rdata, rr_data->type);
			if (knot_dname_in_bailiwick(name, zone_apex) > 0) {
				ret = cb(name, ctx);
			}
			rdata = knot_rdataset_next(rdata);
		}
	}
	return ret;
}

typedef struct {
	additionals_tree_t *a_t;
	zone_node_t *node;
} a_t_node_ctx_t;

static int remove_node_from_a_t(const knot_dname_t *name, void *a_ctx)
{
	a_t_node_ctx_t *ctx = a_ctx;

	knot_dname_storage_t lf_storage;
	uint8_t *lf = knot_dname_lf(name, lf_storage);

	trie_val_t *val = trie_get_try(ctx->a_t, lf + 1, *lf);
	if (val == NULL) {
		return KNOT_EOK;
	}

	a_t_node_t *nodes = *(a_t_node_t **)val;
	if (nodes == NULL) {
		trie_del(ctx->a_t, lf + 1, *lf, NULL);
		return KNOT_EOK;
	}

	nodeptr_dynarray_remove(&nodes->array, &ctx->node);

	if (nodes->array.size == 0) {
		nodeptr_dynarray_free(&nodes->array);
		free(nodes);
		trie_del(ctx->a_t, lf + 1, *lf, NULL);
	}

	return KNOT_EOK;
}

static int add_node_to_a_t(const knot_dname_t *name, void *a_ctx)
{
	a_t_node_ctx_t *ctx = a_ctx;

	knot_dname_storage_t lf_storage;
	uint8_t *lf = knot_dname_lf(name, lf_storage);

	trie_val_t *val = trie_get_ins(ctx->a_t, lf + 1, *lf);
	if (*val == NULL) {
		*val = calloc(1, sizeof(a_t_node_t));
		if (*val == NULL) {
			return KNOT_ENOMEM;
		}
	}

	a_t_node_t *nodes = *(a_t_node_t **)val;
	nodeptr_dynarray_add(&nodes->array, &ctx->node);
	nodes->deduplicated = false;
	return KNOT_EOK;
}

int additionals_tree_update_node(additionals_tree_t *a_t, const knot_dname_t *zone_apex,
                                 zone_node_t *old_node, zone_node_t *new_node)
{
	a_t_node_ctx_t ctx = { a_t, 0 };
	int ret = KNOT_EOK;

	if (a_t == NULL || zone_apex == NULL) {
		return KNOT_EINVAL;
	}

	if (binode_additionals_unchanged(old_node, new_node)) {
		return KNOT_EOK;
	}

	// for every additional in old_node rrsets, remove mentioning of this node in tree
	if (old_node != NULL && !(old_node->flags & NODE_FLAGS_DELETED)) {
		ctx.node = binode_first(old_node);
		ret = zone_node_additionals_foreach(old_node, zone_apex, remove_node_from_a_t, &ctx);
	}

	// for every additional in new_node rrsets, add reverse link into the tree
	if (new_node != NULL && !(new_node->flags & NODE_FLAGS_DELETED) && ret == KNOT_EOK) {
		ctx.node = binode_first(new_node);
		ret = zone_node_additionals_foreach(new_node, zone_apex, add_node_to_a_t, &ctx);
	}
	return ret;
}

int additionals_tree_update_nsec3(additionals_tree_t *a_t, const zone_contents_t *zone,
                                  zone_node_t *old_node, zone_node_t *new_node)
{
	if (!knot_is_nsec3_enabled(zone)) {
		return KNOT_EOK;
	}
	bool oldex = (old_node != NULL && !(old_node->flags & NODE_FLAGS_DELETED));
	bool newex = (new_node != NULL && !(new_node->flags & NODE_FLAGS_DELETED));
	bool addn = (!oldex && newex), remn = (oldex && !newex);
	if (!addn && !remn) {
		return KNOT_EOK;
	}
	const knot_dname_t *nsec3_name = node_nsec3_hash(addn ? new_node : old_node, zone);
	if (nsec3_name == NULL) {
		return KNOT_ENOMEM;
	}
	a_t_node_ctx_t ctx = { a_t, addn ? binode_first(new_node) : binode_first(old_node) };
	return (addn ? add_node_to_a_t : remove_node_from_a_t)(nsec3_name, &ctx);
}

int additionals_tree_from_zone(additionals_tree_t **a_t, const zone_contents_t *zone)
{
	*a_t = additionals_tree_new();
	if (*a_t == NULL) {
		return KNOT_ENOMEM;
	}

	bool do_nsec3 = knot_is_nsec3_enabled(zone);

	zone_tree_it_t it = { 0 };
	int ret = zone_tree_it_begin(zone->nodes, &it);
	while (!zone_tree_it_finished(&it) && ret == KNOT_EOK) {
		ret = additionals_tree_update_node(*a_t, zone->apex->owner, NULL, zone_tree_it_val(&it));
		if (do_nsec3 && ret == KNOT_EOK) {
			ret = additionals_tree_update_nsec3(*a_t, zone,
			                                    NULL, zone_tree_it_val(&it));
		}
		zone_tree_it_next(&it);
	}
	zone_tree_it_free(&it);

	if (ret != KNOT_EOK) {
		additionals_tree_free(*a_t);
		*a_t = NULL;
	}
	return ret;
}

int additionals_tree_update_from_binodes(additionals_tree_t *a_t, const zone_tree_t *tree,
                                         const zone_contents_t *zone)
{
	zone_tree_it_t it = { 0 };
	int ret = zone_tree_it_begin((zone_tree_t *)tree, &it);
	while (!zone_tree_it_finished(&it) && ret == KNOT_EOK) {
		zone_node_t *node = zone_tree_it_val(&it), *counter = binode_counterpart(node);
		ret = additionals_tree_update_node(a_t, zone->apex->owner, counter, node);
		if (ret == KNOT_EOK) {
			ret = additionals_tree_update_nsec3(a_t, zone, counter, node);
		}
		zone_tree_it_next(&it);
	}
	zone_tree_it_free(&it);
	return ret;
}

int additionals_reverse_apply(additionals_tree_t *a_t, const knot_dname_t *name,
                              node_apply_cb_t cb, void *ctx)
{
	knot_dname_storage_t lf_storage;
	uint8_t *lf = knot_dname_lf(name, lf_storage);

	trie_val_t *val = trie_get_try(a_t, lf + 1, *lf);
	if (val == NULL) {
		return KNOT_EOK;
	}

	a_t_node_t *nodes = *(a_t_node_t **)val;
	if (nodes == NULL) {
		return KNOT_EOK;
	}

	if (!nodes->deduplicated) {
		nodeptr_dynarray_sort_dedup(&nodes->array);
		nodes->deduplicated = true;
	}

	knot_dynarray_foreach(nodeptr, zone_node_t *, node_in_arr, nodes->array) {
		int ret = cb(*node_in_arr, ctx);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

int additionals_reverse_apply_multi(additionals_tree_t *a_t, const zone_tree_t *tree,
                                    node_apply_cb_t cb, void *ctx)
{
	zone_tree_it_t it = { 0 };
	int ret = zone_tree_it_begin((zone_tree_t *)tree, &it);
	while (!zone_tree_it_finished(&it) && ret == KNOT_EOK) {
		ret = additionals_reverse_apply(a_t, zone_tree_it_val(&it)->owner, cb, ctx);
		zone_tree_it_next(&it);
	}
	zone_tree_it_free(&it);
	return ret;
}
