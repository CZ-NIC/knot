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

#include "knot/zone/adjust.h"
#include "knot/common/log.h"
#include "knot/dnssec/zone-nsec.h"
#include "knot/zone/adds_tree.h"
#include "knot/zone/measure.h"
#include "libdnssec/error.h"

static bool node_non_dnssec_exists(const zone_node_t *node)
{
	assert(node);

	for (uint16_t i = 0; i < node->rrset_count; ++i) {
		switch (node->rrs[i].type) {
		case KNOT_RRTYPE_NSEC:
		case KNOT_RRTYPE_NSEC3:
		case KNOT_RRTYPE_RRSIG:
			continue;
		default:
			return true;
		}
	}

	return false;
}

int adjust_cb_flags(zone_node_t *node, adjust_ctx_t *ctx)
{
	zone_node_t *parent = node_parent(node);
	uint16_t flags_orig = node->flags;
	bool set_subt_auth = false;
	bool has_data = node_non_dnssec_exists(node);

	assert(!(node->flags & NODE_FLAGS_DELETED));

	node->flags &= ~(NODE_FLAGS_DELEG | NODE_FLAGS_NONAUTH | NODE_FLAGS_SUBTREE_AUTH | NODE_FLAGS_SUBTREE_DATA);

	if (parent && (parent->flags & NODE_FLAGS_DELEG || parent->flags & NODE_FLAGS_NONAUTH)) {
		node->flags |= NODE_FLAGS_NONAUTH;
	} else if (node_rrtype_exists(node, KNOT_RRTYPE_NS) && node != ctx->zone->apex) {
		node->flags |= NODE_FLAGS_DELEG;
		if (node_rrtype_exists(node, KNOT_RRTYPE_DS)) {
			set_subt_auth = true;
		}
	} else if (has_data) {
		set_subt_auth = true;
	}

	if (set_subt_auth) {
		node_set_flag_hierarch(node, NODE_FLAGS_SUBTREE_AUTH);
	}
	if (has_data) {
		node_set_flag_hierarch(node, NODE_FLAGS_SUBTREE_DATA);
	}

	if (node->flags != flags_orig && ctx->changed_nodes != NULL) {
		return zone_tree_insert(ctx->changed_nodes, &node);
	}

	return KNOT_EOK;
}

int unadjust_cb_point_to_nsec3(zone_node_t *node, adjust_ctx_t *ctx)
{
	// downgrade the NSEC3 node pointer to NSEC3 name
	if (node->flags & NODE_FLAGS_NSEC3_NODE) {
		node->nsec3_hash = knot_dname_copy(node->nsec3_node->owner, NULL);
		node->flags &= ~NODE_FLAGS_NSEC3_NODE;
	}
	assert(ctx->changed_nodes == NULL);
	return KNOT_EOK;
}

int adjust_cb_wildcard_nsec3(zone_node_t *node, adjust_ctx_t *ctx)
{
	if (!knot_is_nsec3_enabled(ctx->zone)) {
		if (node->nsec3_wildcard_name != NULL && ctx->changed_nodes != NULL) {
			zone_tree_insert(ctx->changed_nodes, &node);
		}
		node->nsec3_wildcard_name = NULL;
		return KNOT_EOK;
	}

	if (ctx->nsec3_param_changed) {
		node->nsec3_wildcard_name = NULL;
	}

	if (node->nsec3_wildcard_name != NULL) {
		return KNOT_EOK;
	}

	size_t wildcard_size = knot_dname_size(node->owner) + 2;
	size_t wildcard_nsec3 = zone_nsec3_name_len(ctx->zone);
	if (wildcard_size > KNOT_DNAME_MAXLEN) {
		return KNOT_EOK;
	}

	node->nsec3_wildcard_name = malloc(wildcard_nsec3);
	if (node->nsec3_wildcard_name == NULL) {
		return KNOT_ENOMEM;
	}

	if (ctx->changed_nodes != NULL) {
		zone_tree_insert(ctx->changed_nodes, &node);
	}

	knot_dname_t wildcard[wildcard_size];
	assert(wildcard_size > 2);
	memcpy(wildcard, "\x01""*", 2);
	memcpy(wildcard + 2, node->owner, wildcard_size - 2);
	return knot_create_nsec3_owner(node->nsec3_wildcard_name, wildcard_nsec3,
	                               wildcard, ctx->zone->apex->owner, &ctx->zone->nsec3_params);
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

int adjust_cb_nsec3_flags(zone_node_t *node, adjust_ctx_t *ctx)
{
	uint16_t flags_orig = node->flags;

	// check if this node belongs to correct chain
	node->flags &= ~NODE_FLAGS_IN_NSEC3_CHAIN;
	const knot_rdataset_t *nsec3_rrs = node_rdataset(node, KNOT_RRTYPE_NSEC3);
	for (uint16_t i = 0; nsec3_rrs != NULL && i < nsec3_rrs->count; i++) {
		if (nsec3_params_match(nsec3_rrs, &ctx->zone->nsec3_params, i)) {
			node->flags |= NODE_FLAGS_IN_NSEC3_CHAIN;
		}
	}

	if (node->flags != flags_orig && ctx->changed_nodes != NULL) {
		return zone_tree_insert(ctx->changed_nodes, &node);
	}

	return KNOT_EOK;
}

int adjust_cb_nsec3_pointer(zone_node_t *node, adjust_ctx_t *ctx)
{
	uint16_t flags_orig = node->flags;
	zone_node_t *ptr_orig = node->nsec3_node;
	int ret = KNOT_EOK;
	if (ctx->nsec3_param_changed) {
		if (!(node->flags & NODE_FLAGS_NSEC3_NODE) &&
		    node->nsec3_hash != binode_counterpart(node)->nsec3_hash) {
			free(node->nsec3_hash);
		}
		node->nsec3_hash = NULL;
		node->flags &= ~NODE_FLAGS_NSEC3_NODE;
		(void)node_nsec3_node(node, ctx->zone);
	} else {
		ret = binode_fix_nsec3_pointer(node, ctx->zone);
	}
	if (ret == KNOT_EOK && ctx->changed_nodes != NULL &&
	    (flags_orig != node->flags || ptr_orig != node->nsec3_node)) {
		ret = zone_tree_insert(ctx->changed_nodes, &node);
	}
	return ret;
}

/*! \brief Link pointers to additional nodes for this RRSet. */
static int discover_additionals(zone_node_t *adjn, uint16_t rr_at,
                                adjust_ctx_t *ctx)
{
	struct rr_data *rr_data = &adjn->rrs[rr_at];
	assert(rr_data != NULL);

	const knot_rdataset_t *rrs = &rr_data->rrs;
	knot_rdata_t *rdata = knot_rdataset_at(rrs, 0);
	uint16_t rdcount = rrs->count;

	uint16_t mandatory_count = 0;
	uint16_t others_count = 0;
	glue_t mandatory[rdcount];
	glue_t others[rdcount];

	/* Scan new additional nodes. */
	for (uint16_t i = 0; i < rdcount; i++) {
		const knot_dname_t *dname = knot_rdata_name(rdata, rr_data->type);
		const zone_node_t *node = NULL;

		if (!zone_contents_find_node_or_wildcard(ctx->zone, dname, &node)) {
			rdata = knot_rdataset_next(rdata);
			continue;
		}

		glue_t *glue;
		if ((node->flags & (NODE_FLAGS_DELEG | NODE_FLAGS_NONAUTH)) &&
		    rr_data->type == KNOT_RRTYPE_NS &&
		    knot_dname_in_bailiwick(node->owner, adjn->owner) >= 0) {
			glue = &mandatory[mandatory_count++];
			glue->optional = false;
		} else {
			glue = &others[others_count++];
			glue->optional = true;
		}
		glue->node = node;
		glue->ns_pos = i;
		rdata = knot_rdataset_next(rdata);
	}

	/* Store sorted additionals by the type, mandatory first. */
	size_t total_count = mandatory_count + others_count;
	additional_t *new_addit = NULL;
	if (total_count > 0) {
		new_addit = malloc(sizeof(additional_t));
		if (new_addit == NULL) {
			return KNOT_ENOMEM;
		}
		new_addit->count = total_count;

		size_t size = total_count * sizeof(glue_t);
		new_addit->glues = malloc(size);
		if (new_addit->glues == NULL) {
			free(new_addit);
			return KNOT_ENOMEM;
		}

		size_t mandatory_size = mandatory_count * sizeof(glue_t);
		memcpy(new_addit->glues, mandatory, mandatory_size);
		memcpy(new_addit->glues + mandatory_count, others,
		       size - mandatory_size);
	}

	/* If the result differs, shallow copy node and store additionals. */
	if (!additional_equal(rr_data->additional, new_addit)) {
		if (ctx->changed_nodes != NULL) {
			zone_tree_insert(ctx->changed_nodes, &adjn);
		}

		if (!binode_additional_shared(adjn, adjn->rrs[rr_at].type)) {
			// this happens when additionals are adjusted twice during one update, e.g. IXFR-from-diff
			additional_clear(adjn->rrs[rr_at].additional);
		}

		int ret = binode_prepare_change(adjn, NULL);
		if (ret != KNOT_EOK) {
			return ret;
		}
		rr_data = &adjn->rrs[rr_at];

		rr_data->additional = new_addit;
	} else {
		additional_clear(new_addit);
	}

	return KNOT_EOK;
}

int adjust_cb_additionals(zone_node_t *node, adjust_ctx_t *ctx)
{
	/* Lookup additional records for specific nodes. */
	for(uint16_t i = 0; i < node->rrset_count; ++i) {
		struct rr_data *rr_data = &node->rrs[i];
		if (knot_rrtype_additional_needed(rr_data->type)) {
			int ret = discover_additionals(node, i, ctx);
			if (ret != KNOT_EOK) {
				return ret;
			}
		}
	}
	return KNOT_EOK;
}

int adjust_cb_flags_and_nsec3(zone_node_t *node, adjust_ctx_t *ctx)
{
	int ret = adjust_cb_flags(node, ctx);
	if (ret == KNOT_EOK) {
		ret = adjust_cb_nsec3_pointer(node, ctx);
	}
	return ret;
}

int adjust_cb_nsec3_and_additionals(zone_node_t *node, adjust_ctx_t *ctx)
{
	int ret = adjust_cb_nsec3_pointer(node, ctx);
	if (ret == KNOT_EOK) {
		ret = adjust_cb_wildcard_nsec3(node, ctx);
	}
	if (ret == KNOT_EOK) {
		ret = adjust_cb_additionals(node, ctx);
	}
	return ret;
}

int adjust_cb_nsec3_and_wildcard(zone_node_t *node, adjust_ctx_t *ctx)
{
	int ret = adjust_cb_wildcard_nsec3(node, ctx);
	if (ret == KNOT_EOK) {
		ret = adjust_cb_nsec3_pointer(node, ctx);
	}
	return ret;
}

int adjust_cb_void(_unused_ zone_node_t *node, _unused_ adjust_ctx_t *ctx)
{
	return KNOT_EOK;
}

typedef struct {
	zone_node_t *first_node;
	adjust_ctx_t ctx;
	zone_node_t *previous_node;
	adjust_cb_t adjust_cb;
	bool adjust_prevs;
	measure_t *m;

	// just for parallel
	unsigned threads;
	unsigned thr_id;
	size_t i;
	pthread_t thread;
	int ret;
	zone_tree_t *tree;
} zone_adjust_arg_t;

static int adjust_single(zone_node_t *node, void *data)
{
	assert(node != NULL);
	assert(data != NULL);

	zone_adjust_arg_t *args = (zone_adjust_arg_t *)data;

	// parallel adjust support
	if (args->threads > 1) {
		if (args->i++ % args->threads != args->thr_id) {
			return KNOT_EOK;
		}
	}

	if (args->m != NULL) {
		knot_measure_node(node, args->m);
	}

	if ((node->flags & NODE_FLAGS_DELETED)) {
		return KNOT_EOK;
	}

	// remember first node
	if (args->first_node == NULL) {
		args->first_node = node;
	}

	// set pointer to previous node
	if (args->adjust_prevs && args->previous_node != NULL &&
	    node->prev != args->previous_node &&
	    node->prev != binode_counterpart(args->previous_node)) {
		zone_tree_insert(args->ctx.changed_nodes, &node);
		node->prev = args->previous_node;
	}

	// update remembered previous pointer only if authoritative
	if (!(node->flags & NODE_FLAGS_NONAUTH) && node->rrset_count > 0) {
		args->previous_node = node;
	}

	return args->adjust_cb(node, &args->ctx);
}

static int zone_adjust_tree(zone_tree_t *tree, adjust_ctx_t *ctx, adjust_cb_t adjust_cb,
                            bool adjust_prevs, measure_t *measure_ctx)
{
	if (zone_tree_is_empty(tree)) {
		return KNOT_EOK;
	}

	zone_adjust_arg_t arg = { 0 };
	arg.ctx = *ctx;
	arg.adjust_cb = adjust_cb;
	arg.adjust_prevs = adjust_prevs;
	arg.m = measure_ctx;

	int ret = zone_tree_apply(tree, adjust_single, &arg);
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (adjust_prevs && arg.first_node != NULL) {
		zone_tree_insert(ctx->changed_nodes, &arg.first_node);
		arg.first_node->prev = arg.previous_node;
	}

	return KNOT_EOK;
}

static void *adjust_tree_thread(void *ctx)
{
	zone_adjust_arg_t *arg = ctx;

	arg->ret = zone_tree_apply(arg->tree, adjust_single, ctx);

	return NULL;
}

static int zone_adjust_tree_parallel(zone_tree_t *tree, adjust_ctx_t *ctx,
                                     adjust_cb_t adjust_cb, unsigned threads)
{
	if (zone_tree_is_empty(tree)) {
		return KNOT_EOK;
	}

	zone_adjust_arg_t args[threads];
	memset(args, 0, sizeof(args));
	int ret = KNOT_EOK;

	for (unsigned i = 0; i < threads; i++) {
		args[i].first_node = NULL;
		args[i].ctx = *ctx;
		args[i].adjust_cb = adjust_cb;
		args[i].adjust_prevs = false;
		args[i].m = NULL;
		args[i].tree = tree;
		args[i].threads = threads;
		args[i].i = 0;
		args[i].thr_id = i;
		args[i].ret = -1;
		if (ctx->changed_nodes != NULL) {
			args[i].ctx.changed_nodes = zone_tree_create(true);
			if (args[i].ctx.changed_nodes == NULL) {
				ret = KNOT_ENOMEM;
				break;
			}
			args[i].ctx.changed_nodes->flags = tree->flags;
		}
	}
	if (ret != KNOT_EOK) {
		for (unsigned i = 0; i < threads; i++) {
			zone_tree_free(&args[i].ctx.changed_nodes);
		}
		return ret;
	}

	for (unsigned i = 0; i < threads; i++) {
		args[i].ret = pthread_create(&args[i].thread, NULL, adjust_tree_thread, &args[i]);
	}

	for (unsigned i = 0; i < threads; i++) {
		if (args[i].ret == 0) {
			args[i].ret = pthread_join(args[i].thread, NULL);
		}
		if (args[i].ret != 0) {
			ret = knot_map_errno_code(args[i].ret);
		}
		if (ret == KNOT_EOK && ctx->changed_nodes != NULL) {
			ret = zone_tree_merge(ctx->changed_nodes, args[i].ctx.changed_nodes);
		}
		zone_tree_free(&args[i].ctx.changed_nodes);
	}

	return ret;
}

int zone_adjust_contents(zone_contents_t *zone, adjust_cb_t nodes_cb, adjust_cb_t nsec3_cb,
                         bool measure_zone, bool adjust_prevs, unsigned threads,
                         zone_tree_t *add_changed)
{
	int ret = zone_contents_load_nsec3param(zone);
	if (ret != KNOT_EOK) {
		log_zone_error(zone->apex->owner,
		               "failed to load NSEC3 parameters (%s)",
		               knot_strerror(ret));
		return ret;
	}
	zone->dnssec = node_rrtype_is_signed(zone->apex, KNOT_RRTYPE_SOA);

	measure_t m = knot_measure_init(measure_zone, false);
	adjust_ctx_t ctx = { zone, add_changed, true };

	if (threads > 1) {
		assert(nodes_cb != adjust_cb_flags); // This cb demands parent to be adjusted before child
		                                     // => required sequential adjusting (also true for
		                                     // adjust_cb_flags_and_nsec3) !!
		assert(!measure_zone);
		assert(!adjust_prevs);
		if (nsec3_cb != NULL) {
			ret = zone_adjust_tree_parallel(zone->nsec3_nodes, &ctx, nsec3_cb, threads);
		}
		if (ret == KNOT_EOK && nodes_cb != NULL) {
			ret = zone_adjust_tree_parallel(zone->nodes, &ctx, nodes_cb, threads);
		}
	} else {
		if (nsec3_cb != NULL) {
			ret = zone_adjust_tree(zone->nsec3_nodes, &ctx, nsec3_cb, adjust_prevs, &m);
		}
		if (ret == KNOT_EOK && nodes_cb != NULL) {
			ret = zone_adjust_tree(zone->nodes, &ctx, nodes_cb, adjust_prevs, &m);
		}
	}

	if (ret == KNOT_EOK && measure_zone && nodes_cb != NULL && nsec3_cb != NULL) {
		knot_measure_finish_zone(&m, zone);
	}
	return ret;
}

int zone_adjust_update(zone_update_t *update, adjust_cb_t nodes_cb, adjust_cb_t nsec3_cb, bool measure_diff)
{
	int ret = KNOT_EOK;
	measure_t m = knot_measure_init(false, measure_diff);
	adjust_ctx_t ctx = { update->new_cont, update->a_ctx->adjust_ptrs, zone_update_changed_nsec3param(update) };

	if (nsec3_cb != NULL) {
		ret = zone_adjust_tree(update->a_ctx->nsec3_ptrs, &ctx, nsec3_cb, false, &m);
	}
	if (ret == KNOT_EOK && nodes_cb != NULL) {
		ret = zone_adjust_tree(update->a_ctx->node_ptrs, &ctx, nodes_cb, false, &m);
	}
	if (ret == KNOT_EOK && measure_diff && nodes_cb != NULL && nsec3_cb != NULL) {
		knot_measure_finish_update(&m, update);
	}
	return ret;
}

int zone_adjust_full(zone_contents_t *zone, unsigned threads)
{
	int ret = zone_adjust_contents(zone, adjust_cb_flags, adjust_cb_nsec3_flags,
	                               true, true, 1, NULL);
	if (ret == KNOT_EOK) {
		ret = zone_adjust_contents(zone, adjust_cb_nsec3_and_additionals, NULL,
		                           false, false, threads, NULL);
	}
	if (ret == KNOT_EOK) {
		additionals_tree_free(zone->adds_tree);
		ret = additionals_tree_from_zone(&zone->adds_tree, zone);
	}
	return ret;
}

static int adjust_additionals_cb(zone_node_t *node, void *ctx)
{
	adjust_ctx_t *actx = ctx;
	zone_node_t *real_node = zone_tree_fix_get(node, actx->zone->nodes);
	return adjust_cb_additionals(real_node, actx);
}

static int adjust_point_to_nsec3_cb(zone_node_t *node, void *ctx)
{
	adjust_ctx_t *actx = ctx;
	zone_node_t *real_node = zone_tree_fix_get(node, actx->zone->nodes);
	return adjust_cb_nsec3_pointer(real_node, actx);
}

int zone_adjust_incremental_update(zone_update_t *update, unsigned threads)
{
	int ret = zone_contents_load_nsec3param(update->new_cont);
	if (ret != KNOT_EOK) {
		return ret;
	}
	bool nsec3change = zone_update_changed_nsec3param(update);
	adjust_ctx_t ctx = { update->new_cont, update->a_ctx->adjust_ptrs, nsec3change };

	ret = zone_adjust_contents(update->new_cont, adjust_cb_flags, adjust_cb_nsec3_flags,
	                           false, true, 1, update->a_ctx->adjust_ptrs);
	if (ret == KNOT_EOK) {
		if (nsec3change) {
			ret = zone_adjust_contents(update->new_cont, adjust_cb_nsec3_and_wildcard, NULL,
			                           false, false, threads, update->a_ctx->adjust_ptrs);
			if (ret == KNOT_EOK) {
				// just measure zone size
				ret = zone_adjust_update(update, adjust_cb_void, adjust_cb_void, true);
			}
		} else {
			ret = zone_adjust_update(update, adjust_cb_wildcard_nsec3, adjust_cb_void, true);
		}
	}
	if (ret == KNOT_EOK) {
		if (update->new_cont->adds_tree != NULL && !nsec3change) {
			ret = additionals_tree_update_from_binodes(
				update->new_cont->adds_tree,
				update->a_ctx->node_ptrs,
				update->new_cont
			);
		} else {
			additionals_tree_free(update->new_cont->adds_tree);
			ret = additionals_tree_from_zone(&update->new_cont->adds_tree, update->new_cont);
		}
	}
	if (ret == KNOT_EOK) {
		ret = additionals_reverse_apply_multi(
			update->new_cont->adds_tree,
			update->a_ctx->node_ptrs,
			adjust_additionals_cb,
			&ctx
		);
	}
	if (ret == KNOT_EOK) {
		ret = zone_adjust_update(update, adjust_cb_additionals, adjust_cb_void, false);
	}
	if (ret == KNOT_EOK) {
		if (!nsec3change) {
			ret = additionals_reverse_apply_multi(
				update->new_cont->adds_tree,
				update->a_ctx->nsec3_ptrs,
				adjust_point_to_nsec3_cb,
				&ctx
			);
		}
	}
	return ret;
}
