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

#include "knot/zone/adjust.h"

#include "libdnssec/error.h"
#include "contrib/macros.h"
#include "knot/common/log.h"
#include "knot/dnssec/zone-nsec.h"
#include "knot/zone/adds_tree.h"
#include "knot/zone/measure.h"

int adjust_cb_flags(zone_node_t *node, const zone_contents_t *zone)
{
	zone_node_t *parent = node_parent(node);

	assert(!(node->flags & NODE_FLAGS_DELETED));

	// set flags (delegation point, non-authoritative)
	if (parent && (parent->flags & NODE_FLAGS_DELEG || parent->flags & NODE_FLAGS_NONAUTH)) {
		node->flags |= NODE_FLAGS_NONAUTH;
	} else if (node_rrtype_exists(node, KNOT_RRTYPE_NS) && node != zone->apex) {
		node->flags |= NODE_FLAGS_DELEG;
	} else {
		// Default.
		node->flags &= ~(NODE_FLAGS_DELEG | NODE_FLAGS_NONAUTH);
	}

	return KNOT_EOK; // always returns this value :)
}

int unadjust_cb_point_to_nsec3(zone_node_t *node, const zone_contents_t *zone)
{
	UNUSED(zone);
	// downgrade the NSEC3 node pointer to NSEC3 name
	if (node->flags & NODE_FLAGS_NSEC3_NODE) {
		node->nsec3_hash = knot_dname_copy(node->nsec3_node->owner, NULL);
		node->flags &= ~NODE_FLAGS_NSEC3_NODE;
	}
	return KNOT_EOK;
}

int adjust_cb_wildcard_nsec3(zone_node_t *node, const zone_contents_t *zone)
{
	if (!knot_is_nsec3_enabled(zone)) {
		node->nsec3_wildcard_name = NULL;
		return KNOT_EOK;
	}

	if (node->nsec3_wildcard_name != NULL) {
		return KNOT_EOK;
	}

	size_t wildcard_size = knot_dname_size(node->owner) + 2;
	size_t wildcard_nsec3 = zone_nsec3_name_len(zone);
	if (wildcard_size > KNOT_DNAME_MAXLEN) {
		return KNOT_EOK;
	}

	node->nsec3_wildcard_name = malloc(wildcard_nsec3);
	if (node->nsec3_wildcard_name == NULL) {
		return KNOT_ENOMEM;
	}
	assert(wildcard_size > 2);
	knot_dname_t wildcard[wildcard_size];
	memcpy(wildcard, "\x01""*", 2);
	memcpy(wildcard + 2, node->owner, wildcard_size - 2);
	return knot_create_nsec3_owner(node->nsec3_wildcard_name, wildcard_nsec3,
	                               wildcard, zone->apex->owner, &zone->nsec3_params);
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

int adjust_cb_nsec3_flags(zone_node_t *node, const zone_contents_t *zone)
{
	// check if this node belongs to correct chain
	node->flags &= ~NODE_FLAGS_IN_NSEC3_CHAIN;
	const knot_rdataset_t *nsec3_rrs = node_rdataset(node, KNOT_RRTYPE_NSEC3);
	for (uint16_t i = 0; nsec3_rrs != NULL && i < nsec3_rrs->count; i++) {
		if (nsec3_params_match(nsec3_rrs, &zone->nsec3_params, i)) {
			node->flags |= NODE_FLAGS_IN_NSEC3_CHAIN;
		}
	}
	return KNOT_EOK;
}

/*! \brief Link pointers to additional nodes for this RRSet. */
static int discover_additionals(zone_node_t *adjn, uint16_t rr_at,
                                const zone_contents_t *zone)
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

		if (!zone_contents_find_node_or_wildcard(zone, dname, &node)) {
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

int adjust_cb_additionals(zone_node_t *node, const zone_contents_t *zone)
{
	/* Lookup additional records for specific nodes. */
	for(uint16_t i = 0; i < node->rrset_count; ++i) {
		struct rr_data *rr_data = &node->rrs[i];
		if (knot_rrtype_additional_needed(rr_data->type)) {
			int ret = discover_additionals(node, i, zone);
			if (ret != KNOT_EOK) {
				return ret;
			}
		}
	}
	return KNOT_EOK;
}

int adjust_cb_flags_and_additionals(zone_node_t *node, const zone_contents_t *zone)
{
	int ret = adjust_cb_flags(node, zone);
	if (ret == KNOT_EOK) {
		ret = adjust_cb_additionals(node, zone);
	}
	return ret;
}

int adjust_cb_flags_and_nsec3(zone_node_t *node, const zone_contents_t *zone)
{
	int ret = adjust_cb_flags(node, zone);
	if (ret == KNOT_EOK) {
		ret = binode_fix_nsec3_pointer(node, zone);
	}
	return ret;
}

int adjust_cb_nsec3_and_additionals(zone_node_t *node, const zone_contents_t *zone)
{
	int ret = binode_fix_nsec3_pointer(node, zone);
	if (ret == KNOT_EOK) {
		ret = adjust_cb_wildcard_nsec3(node, zone);
	}
	if (ret == KNOT_EOK) {
		ret = adjust_cb_additionals(node, zone);
	}
	return ret;
}

int adjust_cb_void(zone_node_t *node, const zone_contents_t *zone)
{
	UNUSED(node);
	UNUSED(zone);
	return KNOT_EOK;
}

typedef struct {
	zone_node_t *first_node;
	const zone_contents_t *zone;
	zone_node_t *previous_node;
	adjust_cb_t adjust_cb;
	bool adjust_prevs;
	measure_t *m;
} zone_adjust_arg_t;

static int adjust_single(zone_node_t *node, void *data)
{
	assert(node != NULL);
	assert(data != NULL);

	zone_adjust_arg_t *args = (zone_adjust_arg_t *)data;

	knot_measure_node(node, args->m);

	if ((node->flags & NODE_FLAGS_DELETED)) {
		return KNOT_EOK;
	}

	// remember first node
	if (args->first_node == NULL) {
		args->first_node = node;
	}

	// set pointer to previous node
	if (args->adjust_prevs) {
		node->prev = args->previous_node;
	}

	// update remembered previous pointer only if authoritative
	if (!(node->flags & NODE_FLAGS_NONAUTH) && node->rrset_count > 0) {
		args->previous_node = node;
	}

	return args->adjust_cb(node, args->zone);
}

static int zone_adjust_tree(zone_tree_t *tree, const zone_contents_t *zone, adjust_cb_t adjust_cb,
                            bool adjust_prevs, measure_t *measure_ctx)
{
	if (zone_tree_is_empty(tree)) {
		return KNOT_EOK;
	}

	zone_adjust_arg_t arg = { 0 };
	arg.zone = zone;
	arg.adjust_cb = adjust_cb;
	arg.adjust_prevs = adjust_prevs;
	arg.m = measure_ctx;

	int ret = zone_tree_apply(tree, adjust_single, &arg);
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (adjust_prevs && arg.first_node != NULL) {
		arg.first_node->prev = arg.previous_node;
	}

	return KNOT_EOK;
}

int zone_adjust_contents(zone_contents_t *zone, adjust_cb_t nodes_cb, adjust_cb_t nsec3_cb, bool measure_zone)
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

	if (nsec3_cb != NULL) {
		ret = zone_adjust_tree(zone->nsec3_nodes, zone, nsec3_cb, true, &m);
	}
	if (ret == KNOT_EOK && nodes_cb != NULL) {
		ret = zone_adjust_tree(zone->nodes, zone, nodes_cb, true, &m);
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

	if (nsec3_cb != NULL) {
		ret = zone_adjust_tree(update->a_ctx->nsec3_ptrs, update->new_cont, nsec3_cb, false, &m);
	}
	if (ret == KNOT_EOK && nodes_cb != NULL) {
		ret = zone_adjust_tree(update->a_ctx->node_ptrs, update->new_cont, nodes_cb, false, &m);
	}
	if (ret == KNOT_EOK && measure_diff && nodes_cb != NULL && nsec3_cb != NULL) {
		knot_measure_finish_update(&m, update);
	}
	return ret;
}

int zone_adjust_full(zone_contents_t *zone)
{
	int ret = zone_adjust_contents(zone, adjust_cb_flags, adjust_cb_nsec3_flags, true);
	if (ret == KNOT_EOK) {
		ret = zone_adjust_contents(zone, adjust_cb_nsec3_and_additionals, NULL, false);
	}
	if (ret == KNOT_EOK) {
		additionals_tree_free(zone->adds_tree);
		ret = additionals_tree_from_zone(&zone->adds_tree, zone);
	}
	return ret;
}

static int adjust_additionals_cb(zone_node_t *node, void *ctx)
{
	const zone_contents_t *zone = ctx;
	zone_node_t *real_node = binode_node(node, (zone->nodes->flags & ZONE_TREE_BINO_SECOND));
	return adjust_cb_additionals(real_node, zone);
}

static int adjust_point_to_nsec3_cb(zone_node_t *node, void *ctx)
{
	const zone_contents_t *zone = ctx;
	zone_node_t *real_node = binode_node(node, (zone->nodes->flags & ZONE_TREE_BINO_SECOND));
	return binode_fix_nsec3_pointer(real_node, zone);
}

int zone_adjust_incremental_update(zone_update_t *update)
{
	int ret = zone_contents_load_nsec3param(update->new_cont);
	if (ret != KNOT_EOK) {
		return ret;
	}
	bool nsec3change = zone_update_changed_nsec3param(update);

	ret = zone_adjust_contents(update->new_cont, adjust_cb_flags, adjust_cb_nsec3_flags, false);
	if (ret == KNOT_EOK) {
		if (nsec3change) {
			ret = zone_adjust_contents(update->new_cont, adjust_cb_wildcard_nsec3, adjust_cb_void, false);
		} else {
			ret = zone_adjust_update(update, adjust_cb_wildcard_nsec3, adjust_cb_void, true);
		}
	}
	if (ret == KNOT_EOK) {
		ret = additionals_tree_update_from_binodes(
			update->new_cont->adds_tree,
			update->a_ctx->node_ptrs,
			update->new_cont
		);
	}
	if (ret == KNOT_EOK) {
		ret = additionals_reverse_apply_multi(
			update->new_cont->adds_tree,
			update->a_ctx->node_ptrs,
			adjust_additionals_cb,
			update->new_cont
		);
	}
	if (ret == KNOT_EOK) {
		if (nsec3change) {
			ret = zone_adjust_contents(update->new_cont, binode_fix_nsec3_pointer, adjust_cb_void, false);
		} else {
			ret = additionals_reverse_apply_multi(
				update->new_cont->adds_tree,
				update->a_ctx->nsec3_ptrs,
				adjust_point_to_nsec3_cb,
				update->new_cont
			);
		}
	}
	return ret;
}
