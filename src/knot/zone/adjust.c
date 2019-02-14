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

int adjust_cb_flags(zone_node_t *node, const zone_contents_t *zone)
{
	zone_node_t *parent = node_parent(node);

	// check if this node is not a wildcard child of its parent
	if (knot_dname_is_wildcard(node->owner)) {
		parent->flags |= NODE_FLAGS_WILDCARD_CHILD;
	}

	// set flags (delegation point, non-authoritative)
	if (parent && (parent->flags & NODE_FLAGS_DELEG || parent->flags & NODE_FLAGS_NONAUTH)) {
		node->flags |= NODE_FLAGS_NONAUTH;
	} else if (node_rrtype_exists(node, KNOT_RRTYPE_NS) && node != zone->apex) {
		node->flags |= NODE_FLAGS_DELEG;
	} else {
		// Default.
		node->flags &= ~(NODE_FLAGS_DELEG | NODE_FLAGS_NONAUTH | NODE_FLAGS_WILDCARD_CHILD);
	}

	return KNOT_EOK; // always returns this value :)
}

int adjust_cb_point_to_nsec3(zone_node_t *node, const zone_contents_t *zone)
{
	if (!knot_is_nsec3_enabled(zone)) {
		node->nsec3_node = NULL;
		return KNOT_EOK;
	}
	if (node->nsec3_node != NULL) {
		// Optimization: this node has been shallow-copied from older state. Try using already known NSEC3 name.
		zone_node_t *candidate = zone_tree_get(zone->nsec3_nodes, node->nsec3_node->owner);
		if (candidate != NULL && (candidate->flags & NODE_FLAGS_IN_NSEC3_CHAIN)) {
			node->nsec3_node = candidate;
			return KNOT_EOK;
		}
	}
	uint8_t nsec3_name[KNOT_DNAME_MAXLEN];
	int ret = knot_create_nsec3_owner(nsec3_name, sizeof(nsec3_name), node->owner,
	                                  zone->apex->owner, &zone->nsec3_params);
	if (ret == KNOT_EOK) {
		node->nsec3_node = zone_tree_get(zone->nsec3_nodes, nsec3_name);
	}
	return ret;
}

int adjust_cb_wildcard_nsec3(zone_node_t *node, const zone_contents_t *zone)
{
	free(node->nsec3_wildcard_name);
	node->nsec3_wildcard_name = NULL;
	if (!knot_is_nsec3_enabled(zone)) {
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
	uint16_t rdcount = rrs->count;

	uint16_t mandatory_count = 0;
	uint16_t others_count = 0;
	glue_t mandatory[rdcount];
	glue_t others[rdcount];

	/* Scan new additional nodes. */
	for (uint16_t i = 0; i < rdcount; i++) {
		knot_rdata_t *rdata = knot_rdataset_at(rrs, i);
		const knot_dname_t *dname = knot_rdata_name(rdata, rr_data->type);
		const zone_node_t *node = NULL;

		if (!zone_contents_find_node_or_wildcard(zone, dname, &node)) {
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
		ret = adjust_cb_point_to_nsec3(node, zone);
	}
	return ret;
}

int adjust_cb_nsec3_and_additionals(zone_node_t *node, const zone_contents_t *zone)
{
	int ret = adjust_cb_point_to_nsec3(node, zone);
	if (ret == KNOT_EOK) {
		ret = adjust_cb_wildcard_nsec3(node, zone);
	}
	if (ret == KNOT_EOK) {
		ret = adjust_cb_additionals(node, zone);
	}
	return ret;
}

static int adjust_cb_nsec3_and_additionals2(zone_node_t *node, const zone_contents_t *zone)
{
	int ret = adjust_cb_point_to_nsec3(node, zone);
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
	size_t zone_size;
	uint32_t zone_max_ttl;
	adjust_cb_t adjust_cb;
	bool adjust_prevs;
	bool measure_size;
} zone_adjust_arg_t;

static int adjust_single(zone_node_t *node, void *data)
{
	assert(node != NULL);
	assert(data != NULL);

	if ((node->flags & NODE_FLAGS_DELETED)) {
		return KNOT_EOK;
	}

	zone_adjust_arg_t *args = (zone_adjust_arg_t *)data;

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

	if (args->measure_size) {
		node_size(node, &args->zone_size);
	}
	node_max_ttl(node, &args->zone_max_ttl);

	return args->adjust_cb(node, args->zone);
}

static int zone_adjust_tree(zone_tree_t *tree, const zone_contents_t *zone, adjust_cb_t adjust_cb,
                            size_t *tree_size, uint32_t *tree_max_ttl, bool adjust_prevs, bool measure_size)
{
	if (zone_tree_is_empty(tree)) {
		return KNOT_EOK;
	}

	zone_adjust_arg_t arg = {
		.zone = zone,
		.adjust_cb = adjust_cb,
		.adjust_prevs = adjust_prevs,
		.measure_size = measure_size,
	};

	int ret = zone_tree_apply(tree, adjust_single, &arg);
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (adjust_prevs && arg.first_node != NULL) {
		arg.first_node->prev = arg.previous_node;
	}

	if (tree_size != NULL) {
		*tree_size = arg.zone_size;
	}
	if (tree_max_ttl != NULL) {
		*tree_max_ttl = arg.zone_max_ttl;
	}
	return KNOT_EOK;
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

int zone_adjust_contents(zone_contents_t *zone, adjust_cb_t nodes_cb, adjust_cb_t nsec3_cb, bool measure_size)
{
	int ret = load_nsec3param(zone);
	if (ret != KNOT_EOK) {
		log_zone_error(zone->apex->owner,
		               "failed to load NSEC3 parameters (%s)",
		               knot_strerror(ret));
		return ret;
	}
	zone->dnssec = node_rrtype_is_signed(zone->apex, KNOT_RRTYPE_SOA);

	size_t nodes_size = 0, nsec3_size = 0;
	uint32_t nodes_max_ttl = 0, nsec3_max_ttl = 0;

	if (nsec3_cb != NULL) {
		ret = zone_adjust_tree(zone->nsec3_nodes, zone, nsec3_cb, &nsec3_size, &nsec3_max_ttl, true, measure_size && (nodes_cb != NULL));
	}
	if (ret == KNOT_EOK && nodes_cb != NULL) {
		ret = zone_adjust_tree(zone->nodes, zone, nodes_cb, &nodes_size, &nodes_max_ttl, true, measure_size);
	}
	if (ret == KNOT_EOK && nodes_cb != NULL && nsec3_cb != NULL) {
		zone->size = nodes_size + nsec3_size;
		zone->max_ttl = MAX(nodes_max_ttl, nsec3_max_ttl);
	}
	return ret;
}

int zone_adjust_update(zone_update_t *update, adjust_cb_t nodes_cb, adjust_cb_t nsec3_cb)
{
	int ret = KNOT_EOK;
	if (nsec3_cb != NULL) {
		ret = zone_adjust_tree(update->a_ctx->nsec3_ptrs, update->new_cont, nsec3_cb, NULL, NULL, false, false);
	}
	if (ret == KNOT_EOK && nodes_cb != NULL) {
		ret = zone_adjust_tree(update->a_ctx->node_ptrs, update->new_cont, nodes_cb, NULL, NULL, false, false);
	}
	return ret;
}

int zone_adjust_full(zone_contents_t *zone)
{
	int ret = zone_adjust_contents(zone, adjust_cb_flags, adjust_cb_nsec3_flags, true);
	if (ret == KNOT_EOK) {
		ret = zone_adjust_contents(zone, adjust_cb_nsec3_and_additionals, NULL, false);
	}
	return ret;
}

int zone_adjust_incremental_update(zone_update_t *update)
{
	int ret = zone_adjust_contents(update->new_cont, adjust_cb_flags, adjust_cb_nsec3_flags, true);
	if (ret == KNOT_EOK) {
		ret = zone_adjust_contents(update->new_cont, adjust_cb_nsec3_and_additionals2, NULL, false);
	}
	if (ret == KNOT_EOK) {
		ret = zone_adjust_update(update, adjust_cb_wildcard_nsec3, NULL);
	}
	return ret;
}
