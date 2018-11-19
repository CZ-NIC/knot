/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "contrib/macros.h"
#include "knot/common/log.h"
#include "knot/dnssec/zone-nsec.h"

int zone_adjust_node_pointers(zone_node_t *node, const zone_contents_t *zone) // node must be already in zone!
{
	// clear Removed NSEC flag so that no relicts remain
	node->flags &= ~NODE_FLAGS_REMOVED_NSEC;

	// check if this node is not a wildcard child of its parent
	if (knot_dname_is_wildcard(node->owner)) {
		assert(node->parent != NULL);
		node->parent->flags |= NODE_FLAGS_WILDCARD_CHILD;
	}

	// set flags (delegation point, non-authoritative)
	if (node->parent &&
	    (node->parent->flags & NODE_FLAGS_DELEG ||
	     node->parent->flags & NODE_FLAGS_NONAUTH)) {
		node->flags |= NODE_FLAGS_NONAUTH;
	} else if (node_rrtype_exists(node, KNOT_RRTYPE_NS) && node != zone->apex) {
		node->flags |= NODE_FLAGS_DELEG;
	} else {
		// Default.
		node->flags = NODE_FLAGS_AUTH;
	}

	return KNOT_EOK; // always returns this value :)
}

int zone_adjust_nsec3_pointers(zone_node_t *node, const zone_contents_t *zone) // node must be already in zone!
{
	if (!knot_is_nsec3_enabled(zone)) {
		node->nsec3_node = NULL;
		return KNOT_EOK;
	}
	const zone_node_t *ignored;
	node->nsec3_wildcard_prev = NULL;
	uint8_t nsec3_name[KNOT_DNAME_MAXLEN];
	int ret = knot_create_nsec3_owner(nsec3_name, sizeof(nsec3_name), node->owner,
	                                  zone->apex->owner, &zone->nsec3_params);
	if (ret == KNOT_EOK) {
		node->nsec3_node = zone_tree_get(zone->nsec3_nodes, nsec3_name);

		// Connect to NSEC3 node proving nonexistence of wildcard.
		size_t wildcard_size = knot_dname_size(node->owner) + 2;
		if (wildcard_size <= KNOT_DNAME_MAXLEN) {
			assert(wildcard_size > 2);
			knot_dname_t wildcard[wildcard_size];
			memcpy(wildcard, "\x01""*", 2);
			memcpy(wildcard + 2, node->owner, wildcard_size - 2);
			ret = zone_contents_find_nsec3_for_name(zone, wildcard, &ignored,
			                                        (const zone_node_t **)&node->nsec3_wildcard_prev);
			if (ret == ZONE_NAME_FOUND) {
				node->nsec3_wildcard_prev = NULL;
				ret = KNOT_EOK;
			}
		}
	}
	return ret;
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

int zone_adjust_nsec3_chain(zone_node_t *node, const zone_contents_t *zone)
{
	// check if this node belongs to correct chain
	const knot_rdataset_t *nsec3_rrs = node_rdataset(node, KNOT_RRTYPE_NSEC3);
	for (uint16_t i = 0; nsec3_rrs != NULL && i < nsec3_rrs->count; i++) {
		if (nsec3_params_match(nsec3_rrs, &zone->nsec3_params, i)) {
			node->flags |= NODE_FLAGS_IN_NSEC3_CHAIN;
		}
	}
	return KNOT_EOK;
}

/*! \brief Link pointers to additional nodes for this RRSet. */
static int discover_additionals(const knot_dname_t *owner, struct rr_data *rr_data,
                                const zone_contents_t *zone)
{
	assert(rr_data != NULL);

	/* Drop possible previous additional nodes. */
	additional_clear(rr_data->additional);
	rr_data->additional = NULL;

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
		const zone_node_t *node = NULL, *encloser = NULL;

		/* Try to find node for the dname in the RDATA. */
		zone_contents_find_dname(zone, dname, &node, &encloser, NULL);
		if (node == NULL && encloser != NULL
		    && (encloser->flags & NODE_FLAGS_WILDCARD_CHILD)) {
			/* Find wildcard child in the zone. */
			node = zone_contents_find_wildcard_child(zone, encloser);
			assert(node != NULL);
		}

		if (node == NULL) {
			continue;
		}

		glue_t *glue;
		if ((node->flags & (NODE_FLAGS_DELEG | NODE_FLAGS_NONAUTH)) &&
		    rr_data->type == KNOT_RRTYPE_NS &&
		    knot_dname_in_bailiwick(node->owner, owner) >= 0) {
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
	if (total_count > 0) {
		rr_data->additional = malloc(sizeof(additional_t));
		if (rr_data->additional == NULL) {
			return KNOT_ENOMEM;
		}
		rr_data->additional->count = total_count;

		size_t size = total_count * sizeof(glue_t);
		rr_data->additional->glues = malloc(size);
		if (rr_data->additional->glues == NULL) {
			free(rr_data->additional);
			return KNOT_ENOMEM;
		}

		size_t mandatory_size = mandatory_count * sizeof(glue_t);
		memcpy(rr_data->additional->glues, mandatory, mandatory_size);
		memcpy(rr_data->additional->glues + mandatory_count, others,
		       size - mandatory_size);
	}

	return KNOT_EOK;
}

int zone_adjust_additionals(zone_node_t *node, const zone_contents_t *zone)
{
	/* Lookup additional records for specific nodes. */
	for(uint16_t i = 0; i < node->rrset_count; ++i) {
		struct rr_data *rr_data = &node->rrs[i];
		if (knot_rrtype_additional_needed(rr_data->type)) {
			int ret = discover_additionals(node->owner, rr_data, zone);
			if (ret != KNOT_EOK) {
				return ret;
			}
		}
	}
	return KNOT_EOK;
}

int zone_adjust_normal(zone_node_t *node, const zone_contents_t *zone)
{
	int ret = zone_adjust_nsec3_pointers(node, zone);
	if (ret == KNOT_EOK) {
		ret = zone_adjust_node_pointers(node, zone);
	}
	if (ret == KNOT_EOK) {
		ret = zone_adjust_additionals(node, zone);
	}
	return ret;
}

int zone_adjust_pointers(zone_node_t *node, const zone_contents_t *zone)
{
	int ret = zone_adjust_node_pointers(node, zone);
	if (ret == KNOT_EOK) {
		ret = zone_adjust_additionals(node, zone);
	}
	return ret;
}

typedef struct {
	zone_node_t *first_node;
	const zone_contents_t *zone;
	zone_node_t *previous_node;
	size_t zone_size;
	uint32_t zone_max_ttl;
	adjust_cb_t adjust_cb;
} zone_adjust_arg_t;

static int adjust_single(zone_node_t **tnode, void *data)
{
	assert(tnode != NULL);
	assert(data != NULL);

	zone_adjust_arg_t *args = (zone_adjust_arg_t *)data;
	zone_node_t *node = *tnode;

	// remember first node
	if (args->first_node == NULL) {
		args->first_node = node;
	}

	// set pointer to previous node
	node->prev = args->previous_node;

	// update remembered previous pointer only if authoritative
	if (!(node->flags & NODE_FLAGS_NONAUTH) && node->rrset_count > 0) {
		args->previous_node = node;
	}

	node_size(node, &args->zone_size);
	node_max_ttl(node, &args->zone_max_ttl);

	return args->adjust_cb(node, args->zone);
}

static int zone_adjust_tree(zone_tree_t *tree, const zone_contents_t *zone, adjust_cb_t adjust_cb,
                            size_t *tree_size, uint32_t *tree_max_ttl)
{
	if (zone_tree_is_empty(tree)) {
		return KNOT_EOK;
	}

	zone_adjust_arg_t arg = { 0 };
	arg.zone = zone;
	arg.adjust_cb = adjust_cb;

	int ret = zone_tree_apply(tree, adjust_single, &arg);
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (arg.first_node != NULL) {
		arg.first_node->prev = arg.previous_node;
	}

	*tree_size = arg.zone_size;
	*tree_max_ttl = arg.zone_max_ttl;
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
	if (r != 0) {
		return KNOT_EMALF;
	}

	dnssec_nsec3_params_free(&contents->nsec3_params);
	contents->nsec3_params = new_params;
	return KNOT_EOK;
}

int zone_adjust_contents(zone_contents_t *zone, adjust_cb_t nodes_cb, adjust_cb_t nsec3_cb)
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

	ret = zone_adjust_tree(zone->nsec3_nodes, zone, nsec3_cb, &nsec3_size, &nsec3_max_ttl);
	if (ret == KNOT_EOK) {
		ret = zone_adjust_tree(zone->nodes, zone, nodes_cb, &nodes_size, &nodes_max_ttl);
	}
	if (ret == KNOT_EOK) {
		zone->size = nodes_size + nsec3_size;
		zone->max_ttl = MAX(nodes_max_ttl, nsec3_max_ttl);
	}
	return ret;
}
