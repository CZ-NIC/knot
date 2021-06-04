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

#include "knot/zone/node.h"
#include "libknot/libknot.h"

void additional_clear(additional_t *additional)
{
	if (additional == NULL) {
		return;
	}

	free(additional->glues);
	free(additional);
}

bool additional_equal(additional_t *a, additional_t *b)
{
	if (a == NULL || b == NULL || a->count != b->count) {
		return false;
	}
	for (int i = 0; i < a->count; i++) {
		glue_t *ag = &a->glues[i], *bg = &b->glues[i];
		if (ag->ns_pos != bg->ns_pos || ag->optional != bg->optional ||
		    binode_first((zone_node_t *)ag->node) != binode_first((zone_node_t *)bg->node)) {
			return false;
		}
	}
	return true;
}

/*! \brief Clears allocated data in RRSet entry. */
static void rr_data_clear(struct rr_data *data, knot_mm_t *mm)
{
	knot_rdataset_clear(&data->rrs, mm);
	memset(data, 0, sizeof(*data));
}

/*! \brief Clears allocated data in RRSet entry. */
static int rr_data_from(const knot_rrset_t *rrset, struct rr_data *data, knot_mm_t *mm)
{
	int ret = knot_rdataset_copy(&data->rrs, &rrset->rrs, mm);
	if (ret != KNOT_EOK) {
		return ret;
	}
	data->ttl = rrset->ttl;
	data->type = rrset->type;
	data->additional = NULL;

	return KNOT_EOK;
}

/*! \brief Adds RRSet to node directly. */
static int add_rrset_no_merge(zone_node_t *node, const knot_rrset_t *rrset,
                              knot_mm_t *mm)
{
	if (node == NULL) {
		return KNOT_EINVAL;
	}

	const size_t prev_nlen = node->rrset_count * sizeof(struct rr_data);
	const size_t nlen = (node->rrset_count + 1) * sizeof(struct rr_data);
	void *p = mm_realloc(mm, node->rrs, nlen, prev_nlen);
	if (p == NULL) {
		return KNOT_ENOMEM;
	}
	node->rrs = p;

	// ensure rrsets are sorted by rrtype
	struct rr_data *insert_pos = node->rrs, *end = node->rrs + node->rrset_count;
	while (insert_pos != end && insert_pos->type < rrset->type) {
		insert_pos++;
	}
	memmove(insert_pos + 1, insert_pos, (uint8_t *)end - (uint8_t *)insert_pos);

	int ret = rr_data_from(rrset, insert_pos, mm);
	if (ret != KNOT_EOK) {
		return ret;
	}
	++node->rrset_count;

	return KNOT_EOK;
}

/*! \brief Checks if the added RR has the same TTL as the first RR in the node. */
static bool ttl_changed(struct rr_data *node_data, const knot_rrset_t *rrset)
{
	if (rrset->type == KNOT_RRTYPE_RRSIG || node_data->rrs.count == 0) {
		return false;
	}

	return rrset->ttl != node_data->ttl;
}

zone_node_t *node_new(const knot_dname_t *owner, bool binode, bool second, knot_mm_t *mm)
{
	zone_node_t *ret = mm_alloc(mm, (binode ? 2 : 1) * sizeof(zone_node_t));
	if (ret == NULL) {
		return NULL;
	}
	memset(ret, 0, sizeof(*ret));

	if (owner) {
		ret->owner = knot_dname_copy(owner, mm);
		if (ret->owner == NULL) {
			mm_free(mm, ret);
			return NULL;
		}
	}

	// Node is authoritative by default.
	ret->flags = NODE_FLAGS_AUTH;

	if (binode) {
		ret->flags |= NODE_FLAGS_BINODE;
		if (second) {
			ret->flags |= NODE_FLAGS_DELETED;
		}
		memcpy(ret + 1, ret, sizeof(*ret));
		(ret + 1)->flags ^= NODE_FLAGS_SECOND | NODE_FLAGS_DELETED;
	}

	return ret;
}

zone_node_t *binode_counterpart(zone_node_t *node)
{
	zone_node_t *counterpart = NULL;

	assert(node == NULL || (node->flags & NODE_FLAGS_BINODE) || !(node->flags & NODE_FLAGS_SECOND));
	if (node != NULL && (node->flags & NODE_FLAGS_BINODE)) {
		if ((node->flags & NODE_FLAGS_SECOND)) {
			counterpart = node - 1;
			assert(!(counterpart->flags & NODE_FLAGS_SECOND));
		} else {
			counterpart = node + 1;
			assert((counterpart->flags & NODE_FLAGS_SECOND));
		}
		assert((counterpart->flags & NODE_FLAGS_BINODE));
	}

	return counterpart;
}

void binode_unify(zone_node_t *node, bool free_deleted, knot_mm_t *mm)
{
	zone_node_t *counter = binode_counterpart(node);
	if (counter != NULL) {
		if (counter->rrs != node->rrs) {
			for (uint16_t i = 0; i < counter->rrset_count; ++i) {
				if (!binode_additional_shared(node, counter->rrs[i].type)) {
					additional_clear(counter->rrs[i].additional);
				}
				if (!binode_rdata_shared(node, counter->rrs[i].type)) {
					rr_data_clear(&counter->rrs[i], mm);
				}
			}
			mm_free(mm, counter->rrs);
		}
		if (counter->nsec3_wildcard_name != node->nsec3_wildcard_name) {
			free(counter->nsec3_wildcard_name);
		}
		if (!(counter->flags & NODE_FLAGS_NSEC3_NODE) && node->nsec3_hash != counter->nsec3_hash) {
			free(counter->nsec3_hash);
		}
		assert(((node->flags ^ counter->flags) & NODE_FLAGS_SECOND));
		memcpy(counter, node, sizeof(*counter));
		counter->flags ^= NODE_FLAGS_SECOND;

		if (free_deleted && (node->flags & NODE_FLAGS_DELETED)) {
			node_free(node, mm);
		}
	}
}

int binode_prepare_change(zone_node_t *node, knot_mm_t *mm)
{
	zone_node_t *counter = binode_counterpart(node);
	if (counter != NULL && counter->rrs == node->rrs && counter->rrs != NULL) {
		size_t rrlen = sizeof(struct rr_data) * counter->rrset_count;
		node->rrs = mm_alloc(mm, rrlen);
		if (node->rrs == NULL) {
			return KNOT_ENOMEM;
		}
		memcpy(node->rrs, counter->rrs, rrlen);
	}
	return KNOT_EOK;
}

bool binode_rdata_shared(zone_node_t *node, uint16_t type)
{
	if (node == NULL || !(node->flags & NODE_FLAGS_BINODE)) {
		return false;
	}
	zone_node_t *counterpart = ((node->flags & NODE_FLAGS_SECOND) ? node - 1 : node + 1);
	if (counterpart->rrs == node->rrs) {
		return true;
	}
	knot_rdataset_t *r1 = node_rdataset(node, type), *r2 = node_rdataset(counterpart, type);
	return (r1 != NULL && r2 != NULL && r1->rdata == r2->rdata);
}

static additional_t *node_type2addit(zone_node_t *node, uint16_t type)
{
	for (uint16_t i = 0; i < node->rrset_count; i++) {
		if (node->rrs[i].type == type) {
			return node->rrs[i].additional;
		}
	}
	return NULL;
}

bool binode_additional_shared(zone_node_t *node, uint16_t type)
{
	if (node == NULL || !(node->flags & NODE_FLAGS_BINODE)) {
		return false;
	}
	zone_node_t *counter = ((node->flags & NODE_FLAGS_SECOND) ? node - 1 : node + 1);
	if (counter->rrs == node->rrs) {
		return true;
	}
	additional_t *a1 = node_type2addit(node, type), *a2 = node_type2addit(counter, type);
	return (a1 == a2);
}

bool binode_additionals_unchanged(zone_node_t *node, zone_node_t *counterpart)
{
	if (node == NULL || counterpart == NULL) {
		return false;
	}
	if (counterpart->rrs == node->rrs) {
		return true;
	}
	for (int i = 0; i < node->rrset_count; i++) {
		struct rr_data *rr = &node->rrs[i];
		if (knot_rrtype_additional_needed(rr->type)) {
			knot_rdataset_t *counterr = node_rdataset(counterpart, rr->type);
			if (counterr == NULL || counterr->rdata != rr->rrs.rdata) {
				return false;
			}
		}
	}
	for (int i = 0; i < counterpart->rrset_count; i++) {
		struct rr_data *rr = &counterpart->rrs[i];
		if (knot_rrtype_additional_needed(rr->type)) {
			knot_rdataset_t *counterr = node_rdataset(node, rr->type);
			if (counterr == NULL || counterr->rdata != rr->rrs.rdata) {
				return false;
			}
		}
	}
	return true;
}

void node_free_rrsets(zone_node_t *node, knot_mm_t *mm)
{
	if (node == NULL) {
		return;
	}

	for (uint16_t i = 0; i < node->rrset_count; ++i) {
		additional_clear(node->rrs[i].additional);
		rr_data_clear(&node->rrs[i], mm);
	}

	mm_free(mm, node->rrs);
	node->rrs = NULL;
	node->rrset_count = 0;
}

void node_free(zone_node_t *node, knot_mm_t *mm)
{
	if (node == NULL) {
		return;
	}

	knot_dname_free(node->owner, mm);

	assert((node->flags & NODE_FLAGS_BINODE) || !(node->flags & NODE_FLAGS_SECOND));
	assert(binode_counterpart(node) == NULL ||
	       binode_counterpart(node)->nsec3_wildcard_name == node->nsec3_wildcard_name);

	free(node->nsec3_wildcard_name);
	if (!(node->flags & NODE_FLAGS_NSEC3_NODE)) {
		free(node->nsec3_hash);
	}

	if (node->rrs != NULL) {
		mm_free(mm, node->rrs);
	}

	mm_free(mm, binode_node(node, false));
}

int node_add_rrset(zone_node_t *node, const knot_rrset_t *rrset, knot_mm_t *mm)
{
	if (node == NULL || rrset == NULL) {
		return KNOT_EINVAL;
	}

	node->flags &= ~NODE_FLAGS_RRSIGS_VALID;

	for (uint16_t i = 0; i < node->rrset_count; ++i) {
		if (node->rrs[i].type == rrset->type) {
			struct rr_data *node_data = &node->rrs[i];
			const bool ttl_change = ttl_changed(node_data, rrset);
			if (ttl_change) {
				node_data->ttl = rrset->ttl;
			}

			int ret = knot_rdataset_merge(&node_data->rrs,
			                              &rrset->rrs, mm);
			if (ret != KNOT_EOK) {
				return ret;
			} else {
				return ttl_change ? KNOT_ETTL : KNOT_EOK;
			}
		}
	}

	// New RRSet (with one RR)
	return add_rrset_no_merge(node, rrset, mm);
}

void node_remove_rdataset(zone_node_t *node, uint16_t type)
{
	if (node == NULL) {
		return;
	}

	node->flags &= ~NODE_FLAGS_RRSIGS_VALID;

	for (int i = 0; i < node->rrset_count; ++i) {
		if (node->rrs[i].type == type) {
			if (!binode_additional_shared(node, type)) {
				additional_clear(node->rrs[i].additional);
			}
			if (!binode_rdata_shared(node, type)) {
				rr_data_clear(&node->rrs[i], NULL);
			}
			memmove(node->rrs + i, node->rrs + i + 1,
			        (node->rrset_count - i - 1) * sizeof(struct rr_data));
			--node->rrset_count;
			return;
		}
	}
}

int node_remove_rrset(zone_node_t *node, const knot_rrset_t *rrset, knot_mm_t *mm)
{
	if (node == NULL || rrset == NULL) {
		return KNOT_EINVAL;
	}

	knot_rdataset_t *node_rrs = node_rdataset(node, rrset->type);
	if (node_rrs == NULL) {
		return KNOT_ENOENT;
	}

	node->flags &= ~NODE_FLAGS_RRSIGS_VALID;

	int ret = knot_rdataset_subtract(node_rrs, &rrset->rrs, mm);
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (node_rrs->count == 0) {
		node_remove_rdataset(node, rrset->type);
	}

	return KNOT_EOK;
}

knot_rrset_t *node_create_rrset(const zone_node_t *node, uint16_t type)
{
	if (node == NULL) {
		return NULL;
	}

	for (uint16_t i = 0; i < node->rrset_count; ++i) {
		if (node->rrs[i].type == type) {
			knot_rrset_t rrset = node_rrset_at(node, i);
			return knot_rrset_copy(&rrset, NULL);
		}
	}

	return NULL;
}

knot_rdataset_t *node_rdataset(const zone_node_t *node, uint16_t type)
{
	if (node == NULL) {
		return NULL;
	}

	for (uint16_t i = 0; i < node->rrset_count; ++i) {
		if (node->rrs[i].type == type) {
			return &node->rrs[i].rrs;
		}
	}

	return NULL;
}

bool node_rrtype_is_signed(const zone_node_t *node, uint16_t type)
{
	if (node == NULL) {
		return false;
	}

	const knot_rdataset_t *rrsigs = node_rdataset(node, KNOT_RRTYPE_RRSIG);
	if (rrsigs == NULL) {
		return false;
	}

	uint16_t rrsigs_rdata_count = rrsigs->count;
	knot_rdata_t *rrsig = rrsigs->rdata;
	for (uint16_t i = 0; i < rrsigs_rdata_count; ++i) {
		if (knot_rrsig_type_covered(rrsig) == type) {
			return true;
		}
		rrsig = knot_rdataset_next(rrsig);
	}

	return false;
}

bool node_bitmap_equal(const zone_node_t *a, const zone_node_t *b)
{
	if (a == NULL || b == NULL || a->rrset_count != b->rrset_count) {
		return false;
	}

	uint16_t i;
	// heuristics: try if they are equal including order
	for (i = 0; i < a->rrset_count; i++) {
		if (a->rrs[i].type != b->rrs[i].type) {
			break;
		}
	}
	if (i == a->rrset_count) {
		return true;
	}

	for (i = 0; i < a->rrset_count; i++) {
		if (node_rdataset(b, a->rrs[i].type) == NULL) {
			return false;
		}
	}
	return true;
}
