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

#include "knot/zone/node.h"
#include "libknot/libknot.h"
#include "libknot/rrtype/rrsig.h"
#include "contrib/mempattern.h"

/*! \brief Clears allocated data in RRSet entry. */
static void rr_data_clear(struct rr_data *data, knot_mm_t *mm)
{
	knot_rdataset_clear(&data->rrs, mm);
	free(data->additional);
}

/*! \brief Clears allocated data in RRSet entry. */
static int rr_data_from(const knot_rrset_t *rrset, struct rr_data *data, knot_mm_t *mm)
{
	int ret = knot_rdataset_copy(&data->rrs, &rrset->rrs, mm);
	if (ret != KNOT_EOK) {
		return ret;
	}
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
	int ret = rr_data_from(rrset, node->rrs + node->rrset_count, mm);
	if (ret != KNOT_EOK) {
		return ret;
	}
	++node->rrset_count;

	return KNOT_EOK;
}

/*! \brief Checks if the added RR has the same TTL as the first RR in the node. */
static bool ttl_error(struct rr_data *node_data, const knot_rrset_t *rrset)
{
	if (rrset->type == KNOT_RRTYPE_RRSIG || node_data->rrs.rr_count == 0) {
		return false;
	}

	const uint32_t inserted_ttl = knot_rdataset_ttl(&rrset->rrs);
	const uint32_t node_ttl = knot_rdataset_ttl(&node_data->rrs);
	// Return error if TTLs don't match.
	return inserted_ttl != node_ttl;
}

zone_node_t *node_new(const knot_dname_t *owner, knot_mm_t *mm)
{
	zone_node_t *ret = mm_alloc(mm, sizeof(zone_node_t));
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

	return ret;
}

void node_free_rrsets(zone_node_t *node, knot_mm_t *mm)
{
	if (node == NULL) {
		return;
	}

	for (uint16_t i = 0; i < node->rrset_count; ++i) {
		rr_data_clear(&node->rrs[i], mm);
	}

	mm_free(mm, node->rrs);
	node->rrs = NULL;
	node->rrset_count = 0;
}

void node_free(zone_node_t **node, knot_mm_t *mm)
{
	if (node == NULL || *node == NULL) {
		return;
	}

	if ((*node)->rrs != NULL) {
		mm_free(mm, (*node)->rrs);
	}

	knot_dname_free(&(*node)->owner, mm);

	mm_free(mm, *node);
	*node = NULL;
}

zone_node_t *node_shallow_copy(const zone_node_t *src, knot_mm_t *mm)
{
	if (src == NULL) {
		return NULL;
	}

	// create new node
	zone_node_t *dst = node_new(src->owner, mm);
	if (dst == NULL) {
		return NULL;
	}

	dst->flags = src->flags;

	// copy RRSets
	dst->rrset_count = src->rrset_count;
	size_t rrlen = sizeof(struct rr_data) * src->rrset_count;
	dst->rrs = mm_alloc(mm, rrlen);
	if (dst->rrs == NULL) {
		node_free(&dst, mm);
		return NULL;
	}
	memcpy(dst->rrs, src->rrs, rrlen);

	for (uint16_t i = 0; i < src->rrset_count; ++i) {
		// Clear additionals in the copy.
		dst->rrs[i].additional = NULL;
	}

	return dst;
}

int node_add_rrset(zone_node_t *node, const knot_rrset_t *rrset, knot_mm_t *mm)
{
	if (node == NULL || rrset == NULL) {
		return KNOT_EINVAL;
	}

	for (uint16_t i = 0; i < node->rrset_count; ++i) {
		if (node->rrs[i].type == rrset->type) {
			struct rr_data *node_data = &node->rrs[i];
			const bool ttl_err = ttl_error(node_data, rrset);
			if (ttl_err) {
				knot_rdataset_set_ttl(&node_data->rrs,
				                      knot_rdataset_ttl(&rrset->rrs));
			}

			int ret = knot_rdataset_merge(&node_data->rrs,
			                              &rrset->rrs, mm);
			if (ret != KNOT_EOK) {
				return ret;
			} else {
				return ttl_err ? KNOT_ETTL : KNOT_EOK;
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

	for (int i = 0; i < node->rrset_count; ++i) {
		if (node->rrs[i].type == type) {
			memmove(node->rrs + i, node->rrs + i + 1,
			        (node->rrset_count - i - 1) * sizeof(struct rr_data));
			--node->rrset_count;
			return;
		}
	}
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

void node_set_parent(zone_node_t *node, zone_node_t *parent)
{
	if (node == NULL || node->parent == parent) {
		return;
	}

	// decrease number of children of previous parent
	if (node->parent != NULL) {
		--node->parent->children;
	}
	// set the parent
	node->parent = parent;

	// increase the count of children of the new parent
	if (parent != NULL) {
		++parent->children;
	}
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

	uint16_t rrsigs_rdata_count = rrsigs->rr_count;
	for (uint16_t i = 0; i < rrsigs_rdata_count; ++i) {
		const uint16_t type_covered =
			knot_rrsig_type_covered(rrsigs, i);
		if (type_covered == type) {
			return true;
		}
	}

	return false;
}

bool node_rrtype_exists(const zone_node_t *node, uint16_t type)
{
	return node_rdataset(node, type) != NULL;
}

bool node_empty(const zone_node_t *node)
{
	return node == NULL || node->rrset_count == 0;
}
