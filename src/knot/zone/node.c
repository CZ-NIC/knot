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

#include <stdlib.h>
#include <assert.h>
#include <stdio.h>

#include <urcu.h>

#include "libknot/common.h"
#include "knot/zone/node.h"
#include "libknot/rrset.h"
#include "libknot/rr.h"
#include "libknot/rdata.h"
#include "common/descriptor.h"
#include "common/debug.h"
#include "common/mempattern.h"

/*----------------------------------------------------------------------------*/
/* Non-API functions                                                          */
/*----------------------------------------------------------------------------*/
/*!
 * \brief Sets the given flag to node's flags.
 *
 * \param node Node to set the flag in.
 * \param flag Flag to set.
 */
static inline void knot_node_flags_set(knot_node_t *node, uint8_t flag)
{
	node->flags |= flag;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Returns the given flag from node's flags.
 *
 * \param node Node to set the flag in.
 * \param flag Flag to retrieve.
 *
 * \return A byte with only the given flag set if it was set in \a node.
 */
static inline uint8_t knot_node_flags_get(const knot_node_t *node, uint8_t flag)
{
	return node->flags & flag;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Clears the given flag in node's flags.
 *
 * \param node Node to clear the flag in.
 * \param flag Flag to clear.
 */
static inline void knot_node_flags_clear(knot_node_t *node, uint8_t flag)
{
	node->flags &= ~flag;
}

void rr_data_clear(struct rr_data *data, mm_ctx_t *mm)
{
	knot_rrs_clear(&data->rrs, mm);
	mm_free(mm, data->additional);
}

int rr_data_from(const knot_rrset_t *rrset, struct rr_data *data, mm_ctx_t *mm)
{
	int ret = knot_rrs_copy(&data->rrs, &rrset->rrs, mm);
	if (ret != KNOT_EOK) {
		return ret;
	}
	data->type = rrset->type;
	if (rrset->additional) {
		data->additional = mm_alloc(mm, data->rrs.rr_count * sizeof(void *));
		if (data->additional == NULL) {
			ERR_ALLOC_FAILED;
			knot_rrs_clear(&data->rrs, mm);
			return ret;
		}
		memcpy(data->additional, rrset->additional,
		       data->rrs.rr_count * sizeof(void *));
	} else {
		data->additional = NULL;
	}
	return KNOT_EOK;
}

static knot_rrset_t *rrset_from_rr_data(const knot_node_t *n, size_t pos,
                                        mm_ctx_t *mm)
{
	struct rr_data data = n->rrs[pos];
	knot_dname_t *dname_copy = knot_dname_copy(n->owner);
	if (dname_copy == NULL) {
		return NULL;
	}
	knot_rrset_t *rrset = knot_rrset_new(dname_copy, data.type, KNOT_CLASS_IN, mm);
	if (rrset == NULL) {
		knot_dname_free(&dname_copy);
		return NULL;
	}

	int ret = knot_rrs_copy(&rrset->rrs, &data.rrs, mm);
	if (ret != KNOT_EOK) {
		knot_rrset_free(&rrset, mm);
		return NULL;
	}
	
	if (data.additional) {
		size_t alloc_size = data.rrs.rr_count * sizeof(knot_node_t *);
		rrset->additional = mm_alloc(mm, alloc_size);
		if (rrset->additional == NULL) {
			knot_rrset_free(&rrset, mm);
			return NULL;
		}
		memcpy(rrset->additional, data.additional, alloc_size);
	}

	return rrset;
}

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

knot_node_t *knot_node_new(const knot_dname_t *owner, knot_node_t *parent,
                           uint8_t flags)
{
	knot_node_t *ret = (knot_node_t *)calloc(1, sizeof(knot_node_t));
	if (ret == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	/*! \todo This is inconsistent: knot_rrset_new() does not copy owner.
	 *        Either copy in all _new() functions, or in none. I vote for
	 *        the former, as it should be responsibility of the caller to
	 *        do the copying (or not if he decides to do so).
	 */
	if (owner) {
		ret->owner = knot_dname_copy(owner);
	}

	knot_node_set_parent(ret, parent);
	ret->rrs = NULL;
	ret->flags = flags;

	assert(ret->children == 0);

	return ret;
}

int knot_node_add_rrset_no_merge(knot_node_t *node, knot_rrset_t *rrset)
{
	if (node == NULL) {
		return KNOT_EINVAL;
	}

	size_t nlen = (node->rrset_count + 1) * sizeof(struct rr_data);
	void *p = realloc(node->rrs, nlen);
	if (p == NULL) {
		return KNOT_ENOMEM;
	}
	node->rrs = p;
	int ret = rr_data_from(rrset, node->rrs + node->rrset_count, NULL);
	if (ret != KNOT_EOK) {
		return ret;
	}
	++node->rrset_count;

	return KNOT_EOK;
}

int knot_node_add_rrset_replace(knot_node_t *node, knot_rrset_t *rrset)
{
	if (node == NULL) {
		return KNOT_EINVAL;
	}

	for (uint16_t i = 0; i < node->rrset_count; ++i) {
		if (node->rrs[i].type == rrset->type) {
			int ret = rr_data_from(rrset, &node->rrs[i], NULL);
			if (ret != KNOT_EOK) {
				return ret;
			}
		}
	}

	return knot_node_add_rrset_no_merge(node, rrset);
}

int knot_node_add_rrset(knot_node_t *node, knot_rrset_t *rrset,
                        knot_rrset_t **out_rrset)
{
	if (node == NULL) {
		return KNOT_EINVAL;
	}

	for (uint16_t i = 0; i < node->rrset_count; ++i) {
		if (node->rrs[i].type == rrset->type) {
			// TODO this is obviously a workaround
			knot_rrset_t *node_rrset = rrset_from_rr_data(node, i, NULL);
			if (node_rrset == NULL) {
				return KNOT_ENOMEM;
			}
			int merged, deleted_rrs;
			int ret = knot_rrset_merge_sort(node_rrset,
			                                rrset, &merged,
			                                &deleted_rrs, NULL);
			if (ret != KNOT_EOK) {
				knot_rrset_free(&node_rrset, NULL);
				return ret;
			} else {
				rr_data_clear(&node->rrs[i], NULL);
				rr_data_from(node_rrset, &node->rrs[i], NULL);
				knot_rrset_free(&node_rrset, NULL);
				if (merged || deleted_rrs) {
					return 1;
				} else {
					return 0;
				}
			}
		}
	}

	// New RRSet (with one RR)
	return knot_node_add_rrset_no_merge(node, rrset);
}

/*----------------------------------------------------------------------------*/

const knot_rrs_t *knot_node_rrs(const knot_node_t *node, uint16_t type)
{
	return (const knot_rrs_t *)knot_node_get_rrs(node, type);
}

knot_rrs_t *knot_node_get_rrs(const knot_node_t *node, uint16_t type)
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

/*----------------------------------------------------------------------------*/

knot_rrset_t *knot_node_create_rrset(const knot_node_t *node, uint16_t type)
{
	if (node == NULL) {
		return NULL;
	}

	for (uint16_t i = 0; i < node->rrset_count; ++i) {
		if (node->rrs[i].type == type) {
			return rrset_from_rr_data(node, i, NULL);
		}
	}

	return NULL;
}

/*----------------------------------------------------------------------------*/

knot_rrset_t *knot_node_remove_rrset(knot_node_t *node, uint16_t type)
{
	if (node == NULL) {
		return NULL;
	}

	for (int i = 0; i < node->rrset_count; ++i) {
		if (node->rrs[i].type == type) {
			knot_rrset_t *ret = rrset_from_rr_data(node, i, NULL);
			memmove(node->rrs + i, node->rrs + i + 1, (node->rrset_count - i - 1) * sizeof(struct rr_data));
			--node->rrset_count;
			return ret;
		}
	}

	return NULL;
}

/*----------------------------------------------------------------------------*/

short knot_node_rrset_count(const knot_node_t *node)
{
	if (node == NULL) {
		return KNOT_EINVAL;
	}

	return node->rrset_count;
}

/*----------------------------------------------------------------------------*/

knot_rrset_t **knot_node_rrsets(const knot_node_t *node)
{
	if (node == NULL || node->rrset_count == 0) {
		return NULL;
	}

	size_t rrlen = node->rrset_count * sizeof(knot_rrset_t*);
	knot_rrset_t **cpy = malloc(rrlen);
	if (cpy != NULL) {
		for (int i = 0; i < node->rrset_count; ++i) {
			cpy[i] = rrset_from_rr_data(node, i, NULL);
			if (cpy[i] == NULL) {
				knot_node_free_rrset_array(node, cpy);
				return NULL;
			}
		}
	}

	return cpy;
}

/*----------------------------------------------------------------------------*/

const knot_node_t *knot_node_parent(const knot_node_t *node)
{
	if (node == NULL) {
		return NULL;
	}

	return knot_node_get_parent(node);
}

/*----------------------------------------------------------------------------*/

knot_node_t *knot_node_get_parent(const knot_node_t *node)
{
	if (node == NULL) {
		return NULL;
	}

	return node->parent;
}

/*----------------------------------------------------------------------------*/

void knot_node_set_parent(knot_node_t *node, knot_node_t *parent)
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

/*----------------------------------------------------------------------------*/

unsigned int knot_node_children(const knot_node_t *node)
{
	if (node == NULL) {
		return KNOT_EINVAL;
	}

	return node->children;
}

/*----------------------------------------------------------------------------*/

const knot_node_t *knot_node_previous(const knot_node_t *node)
{
	if (node == NULL) {
		return NULL;
	}

	return knot_node_get_previous(node);
}

/*----------------------------------------------------------------------------*/

knot_node_t *knot_node_get_previous(const knot_node_t *node)
{
	if (node == NULL) {
		return NULL;
	}

	return node->prev;
}

/*----------------------------------------------------------------------------*/

void knot_node_set_previous(knot_node_t *node, knot_node_t *prev)
{
	if (node == NULL) {
		return;
	}

	node->prev = prev;
}

/*----------------------------------------------------------------------------*/

knot_node_t *knot_node_get_nsec3_node(const knot_node_t *node)
{
	if (node == NULL) {
		return NULL;
	}

	return node->nsec3_node;
}

/*----------------------------------------------------------------------------*/

const knot_node_t *knot_node_nsec3_node(const knot_node_t *node)
{
	if (node == NULL) {
		return NULL;
	}

	return knot_node_get_nsec3_node(node);
}

/*----------------------------------------------------------------------------*/

void knot_node_set_nsec3_node(knot_node_t *node, knot_node_t *nsec3_node)
{
	if (node == NULL) {
		return;
	}

	node->nsec3_node = nsec3_node;
}

/*----------------------------------------------------------------------------*/

const knot_dname_t *knot_node_owner(const knot_node_t *node)
{
	if (node == NULL) {
		return NULL;
	}

	return node->owner;
}

/*----------------------------------------------------------------------------*/

knot_dname_t *knot_node_get_owner(const knot_node_t *node)
{
	return node->owner;
}

/*----------------------------------------------------------------------------*/

knot_node_t *knot_node_get_wildcard_child(const knot_node_t *node)
{
	if (node == NULL) {
		return NULL;
	}

	return node->wildcard_child;
}

/*----------------------------------------------------------------------------*/

void knot_node_set_wildcard_child(knot_node_t *node,
                                  knot_node_t *wildcard_child)
{
	if (node == NULL) {
		return;
	}

	node->wildcard_child = wildcard_child;
//	assert(wildcard_child->parent == node);
}

/*----------------------------------------------------------------------------*/

const knot_node_t *knot_node_wildcard_child(const knot_node_t *node)
{
	if (node == NULL) {
		return NULL;
	}

	return knot_node_get_wildcard_child(node);
}

/*----------------------------------------------------------------------------*/

const knot_node_t *knot_node_new_node(const knot_node_t *node)
{
	if (node == NULL) {
		return NULL;
	}

	return node->new_node;
}

/*----------------------------------------------------------------------------*/

knot_node_t *knot_node_get_new_node(const knot_node_t *node)
{
	if (node == NULL) {
		return NULL;
	}

	return node->new_node;
}

/*----------------------------------------------------------------------------*/

void knot_node_set_new_node(knot_node_t *node,
                              knot_node_t *new_node)
{
	if (node == NULL) {
		return;
	}

	node->new_node = new_node;
}

/*----------------------------------------------------------------------------*/

void knot_node_update_ref(knot_node_t **ref)
{
	if (*ref != NULL && (*ref)->new_node != NULL) {
		*ref = (*ref)->new_node;
	}
}

/*----------------------------------------------------------------------------*/

void knot_node_update_refs(knot_node_t *node)
{
	// reference to previous node
	knot_node_update_ref(&node->prev);
	// reference to parent
	knot_node_update_ref(&node->parent);
	// reference to wildcard child
	knot_node_update_ref(&node->wildcard_child);
	// reference to NSEC3 node
	knot_node_update_ref(&node->nsec3_node);
}

/*----------------------------------------------------------------------------*/

void knot_node_set_deleg_point(knot_node_t *node)
{
	if (node == NULL) {
		return;
	}

	knot_node_flags_set(node, KNOT_NODE_FLAGS_DELEG);
}

/*----------------------------------------------------------------------------*/

int knot_node_is_deleg_point(const knot_node_t *node)
{
	if (node == NULL) {
		return KNOT_EINVAL;
	}

	return knot_node_flags_get(node, KNOT_NODE_FLAGS_DELEG);
}

/*----------------------------------------------------------------------------*/

void knot_node_set_non_auth(knot_node_t *node)
{
	if (node == NULL) {
		return;
	}

	knot_node_flags_set(node, KNOT_NODE_FLAGS_NONAUTH);
}

/*----------------------------------------------------------------------------*/

int knot_node_is_non_auth(const knot_node_t *node)
{
	if (node == NULL) {
		return KNOT_EINVAL;
	}

	return knot_node_flags_get(node, KNOT_NODE_FLAGS_NONAUTH);
}

/*----------------------------------------------------------------------------*/

void knot_node_set_auth(knot_node_t *node)
{
	if (node == NULL) {
		return;
	}

	knot_node_flags_clear(node, KNOT_NODE_FLAGS_NONAUTH);
	knot_node_flags_clear(node, KNOT_NODE_FLAGS_DELEG);
}

/*----------------------------------------------------------------------------*/

int knot_node_is_auth(const knot_node_t *node)
{
	if (node == NULL) {
		return KNOT_EINVAL;
	}

	return (node->flags == 0);
}

/*----------------------------------------------------------------------------*/

int knot_node_is_empty(const knot_node_t *node)
{
	return knot_node_flags_get(node, KNOT_NODE_FLAGS_EMPTY);
}

/*----------------------------------------------------------------------------*/

void knot_node_set_empty(knot_node_t *node)
{
	knot_node_flags_set(node, KNOT_NODE_FLAGS_EMPTY);
}

/*----------------------------------------------------------------------------*/

void knot_node_clear_empty(knot_node_t *node)
{
	knot_node_flags_clear(node, KNOT_NODE_FLAGS_EMPTY);
}

/*----------------------------------------------------------------------------*/

int knot_node_is_removed_nsec(const knot_node_t *node)
{
	return knot_node_flags_get(node, KNOT_NODE_FLAGS_REMOVED_NSEC);
}

/*----------------------------------------------------------------------------*/

void knot_node_set_removed_nsec(knot_node_t *node)
{
	knot_node_flags_set(node, KNOT_NODE_FLAGS_REMOVED_NSEC);
}

/*----------------------------------------------------------------------------*/

void knot_node_clear_removed_nsec(knot_node_t *node)
{
	knot_node_flags_clear(node, KNOT_NODE_FLAGS_REMOVED_NSEC);
}

/*----------------------------------------------------------------------------*/

void knot_node_free_rrsets(knot_node_t *node)
{
	if (node == NULL) {
		return;
	}

	for (uint16_t i = 0; i < node->rrset_count; ++i) {
		knot_rrs_clear(&node->rrs[i].rrs, NULL);
	}
}

void knot_node_free_rrset_array(const knot_node_t *node, knot_rrset_t **rrsets)
{
	if (node == NULL) {
		return;
	}

	for (uint16_t i = 0; i < node->rrset_count; ++i) {
		knot_rrset_free(&rrsets[i], NULL);
	}

	free(rrsets);
}

/*----------------------------------------------------------------------------*/

void knot_node_free(knot_node_t **node)
{
	if (node == NULL || *node == NULL) {
		return;
	}

	dbg_node_detail("Freeing node: %p\n", *node);

	if ((*node)->rrs != NULL) {
		dbg_node_detail("Freeing RRSets.\n");
		free((*node)->rrs);
		(*node)->rrs = NULL;
		(*node)->rrset_count = 0;
	}

	knot_dname_free(&(*node)->owner);

	free(*node);
	*node = NULL;

	dbg_node_detail("Done.\n");
}

/*----------------------------------------------------------------------------*/

int knot_node_shallow_copy(const knot_node_t *from, knot_node_t **to)
{
	if (from == NULL || to == NULL) {
		return KNOT_EINVAL;
	}

	// create new node
	*to = knot_node_new(NULL, NULL, from->flags);
	if (*to == NULL) {
		return KNOT_ENOMEM;
	}

	// do not use the API function to set parent, so that children count
	// is not changed
	memcpy(*to, from, sizeof(knot_node_t));
	(*to)->owner = knot_dname_copy(from->owner);

	// copy RRSets
	size_t rrlen = sizeof(struct rr_data) * from->rrset_count;
	(*to)->rrs = malloc(rrlen);
	if ((*to)->rrs == NULL) {
		free(*to);
		*to = NULL;
		return KNOT_ENOMEM;
	}
	memcpy((*to)->rrs, from->rrs, rrlen);

	return KNOT_EOK;
}

bool knot_node_rrtype_is_signed(const knot_node_t *node, uint16_t type)
{
	if (node == NULL) {
		return false;
	}

	const knot_rrs_t *rrsigs = knot_node_rrs(node, KNOT_RRTYPE_RRSIG);
	if (rrsigs == NULL) {
		return false;
	}

	uint16_t rrsigs_rdata_count = knot_rrs_rr_count(rrsigs);
	for (uint16_t i = 0; i < rrsigs_rdata_count; ++i) {
		const uint16_t type_covered =
			knot_rrs_rrsig_type_covered(rrsigs, i);
		if (type_covered == type) {
			return true;
		}
	}

	return false;
}

bool knot_node_rrtype_exists(const knot_node_t *node, uint16_t type)
{
	return knot_node_rrs(node, type) != NULL;
}

static void clear_rrset(knot_rrset_t *rrset)
{
	rrset->owner = NULL;
	rrset->type = 0;
	rrset->rclass = KNOT_CLASS_IN;
	knot_rrs_clear(&rrset->rrs, NULL);
	rrset->additional = NULL;
}

void knot_node_fill_rrset(const knot_node_t *node, uint16_t type,
                          knot_rrset_t *rrset)
{
	if (node == NULL || rrset == NULL) {
		return;
	}
	bool hit = false;
	for (uint i = 0; i < node->rrset_count; ++i) {
		hit = node->rrs[i].type == type;
		if (hit) {
			rrset->owner = node->owner;
			rrset->type = type;
			rrset->rclass = KNOT_CLASS_IN;
			rrset->rrs = node->rrs[i].rrs;
			rrset->additional = NULL;
		}
	}
	if (!hit) {
		clear_rrset(rrset);
	}
}

void knot_node_fill_rrset_pos(const knot_node_t *node, size_t pos,
                              knot_rrset_t *rrset)
{
	if (node == NULL || pos >= node->rrset_count || rrset == NULL) {
		clear_rrset(rrset);
		return;
	}
	struct rr_data *rr_data = &node->rrs[pos];
	rrset->owner = node->owner;
	rrset->type = rr_data->type;
	rrset->rclass = KNOT_CLASS_IN;
	rrset->rrs = rr_data->rrs;
	rrset->additional = NULL;
}

