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

static void rr_data_clear(struct rr_data *data, mm_ctx_t *mm)
{
	knot_rrs_clear(&data->rrs, mm);
	free(data->additional);
}

static int rr_data_from(const knot_rrset_t *rrset, struct rr_data *data, mm_ctx_t *mm)
{
	int ret = knot_rrs_copy(&data->rrs, &rrset->rrs, mm);
	if (ret != KNOT_EOK) {
		return ret;
	}
	data->type = rrset->type;
	data->additional = NULL;

	return KNOT_EOK;
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
		ret->owner = knot_dname_copy(owner, NULL);
	}

	knot_node_set_parent(ret, parent);
	ret->rrs = NULL;
	ret->flags = flags;

	assert(ret->children == 0);

	return ret;
}

static int knot_node_add_rrset_no_merge(knot_node_t *node, const knot_rrset_t *rrset)
{
	if (node == NULL) {
		return KNOT_EINVAL;
	}

	const size_t nlen = (node->rrset_count + 1) * sizeof(struct rr_data);
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

int knot_node_add_rrset(knot_node_t *node, const knot_rrset_t *rrset,  bool *ttl_err)
{
	if (node == NULL || rrset == NULL) {
		return KNOT_EINVAL;
	}

	for (uint16_t i = 0; i < node->rrset_count; ++i) {
		if (node->rrs[i].type == rrset->type) {
			struct rr_data *node_data = &node->rrs[i];

			/* Check if the added RR has the same TTL as the first
			 * RR in the RRSet.
			 */
			knot_rr_t *first = knot_rrs_rr(&node_data->rrs, 0);
			uint32_t inserted_ttl = knot_rrset_rr_ttl(rrset, 0);
			if (ttl_err && rrset->type != KNOT_RRTYPE_RRSIG &&
			    inserted_ttl != knot_rr_ttl(first)) {
				*ttl_err = true;
			}

			return knot_rrs_merge(&node_data->rrs, &rrset->rrs, NULL);
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
			knot_rrset_t rrset = knot_node_rrset_at(node, i);
			return knot_rrset_copy(&rrset, NULL);
		}
	}

	return NULL;
}

/*----------------------------------------------------------------------------*/

void knot_node_remove_rrset(knot_node_t *node, uint16_t type)
{
	if (node == NULL) {
		return;
	}

	for (int i = 0; i < node->rrset_count; ++i) {
		if (node->rrs[i].type == type) {
			memmove(node->rrs + i, node->rrs + i + 1, (node->rrset_count - i - 1) * sizeof(struct rr_data));
			--node->rrset_count;
			return;
		}
	}

	return;
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

void knot_node_set_wildcard_child(knot_node_t *node)
{
	if (node == NULL) {
		return;
	}

	knot_node_flags_set(node, KNOT_NODE_FLAGS_WILDCARD_CHILD);
}

/*----------------------------------------------------------------------------*/

int knot_node_has_wildcard_child(const knot_node_t *node)
{
	return knot_node_flags_get(node, KNOT_NODE_FLAGS_WILDCARD_CHILD);
}

/*----------------------------------------------------------------------------*/

void knot_node_clear_wildcard_child(knot_node_t *node)
{
	knot_node_flags_clear(node, KNOT_NODE_FLAGS_WILDCARD_CHILD);
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

void knot_node_set_apex(knot_node_t *node)
{
	if (node == NULL) {
		return;
	}

	knot_node_flags_set(node, KNOT_NODE_FLAGS_APEX);
}

/*----------------------------------------------------------------------------*/

int knot_node_is_apex(const knot_node_t *node)
{
	if (node == NULL) {
		return KNOT_EINVAL;
	}

	return knot_node_flags_get(node, KNOT_NODE_FLAGS_APEX);
}

/*----------------------------------------------------------------------------*/

void knot_node_free_rrsets(knot_node_t *node)
{
	if (node == NULL) {
		return;
	}

	for (uint16_t i = 0; i < node->rrset_count; ++i) {
		rr_data_clear(&node->rrs[i], NULL);
	}
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

	knot_dname_free(&(*node)->owner, NULL);

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
	memset(*to, 0, sizeof(knot_node_t));

	// Copy owner
	(*to)->owner = knot_dname_copy(from->owner, NULL);
	if ((*to)->owner == NULL) {
		free(*to);
		return KNOT_ENOMEM;
	}

	// copy RRSets
	(*to)->rrset_count = from->rrset_count;
	size_t rrlen = sizeof(struct rr_data) * from->rrset_count;
	(*to)->rrs = malloc(rrlen);
	if ((*to)->rrs == NULL) {
		knot_node_free(to);
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

	uint16_t rrsigs_rdata_count = rrsigs->rr_count;
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
