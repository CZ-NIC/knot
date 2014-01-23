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

#include <config.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>

#include <urcu.h>

#include "libknot/common.h"
#include "libknot/zone/node.h"
#include "libknot/rrset.h"
#include "common/descriptor.h"
#include "libknot/util/debug.h"

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
	ret->rrset_tree = NULL;
	ret->flags = flags;

	assert(ret->children == 0);

	return ret;
}


int knot_node_add_rrset_no_merge(knot_node_t *node, knot_rrset_t *rrset)
{
	if (node == NULL) {
		return KNOT_EINVAL;
	}

	size_t nlen = (node->rrset_count + 1) * sizeof(knot_rrset_t*);
	void *p = realloc(node->rrset_tree, nlen);
	if (p == NULL) {
		return KNOT_ENOMEM;
	}
	node->rrset_tree = p;
	node->rrset_tree[node->rrset_count] = rrset;
	++node->rrset_count;
	return KNOT_EOK;
}

int knot_node_add_rrset_replace(knot_node_t *node, knot_rrset_t *rrset)
{
	if (node == NULL) {
		return KNOT_EINVAL;
	}

	for (uint16_t i = 0; i < node->rrset_count; ++i) {
		if (node->rrset_tree[i]->type == rrset->type) {
		node->rrset_tree[i] = rrset;
		}
	}

	return knot_node_add_rrset_no_merge(node, rrset);
}

int knot_node_add_rrset(knot_node_t *node, knot_rrset_t *rrset)
{
	if (node == NULL) {
		return KNOT_EINVAL;
	}

	for (uint16_t i = 0; i < node->rrset_count; ++i) {
		if (node->rrset_tree[i]->type == rrset->type) {
			int merged, deleted_rrs;
			int ret = knot_rrset_merge_sort(node->rrset_tree[i],
			                                rrset, &merged,
			                                &deleted_rrs);
			if (ret != KNOT_EOK) {
				return ret;
			} else if (merged || deleted_rrs) {
				return 1;
			} else {
				return 0;
			}
		}
	}

	// New RRSet (with one RR)
	return knot_node_add_rrset_no_merge(node, rrset);
}

/*----------------------------------------------------------------------------*/

const knot_rrset_t *knot_node_rrset(const knot_node_t *node,
                                        uint16_t type)
{
	return knot_node_get_rrset(node, type);
}

/*----------------------------------------------------------------------------*/

knot_rrset_t *knot_node_get_rrset(const knot_node_t *node, uint16_t type)
{
	if (node == NULL) {
		return NULL;
	}

	knot_rrset_t **rrs = node->rrset_tree;
	for (uint16_t i = 0; i < node->rrset_count; ++i) {
		if (rrs[i]->type == type) {
			return rrs[i];
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

	uint16_t i = 0;
	knot_rrset_t *ret = NULL;
	knot_rrset_t **rrs = node->rrset_tree;
	for (; i < node->rrset_count && ret == NULL; ++i) {
		if (rrs[i]->type == type) {
			ret = rrs[i];
			memmove(rrs + i, rrs + i + 1, (node->rrset_count - i - 1) * sizeof(knot_rrset_t *));
			--node->rrset_count;
		}
	}

	return ret;
}

/*----------------------------------------------------------------------------*/

void knot_node_remove_all_rrsets(knot_node_t *node)
{
	if (node == NULL) {
		return;
	}

	// remove RRSets but do not delete them
	node->rrset_count = 0;
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

knot_rrset_t **knot_node_get_rrsets(const knot_node_t *node)
{
	if (node == NULL || node->rrset_count == 0) {
		return NULL;
	}

	size_t rrlen = node->rrset_count * sizeof(knot_rrset_t*);
	knot_rrset_t **cpy = malloc(rrlen);
	if (cpy != NULL) {
		memcpy(cpy, node->rrset_tree, rrlen);
	}

	return cpy;
}

/*----------------------------------------------------------------------------*/

const knot_rrset_t **knot_node_rrsets(const knot_node_t *node)
{
	if (node == NULL) {
		return NULL;
	}

	return (const knot_rrset_t **)knot_node_get_rrsets(node);
}

knot_rrset_t **knot_node_get_rrsets_no_copy(const knot_node_t *node)
{
	if (node == NULL) {
		return NULL;
	}

	return node->rrset_tree;
}

const knot_rrset_t **knot_node_rrsets_no_copy(const knot_node_t *node)
{
	return (const knot_rrset_t **)knot_node_get_rrsets_no_copy(node);
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

int knot_node_is_replaced_nsec(const knot_node_t *node)
{
	return knot_node_flags_get(node, KNOT_NODE_FLAGS_REPLACED_NSEC);
}

/*----------------------------------------------------------------------------*/

void knot_node_set_replaced_nsec(knot_node_t *node)
{
	knot_node_flags_set(node, KNOT_NODE_FLAGS_REPLACED_NSEC);
}

/*----------------------------------------------------------------------------*/

void knot_node_clear_replaced_nsec(knot_node_t *node)
{
	knot_node_flags_clear(node, KNOT_NODE_FLAGS_REPLACED_NSEC);
}

/*----------------------------------------------------------------------------*/

void knot_node_free_rrsets(knot_node_t *node)
{
	if (node == NULL) {
		return;
	}

	knot_rrset_t **rrs = node->rrset_tree;
	for (uint16_t i = 0; i < node->rrset_count; ++i) {
		knot_rrset_deep_free(&(rrs[i]), 1);
	}
}

/*----------------------------------------------------------------------------*/

void knot_node_free(knot_node_t **node)
{
	if (node == NULL || *node == NULL) {
		return;
	}

	dbg_node_detail("Freeing node: %p\n", *node);

	if ((*node)->rrset_tree != NULL) {
		dbg_node_detail("Freeing RRSets.\n");
		free((*node)->rrset_tree);
		(*node)->rrset_tree = NULL;
		(*node)->rrset_count = 0;
	}

	knot_dname_free(&(*node)->owner);

	free(*node);
	*node = NULL;

	dbg_node_detail("Done.\n");
}

/*----------------------------------------------------------------------------*/

int knot_node_compare(knot_node_t *node1, knot_node_t *node2)
{
	assert(node1 != NULL && node2 != NULL);

	return knot_dname_cmp(node1->owner, node2->owner);
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
	size_t rrlen = sizeof(knot_rrset_t*) * from->rrset_count;
	(*to)->rrset_tree = malloc(rrlen);
	if ((*to)->rrset_tree == NULL) {
		free(*to);
		*to = NULL;
		return KNOT_ENOMEM;
	}
	memcpy((*to)->rrset_tree, from->rrset_tree, rrlen);

	return KNOT_EOK;
}

