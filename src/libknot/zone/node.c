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

#include "common.h"
#include "zone/node.h"
#include "rrset.h"
#include "util/error.h"
#include "common/skip-list.h"
#include "common/tree.h"
#include "util/debug.h"

/*----------------------------------------------------------------------------*/
/* Non-API functions                                                          */
/*----------------------------------------------------------------------------*/
/*!
 * \brief Returns the delegation point flag
 *
 * \param flags Flags to retrieve the flag from.
 *
 * \return A byte with only the delegation point flag set if it was set in
 *         \a flags.
 */
static inline uint8_t knot_node_flags_get_deleg(uint8_t flags)
{
	return flags & KNOT_NODE_FLAGS_DELEG;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Sets the delegation point flag.
 *
 * \param flags Flags to set the flag in.
 */
static inline void knot_node_flags_set_deleg(uint8_t *flags)
{
	*flags |= KNOT_NODE_FLAGS_DELEG;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Returns the non-authoritative node flag
 *
 * \param flags Flags to retrieve the flag from.
 *
 * \return A byte with only the non-authoritative node flag set if it was set in
 *         \a flags.
 */
static inline uint8_t knot_node_flags_get_nonauth(uint8_t flags)
{
	return flags & KNOT_NODE_FLAGS_NONAUTH;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Sets the non-authoritative node flag.
 *
 * \param flags Flags to set the flag in.
 */
static inline void knot_node_flags_set_nonauth(uint8_t *flags)
{
	*flags |= KNOT_NODE_FLAGS_NONAUTH;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Returns the old node flag
 *
 * \param flags Flags to retrieve the flag from.
 *
 * \return A byte with only the old node flag set if it was set in \a flags.
 */
static inline uint8_t knot_node_flags_get_old(uint8_t flags)
{
	return flags & KNOT_NODE_FLAGS_OLD;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Sets the old node flag.
 *
 * \param flags Flags to set the flag in.
 */
static inline void knot_node_flags_set_new(uint8_t *flags)
{
	*flags |= KNOT_NODE_FLAGS_NEW;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Returns the new node flag
 *
 * \param flags Flags to retrieve the flag from.
 *
 * \return A byte with only the new node flag set if it was set in \a flags.
 */
static inline uint8_t knot_node_flags_get_new(uint8_t flags)
{
	return flags & KNOT_NODE_FLAGS_NEW;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Sets the new node flag.
 *
 * \param flags Flags to set the flag in.
 */
static inline void knot_node_flags_set_old(uint8_t *flags)
{
	*flags |= KNOT_NODE_FLAGS_OLD;
}

/*----------------------------------------------------------------------------*/

static inline void knot_node_flags_clear_new(uint8_t *flags)
{
	*flags &= ~KNOT_NODE_FLAGS_NEW;
}

/*----------------------------------------------------------------------------*/

static inline void knot_node_flags_clear_old(uint8_t *flags)
{
	*flags &= ~KNOT_NODE_FLAGS_OLD;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Compares the two keys as RR types.
 *
 * \note This function may be used in data structures requiring generic
 *       comparation function.
 *
 * \param key1 First RR type.
 * \param key2 Second RR type.
 *
 * \retval 0 if \a key1 is equal to \a key2.
 * \retval < 0 if \a key1 is lower than \a key2.
 * \retval > 0 if \a key1 is higher than \a key2.
 */
static int compare_rrset_types(void *rr1, void *rr2)
{
	knot_rrset_t *rrset1 = (knot_rrset_t *)rr1;
	knot_rrset_t *rrset2 = (knot_rrset_t *)rr2;
	return ((rrset1->type > rrset2->type) ? 1 :
	        (rrset1->type == rrset2->type) ? 0 : -1);
}

/*----------------------------------------------------------------------------*/

static int knot_node_zone_gen_is_new(const knot_node_t *node)
{
	assert(node->zone != NULL);
	knot_zone_contents_t *cont = rcu_dereference(node->zone->contents);
	assert(cont != NULL);
	return knot_zone_contents_gen_is_new(cont);
}

/*----------------------------------------------------------------------------*/

static int knot_node_zone_gen_is_old(const knot_node_t *node)
{
	assert(node->zone != NULL);
	knot_zone_contents_t *cont = rcu_dereference(node->zone->contents);
	assert(cont != NULL);
	return knot_zone_contents_gen_is_old(cont);
}

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

knot_node_t *knot_node_new(knot_dname_t *owner, knot_node_t *parent,
                               uint8_t flags)
{
	knot_node_t *ret = (knot_node_t *)calloc(1, sizeof(knot_node_t));
	if (ret == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	/* Store reference to owner. */
	knot_dname_retain(owner);
	ret->owner = owner;
	knot_node_set_parent(ret, parent);
	ret->rrset_tree = gen_tree_new(compare_rrset_types);
	ret->flags = flags;
	
	assert(ret->children == 0);

	return ret;
}

/*----------------------------------------------------------------------------*/

int knot_node_add_rrset(knot_node_t *node, knot_rrset_t *rrset,
                          int merge)
{
	int ret = 0;

	if ((ret = (gen_tree_add(node->rrset_tree, rrset,
	                         (merge) ? knot_rrset_merge : NULL))) < 0) {
		dbg_node("Failed to add rrset to node->rrset_tree.\n");
		return KNOT_ERROR;
	}

	if (ret >= 0) {
		node->rrset_count += (ret > 0 ? 0 : 1);
		return ret;
	} else {
		return KNOT_ERROR;
	}
}

/*----------------------------------------------------------------------------*/

const knot_rrset_t *knot_node_rrset(const knot_node_t *node,
                                        uint16_t type)
{
	assert(node != NULL);
	assert(node->rrset_tree != NULL);
	knot_rrset_t rrset;
	rrset.type = type;
	return (const knot_rrset_t *)gen_tree_find(node->rrset_tree, &rrset);
}

/*----------------------------------------------------------------------------*/

knot_rrset_t *knot_node_get_rrset(knot_node_t *node, uint16_t type)
{
	knot_rrset_t rrset;
	rrset.type = type;
	return (knot_rrset_t *)gen_tree_find(node->rrset_tree, &rrset);
}

/*----------------------------------------------------------------------------*/

knot_rrset_t *knot_node_remove_rrset(knot_node_t *node, uint16_t type)
{
	knot_rrset_t dummy_rrset;
	dummy_rrset.type = type;
	knot_rrset_t *rrset =
		(knot_rrset_t *)gen_tree_find(node->rrset_tree, &dummy_rrset);
	if (rrset != NULL) {
		gen_tree_remove(node->rrset_tree, rrset);
		node->rrset_count--;
	}
	return rrset;
}

/*----------------------------------------------------------------------------*/

void knot_node_remove_all_rrsets(knot_node_t *node)
{
	// remove RRSets but do not delete them
	gen_tree_clear(node->rrset_tree);
	node->rrset_count = 0;

}

/*----------------------------------------------------------------------------*/

short knot_node_rrset_count(const knot_node_t *node)
{
	return node->rrset_count;
}

/*----------------------------------------------------------------------------*/

struct knot_node_save_rrset_arg {
	knot_rrset_t **array;
	size_t count;
};

static void save_rrset_to_array(void *node, void *data)
{
	knot_rrset_t *rrset = (knot_rrset_t *)node;
	struct knot_node_save_rrset_arg *args =
		(struct knot_node_save_rrset_arg *)data;
	args->array[args->count++] = rrset;
}

knot_rrset_t **knot_node_get_rrsets(const knot_node_t *node)
{
//	knot_node_dump(node, 1);
	if (node->rrset_count == 0) {
		return NULL;
	}
	knot_rrset_t **rrsets = (knot_rrset_t **)malloc(
		node->rrset_count * sizeof(knot_rrset_t *));
	CHECK_ALLOC_LOG(rrsets, NULL);
	struct knot_node_save_rrset_arg args;
	args.array = rrsets;
	args.count = 0;

	gen_tree_apply_inorder(node->rrset_tree, save_rrset_to_array,
	                       &args);

	assert(args.count == node->rrset_count);

	return rrsets;
}

/*----------------------------------------------------------------------------*/

const knot_rrset_t **knot_node_rrsets(const knot_node_t *node)
{
	//knot_node_dump((knot_node_t *)node, (void*)1);
	if (node->rrset_count == 0) {
		return NULL;
	}
	
	knot_rrset_t **rrsets = (knot_rrset_t **)malloc(
		node->rrset_count * sizeof(knot_rrset_t *));
	CHECK_ALLOC_LOG(rrsets, NULL);
	struct knot_node_save_rrset_arg args;
	args.array = rrsets;
	args.count = 0;

	gen_tree_apply_inorder(node->rrset_tree, save_rrset_to_array,
	                       &args);

	assert(args.count == node->rrset_count);
	assert(args.count);

	return (const knot_rrset_t **)rrsets;

}

/*----------------------------------------------------------------------------*/

const knot_node_t *knot_node_parent(const knot_node_t *node, 
                                        int check_version)
{
//	assert(!check_version
//	       || (node->zone != NULL && node->zone->contents != NULL));
	
	knot_node_t *parent = node->parent;
	
	if (check_version && node->zone != NULL) {
		int new_gen = knot_node_zone_gen_is_new(node);
//		short ver = knot_node_zone_generation(node);
	
		/*! \todo Remove, this will not be true during the reference
		 *        fixing.
		 */
//		assert(new_gen || parent == NULL
//		       || !knot_node_is_new(parent));

		if (new_gen && parent != NULL) {
			// we want the new node
			assert(node->parent->new_node != NULL);
			parent = parent->new_node;
		}
	}
	
	return parent;
}

/*----------------------------------------------------------------------------*/

void knot_node_set_parent(knot_node_t *node, knot_node_t *parent)
{
	// decrease number of children of previous parent
	if (node->parent != NULL) {
		--parent->children;
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
	return node->children;
}

/*----------------------------------------------------------------------------*/

const knot_node_t *knot_node_previous(const knot_node_t *node, 
                                          int check_version)
{
	return knot_node_get_previous(node, check_version);
}

/*----------------------------------------------------------------------------*/

knot_node_t *knot_node_get_previous(const knot_node_t *node, 
                                        int check_version)
{
	assert(!check_version
	       || (node->zone != NULL && node->zone->contents != NULL));
	
	knot_node_t *prev = node->prev;
	
	if (check_version && prev != NULL) {
		int new_gen = knot_node_zone_gen_is_new(node);
		int old_gen = knot_node_zone_gen_is_old(node);
//		short ver = knot_node_zone_generation(node);
		
		if (old_gen) {  // we want old node
			while (knot_node_is_new(prev)) {
				prev = prev->prev;
			}
			assert(!knot_node_is_new(prev));
		} else if (new_gen) {  // we want new node
			while (knot_node_is_old(prev)) {
				if (prev->new_node) {
					prev = prev->new_node;
				} else {
					prev = prev;
				}
			}
			assert(knot_node_is_new(prev));
		}
	}
	
	return prev;
}

/*----------------------------------------------------------------------------*/

void knot_node_set_previous(knot_node_t *node, knot_node_t *prev)
{
	node->prev = prev;
	if (prev != NULL) {
		// set the prev pointer of the next node to the given node
		if (prev->next != NULL) {
			assert(prev->next->prev == prev);
			prev->next->prev = node;
		}
		node->next = prev->next;
		prev->next = node;
	}
}

/*----------------------------------------------------------------------------*/

const knot_node_t *knot_node_nsec3_node(const knot_node_t *node, 
                                            int check_version)
{
	knot_node_t *nsec3_node = node->nsec3_node;
	if (nsec3_node == NULL) {
		return NULL;
	}
	
	if (check_version) {
		int new_gen = knot_node_zone_gen_is_new(node);
		int old_gen = knot_node_zone_gen_is_old(node);
//		short ver = knot_node_zone_generation(node);
		assert(new_gen || !knot_node_is_new(nsec3_node));
		if (old_gen && knot_node_is_new(nsec3_node)) {
			return NULL;
		} else if (new_gen && knot_node_is_old(nsec3_node)) {
			nsec3_node = nsec3_node->new_node;
		}
	}
	
	return nsec3_node;
}

/*----------------------------------------------------------------------------*/

void knot_node_set_nsec3_node(knot_node_t *node, knot_node_t *nsec3_node)
{
	node->nsec3_node = nsec3_node;
	if (nsec3_node != NULL) {
		nsec3_node->nsec3_referer = node;
	}
}

/*----------------------------------------------------------------------------*/

const knot_dname_t *knot_node_owner(const knot_node_t *node)
{
	return node->owner;
}

/*----------------------------------------------------------------------------*/

knot_dname_t *knot_node_get_owner(const knot_node_t *node)
{
	return node->owner;
}

/*----------------------------------------------------------------------------*/

void knot_node_set_owner(knot_node_t *node, knot_dname_t* owner)
{
	if (node) {
		/* Retain new owner and release old owner. */
		knot_dname_retain(owner);
		knot_dname_release(node->owner);
		node->owner = owner;
	}
}

/*----------------------------------------------------------------------------*/

const knot_node_t *knot_node_wildcard_child(const knot_node_t *node, 
                                                int check_version)
{
	knot_node_t *w = node->wildcard_child;
	
	if (check_version && w != 0) {
		int new_gen = knot_node_zone_gen_is_new(node);
		int old_gen = knot_node_zone_gen_is_old(node);
//		short ver = knot_node_zone_generation(node);

		if (old_gen && knot_node_is_new(w)) {
			return NULL;
		} else if (new_gen && knot_node_is_old(w)) {
			assert(w->new_node != NULL);
			w = w->new_node;
		}
	}
	
	return w;
}

/*----------------------------------------------------------------------------*/

void knot_node_set_wildcard_child(knot_node_t *node,
                                    knot_node_t *wildcard_child)
{
	node->wildcard_child = wildcard_child;
//	assert(wildcard_child->parent == node);
}

/*----------------------------------------------------------------------------*/

const knot_node_t *knot_node_current(const knot_node_t *node)
{
	if (node == NULL || node->zone == NULL
	    || knot_zone_contents(node->zone) == NULL) {
		return node;
	}

	int new_gen = knot_node_zone_gen_is_new(node);
	int old_gen = knot_node_zone_gen_is_old(node);
//	short ver = knot_node_zone_generation(node);

	if (old_gen && knot_node_is_new(node)) {
		return NULL;
	} else if (new_gen && knot_node_is_old(node)) {
		assert(node->new_node != NULL);
		return node->new_node;
	}
	return node;
}

/*----------------------------------------------------------------------------*/

knot_node_t *knot_node_get_current(knot_node_t *node)
{
	if (node == NULL || node->zone == NULL
	    || knot_zone_contents(node->zone) == NULL) {
		return node;
	}

	int new_gen = knot_node_zone_gen_is_new(node);
	int old_gen = knot_node_zone_gen_is_old(node);
//	short ver = knot_node_zone_generation(node);

	if (old_gen && knot_node_is_new(node)) {
		return NULL;
	} else if (new_gen && knot_node_is_old(node)) {
		assert(node->new_node != NULL);
		return node->new_node;
	}
	
	assert((old_gen && knot_node_is_old(node))
	       || (new_gen && knot_node_is_new(node))
	       || (!old_gen && !new_gen));
	
	return node;
}

/*----------------------------------------------------------------------------*/

const knot_node_t *knot_node_new_node(const knot_node_t *node)
{
	return node->new_node;
}

/*----------------------------------------------------------------------------*/

knot_node_t *knot_node_get_new_node(const knot_node_t *node)
{
	return node->new_node;
}

/*----------------------------------------------------------------------------*/

void knot_node_set_new_node(knot_node_t *node,
                              knot_node_t *new_node)
{
	node->new_node = new_node;
}

/*----------------------------------------------------------------------------*/

void knot_node_set_zone(knot_node_t *node, knot_zone_t *zone)
{
	node->zone = zone;
}

/*----------------------------------------------------------------------------*/

void knot_node_update_ref(knot_node_t **ref)
{
	if (*ref != NULL && knot_node_is_old(*ref)) {
		*ref = (*ref)->new_node;
	}
}

/*----------------------------------------------------------------------------*/

void knot_node_update_refs(knot_node_t *node)
{
	/* CLEANUP */
	/* OMG! */
	// reference to previous node
	knot_node_update_ref(&node->prev);
//	if (node->prev && knot_node_is_old(node->prev)) {
//		assert(node->prev->new_node != NULL);
//		node->prev = node->prev->new_node;
//	}

	// reference to next node
	knot_node_update_ref(&node->next);
//	if (node->next && knot_node_is_old(node->next)) {
//		assert(node->next->new_node != NULL);
//		node->next = node->next->new_node;
//	}

	// reference to parent
//	if (node->parent && knot_node_is_old(node->parent)) {
//		assert(node->parent->new_node != NULL);
//		// do not use the API function to set parent, so that children count
//		// is not changed
//		//knot_node_set_parent(node, node->parent->new_node);
//		node->parent = node->parent->new_node;
//	}
	knot_node_update_ref(&node->parent);

	// reference to wildcard child
	knot_node_update_ref(&node->wildcard_child);
//	if (node->wildcard_child && knot_node_is_old(node->wildcard_child)) {
//		assert(node->wildcard_child->new_node != NULL);
//		node->wildcard_child = node->wildcard_child->new_node;
//	}

	// reference to NSEC3 node
	knot_node_update_ref(&node->nsec3_node);
//	if (node->nsec3_node && knot_node_is_old(node->nsec3_node)) {
//		assert(node->nsec3_node->new_node != NULL);
//		node->nsec3_node = node->nsec3_node->new_node;
//	}

	// reference to NSEC3 referrer
	knot_node_update_ref(&node->nsec3_referer);
//	if (node->nsec3_referer && knot_node_is_old(node->nsec3_referer)) {
//		assert(node->nsec3_referer->new_node != NULL);
//		node->nsec3_referer = node->nsec3_referer->new_node;
//	}
}

/*----------------------------------------------------------------------------*/

void knot_node_set_deleg_point(knot_node_t *node)
{
	knot_node_flags_set_deleg(&node->flags);
}

/*----------------------------------------------------------------------------*/

int knot_node_is_deleg_point(const knot_node_t *node)
{
	return knot_node_flags_get_deleg(node->flags);
}

/*----------------------------------------------------------------------------*/

void knot_node_set_non_auth(knot_node_t *node)
{
	knot_node_flags_set_nonauth(&node->flags);
}

/*----------------------------------------------------------------------------*/

int knot_node_is_non_auth(const knot_node_t *node)
{
	return knot_node_flags_get_nonauth(node->flags);
}

/*----------------------------------------------------------------------------*/

int knot_node_is_auth(const knot_node_t *node)
{
	return (node->flags == 0);
}

/*----------------------------------------------------------------------------*/

int knot_node_is_new(const knot_node_t *node)
{
	return knot_node_flags_get_new(node->flags);
}

/*----------------------------------------------------------------------------*/

int knot_node_is_old(const knot_node_t *node)
{
	return knot_node_flags_get_old(node->flags);
}

/*----------------------------------------------------------------------------*/

void knot_node_set_new(knot_node_t *node)
{
	knot_node_flags_set_new(&node->flags);
}

/*----------------------------------------------------------------------------*/

void knot_node_set_old(knot_node_t *node)
{
	knot_node_flags_set_old(&node->flags);
}

/*----------------------------------------------------------------------------*/

void knot_node_clear_new(knot_node_t *node)
{
	knot_node_flags_clear_new(&node->flags);
}

/*----------------------------------------------------------------------------*/

void knot_node_clear_old(knot_node_t *node)
{
	knot_node_flags_clear_old(&node->flags);
}

/*----------------------------------------------------------------------------*/

static void knot_node_free_rrsets_from_tree(void *item, void *data)
{
	if (item == NULL) {
		return;
	}
	
	knot_rrset_t *rrset = (knot_rrset_t *)(item);
	knot_rrset_deep_free(&rrset, 0, 1, *((int *)data));
}

/*----------------------------------------------------------------------------*/

void knot_node_free_rrsets(knot_node_t *node, int free_rdata_dnames)
{
	/* CLEANUP */
//	knot_rrset_t **rrsets = knot_node_get_rrsets(node);
//	for (int i = 0; i < node->rrset_count; i++) {
//		knot_rrset_deep_free(&(rrsets[i]), 0, 1, free_rdata_dnames);
//	}
	
//	free(rrsets);

	char *name = knot_dname_to_str(node->owner);
	free(name);

	gen_tree_destroy(&node->rrset_tree, knot_node_free_rrsets_from_tree, 
	                 (void *)&free_rdata_dnames);
}

/*----------------------------------------------------------------------------*/

void knot_node_free(knot_node_t **node, int free_owner, int fix_refs)
{
	if (node == NULL || *node == NULL) {
		return;
	}
	
	dbg_node("Freeing node.\n");
	if ((*node)->rrset_tree != NULL) {
		dbg_node("Freeing RRSets.\n");
		gen_tree_destroy(&(*node)->rrset_tree, NULL, NULL);
	}

	/*! \todo Always release owner? */
	//if (free_owner) {
		dbg_node("Releasing owner.\n");
		knot_dname_release((*node)->owner);
	//}

	// check nodes referencing this node and fix the references

	if (fix_refs) {
		// previous node
		dbg_node("Checking previous.\n");
		if ((*node)->prev && (*node)->prev->next == (*node)) {
			(*node)->prev->next = (*node)->next;
		}

		dbg_node("Checking next.\n");
		if ((*node)->next && (*node)->next->prev == (*node)) {
			(*node)->next->prev = (*node)->prev;
		}

		// NSEC3 node
		dbg_node("Checking NSEC3.\n");
		if ((*node)->nsec3_node
		    && (*node)->nsec3_node->nsec3_referer == (*node)) {
			(*node)->nsec3_node->nsec3_referer = NULL;
		}

		dbg_node("Checking NSEC3 ref.\n");
		if ((*node)->nsec3_referer
		    && (*node)->nsec3_referer->nsec3_node == (*node)) {
			(*node)->nsec3_referer->nsec3_node = NULL;
		}

		// wildcard child node
		dbg_node("Checking parent's wildcard child.\n");
		if ((*node)->parent
		    && (*node)->parent->wildcard_child == (*node)) {
			(*node)->parent->wildcard_child = NULL;
		}
		
		// fix parent's children count
		if ((*node)->parent) {
			--(*node)->parent->children;
		}
	}

	free(*node);
	*node = NULL;

	dbg_node("Done.\n");
}

/*----------------------------------------------------------------------------*/

int knot_node_compare(knot_node_t *node1, knot_node_t *node2)
{
	return knot_dname_compare(node1->owner, node2->owner);
}

/*----------------------------------------------------------------------------*/

int knot_node_shallow_copy(const knot_node_t *from, knot_node_t **to)
{
	// create new node
	*to = knot_node_new(from->owner, from->parent, from->flags);
	if (*to == NULL) {
		return KNOT_ENOMEM;
	}

	/* Free old rrset_tree, as it will be replaced by shallow copy. */
	gen_tree_destroy(&(*to)->rrset_tree, 0, 0);

	// copy references	
	// do not use the API function to set parent, so that children count 
	// is not changed
	memcpy(*to, from, sizeof(knot_node_t));

	// copy RRSets
	// copy the skip list with the old references
	/* CLEANUP */
	(*to)->rrset_tree = gen_tree_shallow_copy(from->rrset_tree);
//	assert((*to)->rrset_tree != from->rrset_tree);
//	(*to)->rrsets = skip_copy_list(from->rrsets);
	if ((*to)->rrset_tree == NULL) {
		free(*to);
		*to = NULL;
		return KNOT_ENOMEM;
	}

	return KNOT_EOK;
}
