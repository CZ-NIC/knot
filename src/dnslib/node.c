#include <config.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>

#include <urcu.h>

#include "dnslib/dnslib-common.h"
#include "dnslib/node.h"
#include "dnslib/rrset.h"
#include "dnslib/error.h"
#include "common/skip-list.h"
#include "common/tree.h"
#include "dnslib/debug.h"

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
static inline uint8_t dnslib_node_flags_get_deleg(uint8_t flags)
{
	return flags & DNSLIB_NODE_FLAGS_DELEG;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Sets the delegation point flag.
 *
 * \param flags Flags to set the flag in.
 */
static inline void dnslib_node_flags_set_deleg(uint8_t *flags)
{
	*flags |= DNSLIB_NODE_FLAGS_DELEG;
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
static inline uint8_t dnslib_node_flags_get_nonauth(uint8_t flags)
{
	return flags & DNSLIB_NODE_FLAGS_NONAUTH;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Sets the non-authoritative node flag.
 *
 * \param flags Flags to set the flag in.
 */
static inline void dnslib_node_flags_set_nonauth(uint8_t *flags)
{
	*flags |= DNSLIB_NODE_FLAGS_NONAUTH;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Returns the old node flag
 *
 * \param flags Flags to retrieve the flag from.
 *
 * \return A byte with only the old node flag set if it was set in \a flags.
 */
static inline uint8_t dnslib_node_flags_get_old(uint8_t flags)
{
	return flags & DNSLIB_NODE_FLAGS_OLD;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Sets the old node flag.
 *
 * \param flags Flags to set the flag in.
 */
static inline void dnslib_node_flags_set_new(uint8_t *flags)
{
	*flags |= DNSLIB_NODE_FLAGS_NEW;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Returns the new node flag
 *
 * \param flags Flags to retrieve the flag from.
 *
 * \return A byte with only the new node flag set if it was set in \a flags.
 */
static inline uint8_t dnslib_node_flags_get_new(uint8_t flags)
{
	return flags & DNSLIB_NODE_FLAGS_NEW;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Sets the new node flag.
 *
 * \param flags Flags to set the flag in.
 */
static inline void dnslib_node_flags_set_old(uint8_t *flags)
{
	*flags |= DNSLIB_NODE_FLAGS_OLD;
}

/*----------------------------------------------------------------------------*/

static inline void dnslib_node_flags_clear_new(uint8_t *flags)
{
	*flags &= ~DNSLIB_NODE_FLAGS_NEW;
}

/*----------------------------------------------------------------------------*/

static inline void dnslib_node_flags_clear_old(uint8_t *flags)
{
	*flags &= ~DNSLIB_NODE_FLAGS_OLD;
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
	dnslib_rrset_t *rrset1 = (dnslib_rrset_t *)rr1;
	dnslib_rrset_t *rrset2 = (dnslib_rrset_t *)rr2;
	return ((rrset1->type > rrset2->type) ? 1 :
	        (rrset1->type == rrset2->type) ? 0 : -1);
}

/*----------------------------------------------------------------------------*/

static short dnslib_node_zone_generation(const dnslib_node_t *node)
{
	assert(node->zone != NULL);
	dnslib_zone_contents_t *cont = rcu_dereference(node->zone->contents);
	assert(cont != NULL);
	return cont->generation;
}

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

dnslib_node_t *dnslib_node_new(dnslib_dname_t *owner, dnslib_node_t *parent,
                               uint8_t flags)
{
	dnslib_node_t *ret = (dnslib_node_t *)calloc(1, sizeof(dnslib_node_t));
	if (ret == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	ret->owner = owner;
	dnslib_node_set_parent(ret, parent);
	ret->rrset_tree = gen_tree_new(compare_rrset_types, dnslib_rrset_merge);
	ret->flags = flags;
	
	assert(ret->children == 0);

	return ret;
}

/*----------------------------------------------------------------------------*/

int dnslib_node_add_rrset(dnslib_node_t *node, dnslib_rrset_t *rrset,
                          int merge)
{
	int ret;
	/*!< \todo MISSING MERGE OPTION */
	if ((ret = (gen_tree_add(node->rrset_tree, rrset))) != 0) {
		return DNSLIB_ERROR;
	}

	if (ret == 0) {
		++node->rrset_count;
		return DNSLIB_EOK;
	} else {
		return 1;
	}
}

/*----------------------------------------------------------------------------*/

const dnslib_rrset_t *dnslib_node_rrset(const dnslib_node_t *node,
                                        uint16_t type)
{
	assert(node != NULL);
	assert(node->rrset_tree != NULL);
	dnslib_rrset_t rrset;
	rrset.type = type;
	return (const dnslib_rrset_t *)gen_tree_find(node->rrset_tree, &rrset);
}

/*----------------------------------------------------------------------------*/

dnslib_rrset_t *dnslib_node_get_rrset(dnslib_node_t *node, uint16_t type)
{
	dnslib_rrset_t rrset;
	rrset.type = type;
	return (dnslib_rrset_t *)gen_tree_find(node->rrset_tree, &rrset);
}

/*----------------------------------------------------------------------------*/

dnslib_rrset_t *dnslib_node_remove_rrset(dnslib_node_t *node, uint16_t type)
{
	dnslib_rrset_t dummy_rrset;
	dummy_rrset.type = type;
	dnslib_rrset_t *rrset =
		(dnslib_rrset_t *)gen_tree_find(node->rrset_tree, &dummy_rrset);
	if (rrset != NULL) {
		gen_tree_remove(node->rrset_tree, rrset);
	}
	return rrset;
}

/*----------------------------------------------------------------------------*/

short dnslib_node_rrset_count(const dnslib_node_t *node)
{
	return node->rrset_count;
}

/*----------------------------------------------------------------------------*/

struct dnslib_node_save_rrset_arg {
	dnslib_rrset_t **array;
	size_t count;
};

void save_rrset_to_array(void *node, void *data)
{
	dnslib_rrset_t *rrset = (dnslib_rrset_t *)node;
	struct dnslib_node_save_rrset_arg *args =
		(struct dnslib_node_save_rrset_arg *)data;
	args->array[args->count++] = rrset;
}

dnslib_rrset_t **dnslib_node_get_rrsets(const dnslib_node_t *node)
{
	dnslib_rrset_t **rrsets = (dnslib_rrset_t **)malloc(
		node->rrset_count * sizeof(dnslib_rrset_t *));
	CHECK_ALLOC_LOG(rrsets, NULL);
	struct dnslib_node_save_rrset_arg args;
	args.array = rrsets;
	args.count = 0;

	gen_tree_apply_inorder(node->rrset_tree, save_rrset_to_array,
	                       &args);

	//printf("Returning %d RRSets.\n", i);

	return rrsets;
}

/*----------------------------------------------------------------------------*/

const dnslib_rrset_t **dnslib_node_rrsets(const dnslib_node_t *node)
{
	dnslib_rrset_t **rrsets = (dnslib_rrset_t **)malloc(
		node->rrset_count * sizeof(dnslib_rrset_t *));
		CHECK_ALLOC_LOG(rrsets, NULL);
		struct dnslib_node_save_rrset_arg args;
		args.array = rrsets;
		args.count = 0;

		gen_tree_apply_inorder(node->rrset_tree, save_rrset_to_array,
		                       &args);

		//printf("Returning %d RRSets.\n", i);

		return (const dnslib_rrset_t **)rrsets;

}

/*----------------------------------------------------------------------------*/

const dnslib_node_t *dnslib_node_parent(const dnslib_node_t *node, 
                                        int check_version)
{
//	assert(!check_version
//	       || (node->zone != NULL && node->zone->contents != NULL));
	
	dnslib_node_t *parent = node->parent;
	
	if (check_version && node->zone != NULL) {
		short ver = dnslib_node_zone_generation(node);
	
		assert(ver != 0 || parent == NULL 
		       || !dnslib_node_is_new(parent));
		
		if (ver != 0 && parent != NULL) {
			// we want the new node
			assert(node->parent->new_node != NULL);
			parent = parent->new_node;
		}
	}
	
	return parent;
}

/*----------------------------------------------------------------------------*/

void dnslib_node_set_parent(dnslib_node_t *node, dnslib_node_t *parent)
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

unsigned int dnslib_node_children(const dnslib_node_t *node)
{
	return node->children;
}

/*----------------------------------------------------------------------------*/

const dnslib_node_t *dnslib_node_previous(const dnslib_node_t *node, 
                                          int check_version)
{
	return dnslib_node_get_previous(node, check_version);
}

/*----------------------------------------------------------------------------*/

dnslib_node_t *dnslib_node_get_previous(const dnslib_node_t *node, 
                                        int check_version)
{
	assert(!check_version 
	       || (node->zone != NULL && node->zone->contents != NULL));
	
	dnslib_node_t *prev = node->prev;
	
	if (check_version && prev != NULL) {
		short ver = dnslib_node_zone_generation(node);
		
		if (ver == 0) {  // we want old node
			while (dnslib_node_is_new(prev)) {
				prev = prev->prev;
			}
			assert(!dnslib_node_is_new(prev));
		} else {  // we want new node
			while (dnslib_node_is_old(prev)) {
				if (prev->new_node) {
					prev = prev->new_node;
				} else {
					prev = prev;
				}
			}
			assert(dnslib_node_is_new(prev));
		}
	}
	
	return prev;
}

/*----------------------------------------------------------------------------*/

void dnslib_node_set_previous(dnslib_node_t *node, dnslib_node_t *prev)
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

const dnslib_node_t *dnslib_node_nsec3_node(const dnslib_node_t *node, 
                                            int check_version)
{
	dnslib_node_t *nsec3_node = node->nsec3_node;
	if (nsec3_node == NULL) {
		return NULL;
	}
	
	if (check_version) {
		short ver = dnslib_node_zone_generation(node);
		assert(ver != 0 || !dnslib_node_is_new(nsec3_node));
		if (ver != 0 && dnslib_node_is_old(nsec3_node)) {
			nsec3_node = nsec3_node->new_node;
		}
	}
	
	return nsec3_node;
}

/*----------------------------------------------------------------------------*/

void dnslib_node_set_nsec3_node(dnslib_node_t *node, dnslib_node_t *nsec3_node)
{
	node->nsec3_node = nsec3_node;
	if (nsec3_node != NULL) {
		nsec3_node->nsec3_referer = node;
	}
}

/*----------------------------------------------------------------------------*/

const dnslib_dname_t *dnslib_node_owner(const dnslib_node_t *node)
{
	return node->owner;
}

/*----------------------------------------------------------------------------*/

dnslib_dname_t *dnslib_node_get_owner(const dnslib_node_t *node)
{
	return node->owner;
}

/*----------------------------------------------------------------------------*/

const dnslib_node_t *dnslib_node_wildcard_child(const dnslib_node_t *node, 
                                                int check_version)
{
	dnslib_node_t *w = node->wildcard_child;
	
	if (check_version && w != 0) {
		short ver = dnslib_node_zone_generation(node);

		if (ver == 0 && dnslib_node_is_new(w)) {
			return NULL;
		} else if (ver != 0 && dnslib_node_is_old(w)) {
			assert(w->new_node != NULL);
			w = w->new_node;
		}
	}
	
	return w;
}

/*----------------------------------------------------------------------------*/

void dnslib_node_set_wildcard_child(dnslib_node_t *node,
                                    dnslib_node_t *wildcard_child)
{
	node->wildcard_child = wildcard_child;
//	assert(wildcard_child->parent == node);
}

/*----------------------------------------------------------------------------*/

const dnslib_node_t *dnslib_node_current(const dnslib_node_t *node)
{
	if (node == NULL || node->zone == NULL
	    || dnslib_zone_contents(node->zone) == NULL) {
		return node;
	}

	short ver = dnslib_node_zone_generation(node);

	if (ver == 0 && dnslib_node_is_new(node)) {
		return NULL;
	} else if (ver != 0 && dnslib_node_is_old(node)) {
		assert(node->new_node != NULL);
		return node->new_node;
	}
	return node;
}

/*----------------------------------------------------------------------------*/

dnslib_node_t *dnslib_node_get_current(dnslib_node_t *node)
{
	if (node == NULL || node->zone == NULL
	    || dnslib_zone_contents(node->zone) == NULL) {
		return node;
	}

	short ver = dnslib_node_zone_generation(node);

	if (ver == 0 && dnslib_node_is_new(node)) {
		return NULL;
	} else if (ver != 0 && dnslib_node_is_old(node)) {
		assert(node->new_node != NULL);
		return node->new_node;
	}
	return node;
}

/*----------------------------------------------------------------------------*/

const dnslib_node_t *dnslib_node_new_node(const dnslib_node_t *node)
{
	return node->new_node;
}

/*----------------------------------------------------------------------------*/

dnslib_node_t *dnslib_node_get_new_node(const dnslib_node_t *node)
{
	return node->new_node;
}

/*----------------------------------------------------------------------------*/

void dnslib_node_set_new_node(dnslib_node_t *node,
                              dnslib_node_t *new_node)
{
	node->new_node = new_node;
}

/*----------------------------------------------------------------------------*/

void dnslib_node_set_zone(dnslib_node_t *node, dnslib_zone_t *zone)
{
	node->zone = zone;
}

/*----------------------------------------------------------------------------*/

void dnslib_node_update_ref(dnslib_node_t **ref)
{
	if (*ref != NULL && dnslib_node_is_old(*ref)) {
		*ref = (*ref)->new_node;
	}
}

/*----------------------------------------------------------------------------*/

void dnslib_node_update_refs(dnslib_node_t *node)
{
	// reference to previous node
	dnslib_node_update_ref(&node->prev);
//	if (node->prev && dnslib_node_is_old(node->prev)) {
//		assert(node->prev->new_node != NULL);
//		node->prev = node->prev->new_node;
//	}

	// reference to next node
	dnslib_node_update_ref(&node->next);
//	if (node->next && dnslib_node_is_old(node->next)) {
//		assert(node->next->new_node != NULL);
//		node->next = node->next->new_node;
//	}

	// reference to parent
//	if (node->parent && dnslib_node_is_old(node->parent)) {
//		assert(node->parent->new_node != NULL);
//		// do not use the API function to set parent, so that children count
//		// is not changed
//		//dnslib_node_set_parent(node, node->parent->new_node);
//		node->parent = node->parent->new_node;
//	}
	dnslib_node_update_ref(&node->parent);

	// reference to wildcard child
	dnslib_node_update_ref(&node->wildcard_child);
//	if (node->wildcard_child && dnslib_node_is_old(node->wildcard_child)) {
//		assert(node->wildcard_child->new_node != NULL);
//		node->wildcard_child = node->wildcard_child->new_node;
//	}

	// reference to NSEC3 node
	dnslib_node_update_ref(&node->nsec3_node);
//	if (node->nsec3_node && dnslib_node_is_old(node->nsec3_node)) {
//		assert(node->nsec3_node->new_node != NULL);
//		node->nsec3_node = node->nsec3_node->new_node;
//	}

	// reference to NSEC3 referrer
	dnslib_node_update_ref(&node->nsec3_referer);
//	if (node->nsec3_referer && dnslib_node_is_old(node->nsec3_referer)) {
//		assert(node->nsec3_referer->new_node != NULL);
//		node->nsec3_referer = node->nsec3_referer->new_node;
//	}
}

/*----------------------------------------------------------------------------*/

void dnslib_node_set_deleg_point(dnslib_node_t *node)
{
	dnslib_node_flags_set_deleg(&node->flags);
}

/*----------------------------------------------------------------------------*/

int dnslib_node_is_deleg_point(const dnslib_node_t *node)
{
	return dnslib_node_flags_get_deleg(node->flags);
}

/*----------------------------------------------------------------------------*/

void dnslib_node_set_non_auth(dnslib_node_t *node)
{
	dnslib_node_flags_set_nonauth(&node->flags);
}

/*----------------------------------------------------------------------------*/

int dnslib_node_is_non_auth(const dnslib_node_t *node)
{
	return dnslib_node_flags_get_nonauth(node->flags);
}

/*----------------------------------------------------------------------------*/

int dnslib_node_is_auth(const dnslib_node_t *node)
{
	return (node->flags == 0);
}

/*----------------------------------------------------------------------------*/

int dnslib_node_is_new(const dnslib_node_t *node)
{
	return dnslib_node_flags_get_new(node->flags);
}

/*----------------------------------------------------------------------------*/

int dnslib_node_is_old(const dnslib_node_t *node)
{
	return dnslib_node_flags_get_old(node->flags);
}

/*----------------------------------------------------------------------------*/

void dnslib_node_set_new(dnslib_node_t *node)
{
	dnslib_node_flags_set_new(&node->flags);
}

/*----------------------------------------------------------------------------*/

void dnslib_node_set_old(dnslib_node_t *node)
{
	dnslib_node_flags_set_old(&node->flags);
}

/*----------------------------------------------------------------------------*/

void dnslib_node_clear_new(dnslib_node_t *node)
{
	dnslib_node_flags_clear_new(&node->flags);
}

/*----------------------------------------------------------------------------*/

void dnslib_node_clear_old(dnslib_node_t *node)
{
	dnslib_node_flags_clear_old(&node->flags);
}

/*----------------------------------------------------------------------------*/

void dnslib_node_free_rrsets(dnslib_node_t *node, int free_rdata_dnames)
{
//	const skip_node_t *skip_node =
//		(skip_node_t *)skip_first(node->rrsets);

//	if (skip_node != NULL) {
//		dnslib_rrset_deep_free((dnslib_rrset_t **)(&skip_node->value), 0,
//				       1, free_rdata_dnames);
//		while ((skip_node = skip_next(skip_node)) != NULL) {
//			dnslib_rrset_deep_free((dnslib_rrset_t **)
//						(&skip_node->value), 0,
//						1, free_rdata_dnames);
//		}
//	}

//	skip_destroy_list(&node->rrsets, NULL, NULL);
//	node->rrsets = NULL;
}

/*----------------------------------------------------------------------------*/

void dnslib_node_free(dnslib_node_t **node, int free_owner, int fix_refs)
{
//	debug_dnslib_node("Freeing node.\n");
//	if ((*node)->rrsets != NULL) {
//		debug_dnslib_node("Freeing RRSets.\n");
//		skip_destroy_list(&(*node)->rrsets, NULL, NULL);
//	}
//	if (free_owner) {
//		debug_dnslib_node("Freeing owner.\n");
//		dnslib_dname_free(&(*node)->owner);
//	}

//	// check nodes referencing this node and fix the references

//	if (fix_refs) {
//		// previous node
//		debug_dnslib_node("Checking previous.\n");
//		if ((*node)->prev && (*node)->prev->next == (*node)) {
//			(*node)->prev->next = (*node)->next;
//		}

//		debug_dnslib_node("Checking next.\n");
//		if ((*node)->next && (*node)->next->prev == (*node)) {
//			(*node)->next->prev = (*node)->prev;
//		}

//		// NSEC3 node
//		debug_dnslib_node("Checking NSEC3.\n");
//		if ((*node)->nsec3_node
//		    && (*node)->nsec3_node->nsec3_referer == (*node)) {
//			(*node)->nsec3_node->nsec3_referer = NULL;
//		}

//		debug_dnslib_node("Checking NSEC3 ref.\n");
//		if ((*node)->nsec3_referer
//		    && (*node)->nsec3_referer->nsec3_node == (*node)) {
//			(*node)->nsec3_referer->nsec3_node = NULL;
//		}

//		// wildcard child node
//		debug_dnslib_node("Checking parent's wildcard child.\n");
//		if ((*node)->parent
//		    && (*node)->parent->wildcard_child == (*node)) {
//			(*node)->parent->wildcard_child = NULL;
//		}
		
//		// fix parent's children count
//		if ((*node)->parent) {
//			--(*node)->parent->children;
//		}
//	}

//	free(*node);
//	*node = NULL;

//	debug_dnslib_node("Done.\n");
}

/*----------------------------------------------------------------------------*/

int dnslib_node_compare(dnslib_node_t *node1, dnslib_node_t *node2)
{
	return dnslib_dname_compare(node1->owner, node2->owner);
}

/*----------------------------------------------------------------------------*/

int dnslib_node_deep_copy(const dnslib_node_t *from, dnslib_node_t **to)
{
	// create new node
	*to = dnslib_node_new(from->owner, from->parent, from->flags);
	if (*to == NULL) {
		return DNSLIB_ENOMEM;
	}

	// copy references
	
	// do not use the API function to set parent, so that children count 
	// is not changed
	(*to)->parent = from->parent;
	(*to)->nsec3_node = from->nsec3_node;
	(*to)->nsec3_referer = from->nsec3_referer;
	(*to)->wildcard_child = from->wildcard_child;
	(*to)->prev = from->prev;
	(*to)->next = from->next;
	(*to)->children = from->children;

	// copy RRSets
	// copy the skip list with the old references
//	(*to)->rrsets = skip_copy_list(from->rrsets);
//	if ((*to)->rrsets == NULL) {
//		free(*to);
//		*to = NULL;
//		return DNSLIB_ENOMEM;
//	}

	(*to)->rrset_count = from->rrset_count;

	return DNSLIB_EOK;
}
