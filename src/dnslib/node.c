#include <config.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>

#include "dnslib/dnslib-common.h"
#include "dnslib/node.h"
#include "dnslib/rrset.h"
#include "dnslib/error.h"
#include "common/skip-list.h"
#include "common/tree.h"
#include "dnslib/debug.h"

/*----------------------------------------------------------------------------*/
/*! \brief Flags used to mark nodes with some property. */
enum {
	/*! \brief Node is a delegation point (i.e. marking a zone cut). */
	DNSLIB_NODE_FLAGS_DELEG = (uint8_t)0x01,
	/*! \brief Node is not authoritative (i.e. below a zone cut). */
	DNSLIB_NODE_FLAGS_NONAUTH = (uint8_t)0x02,
	/*! \brief Node is old and will be removed (during update). */
	DNSLIB_NODE_FLAGS_OLD = (uint8_t)0x80,
	/*! \brief Node is new and should not be used while zoen is old. */
	DNSLIB_NODE_FLAGS_NEW = (uint8_t)0x40
};

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
static int compare_rrset_types(void *key1, void *key2)
{
	return (*((uint16_t *)key1) == *((uint16_t *)key2) ?
	        0 : *((uint16_t *)key1) < *((uint16_t *)key2) ? -1 : 1);
}

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

dnslib_node_t *dnslib_node_new(dnslib_dname_t *owner, dnslib_node_t *parent)
{
	dnslib_node_t *ret = (dnslib_node_t *)calloc(1, sizeof(dnslib_node_t));
	if (ret == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	ret->owner = owner;
	ret->parent = parent;
	ret->rrsets = skip_create_list(compare_rrset_types);

//	ret->avl.avl_left = NULL;
//	ret->avl.avl_right = NULL;
//	ret->avl.avl_height = 0;

	return ret;
}

/*----------------------------------------------------------------------------*/

int dnslib_node_add_rrset(dnslib_node_t *node, dnslib_rrset_t *rrset,
                          int merge)
{
	int ret;
	if ((ret = (skip_insert(node->rrsets,
	                        (void *)&rrset->type, (void *)rrset,
	                        (merge) ? dnslib_rrset_merge : NULL))) < 0) {
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
	assert(node->rrsets != NULL);
	return (const dnslib_rrset_t *)skip_find(node->rrsets, (void *)&type);
}

/*----------------------------------------------------------------------------*/

dnslib_rrset_t *dnslib_node_get_rrset(dnslib_node_t *node, uint16_t type)
{
	return (dnslib_rrset_t *)skip_find(node->rrsets, (void *)&type);
}

/*----------------------------------------------------------------------------*/

short dnslib_node_rrset_count(const dnslib_node_t *node)
{
	return node->rrset_count;
}

/*----------------------------------------------------------------------------*/

dnslib_rrset_t **dnslib_node_get_rrsets(const dnslib_node_t *node)
{
	dnslib_rrset_t **rrsets = (dnslib_rrset_t **)malloc(
		node->rrset_count * sizeof(dnslib_rrset_t *));
	CHECK_ALLOC_LOG(rrsets, NULL);

	const skip_node_t *sn = skip_first(node->rrsets);
	int i = 0;
	while (sn != NULL) {
		assert(i < node->rrset_count);
		rrsets[i] = (dnslib_rrset_t *)sn->value;
		sn = skip_next(sn);
		++i;
	}

	//printf("Returning %d RRSets.\n", i);

	return rrsets;
}

/*----------------------------------------------------------------------------*/

const dnslib_rrset_t **dnslib_node_rrsets(const dnslib_node_t *node)
{
	const dnslib_rrset_t **rrsets = (const dnslib_rrset_t **)malloc(
		node->rrset_count * sizeof(dnslib_rrset_t *));
	CHECK_ALLOC_LOG(rrsets, NULL);

	const skip_node_t *sn = skip_first(node->rrsets);
	int i = 0;
	while (sn != NULL) {
		assert(i < node->rrset_count);
		rrsets[i] = (const dnslib_rrset_t *)sn->value;
		sn = skip_next(sn);
		++i;
	}

	//printf("Returning %d RRSets.\n", i);

	return rrsets;
}

/*----------------------------------------------------------------------------*/

const dnslib_node_t *dnslib_node_parent(const dnslib_node_t *node)
{
	return node->parent;
}

void dnslib_node_set_parent(dnslib_node_t *node, dnslib_node_t *parent)
{
	node->parent = parent;
}

/*----------------------------------------------------------------------------*/

const dnslib_node_t *dnslib_node_previous(const dnslib_node_t *node)
{
	return node->prev;
}

/*----------------------------------------------------------------------------*/

dnslib_node_t *dnslib_node_get_previous(const dnslib_node_t *node)
{
	return node->prev;
}

/*----------------------------------------------------------------------------*/

void dnslib_node_set_previous(dnslib_node_t *node, dnslib_node_t *prev)
{
	node->prev = prev;
	if (prev != NULL) {
		prev->next = node;
	}
}

/*----------------------------------------------------------------------------*/

const dnslib_node_t *dnslib_node_nsec3_node(const dnslib_node_t *node)
{
	return node->nsec3_node;
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

const dnslib_node_t *dnslib_node_wildcard_child(const dnslib_node_t *node)
{
	return node->wildcard_child;
}

/*----------------------------------------------------------------------------*/

void dnslib_node_set_wildcard_child(dnslib_node_t *node,
                                    dnslib_node_t *wildcard_child)
{
	node->wildcard_child = wildcard_child;
	assert(wildcard_child->parent == node);
}

/*----------------------------------------------------------------------------*/

const dnslib_node_t *dnslib_node_new_node(const dnslib_node_t *node)
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
	const skip_node_t *skip_node =
		(skip_node_t *)skip_first(node->rrsets);

	if (skip_node != NULL) {
		dnslib_rrset_deep_free((dnslib_rrset_t **)(&skip_node->value), 0,
				       1, free_rdata_dnames);
		while ((skip_node = skip_next(skip_node)) != NULL) {
			dnslib_rrset_deep_free((dnslib_rrset_t **)
						(&skip_node->value), 0,
						1, free_rdata_dnames);
		}
	}

	skip_destroy_list(&node->rrsets, NULL, NULL);
	node->rrsets = NULL;
}

/*----------------------------------------------------------------------------*/

void dnslib_node_free(dnslib_node_t **node, int free_owner)
{
	debug_dnslib_node("Freeing node.\n");
	if ((*node)->rrsets != NULL) {
		debug_dnslib_node("Freeing RRSets.\n");
		skip_destroy_list(&(*node)->rrsets, NULL, NULL);
	}
	if (free_owner) {
		debug_dnslib_node("Freeing owner.\n");
		dnslib_dname_free(&(*node)->owner);
	}

	// check nodes referencing this node and fix the references

	// previous node
	debug_dnslib_node("Checking previous.\n");
	if ((*node)->prev && (*node)->prev->next == (*node)) {
		(*node)->prev->next = (*node)->next;
	}

	debug_dnslib_node("Checking next.\n");
	if ((*node)->next && (*node)->next->prev == (*node)) {
		(*node)->next->prev = (*node)->prev;
	}

	// NSEC3 node
	debug_dnslib_node("Checking NSEC3.\n");
	if ((*node)->nsec3_node
	    && (*node)->nsec3_node->nsec3_referer == (*node)) {
		(*node)->nsec3_node->nsec3_referer = NULL;
	}

	debug_dnslib_node("Checking NSEC3 ref.\n");
	if ((*node)->nsec3_referer
	    && (*node)->nsec3_referer->nsec3_node == (*node)) {
		(*node)->nsec3_referer->nsec3_node = NULL;
	}

	// wildcard child node
	debug_dnslib_node("Checking parent's wildcard child.\n");
	if ((*node)->parent && (*node)->parent->wildcard_child == (*node)) {
		(*node)->parent->wildcard_child = NULL;
	}

	free(*node);
	*node = NULL;

	debug_dnslib_node("Done.\n");
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
	*to = dnslib_node_new(from->owner, from->parent);
	if (*to == NULL) {
		return DNSLIB_ENOMEM;
	}

	// copy flags
	(*to)->flags = from->flags;

	// copy references
	(*to)->parent = from->parent;
	(*to)->nsec3_node = from->nsec3_node;
	(*to)->nsec3_referer = from->nsec3_referer;
	(*to)->wildcard_child = from->wildcard_child;
	(*to)->prev = from->prev;
	(*to)->next = from->next;

	// copy RRSets
	// copy the skip list with the old references
	(*to)->rrsets = skip_copy_list(from->rrsets);
	if ((*to)->rrsets == NULL) {
		free(*to);
		*to = NULL;
		return DNSLIB_ENOMEM;
	}

	(*to)->rrset_count = from->rrset_count;

	return DNSLIB_EOK;
}
