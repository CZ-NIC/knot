#include <config.h>
#include <malloc.h>
#include <assert.h>

#include "dnslib/dnslib-common.h"
#include "dnslib/node.h"
#include "dnslib/rrset.h"
#include "dnslib/error.h"
#include "common/skip-list.h"
#include "common/tree.h"

/*----------------------------------------------------------------------------*/
/*! \brief Flags used to mark nodes with some property. */
enum {
	/*! \brief Node is a delegation point (i.e. marking a zone cut). */
	DNSLIB_NODE_FLAGS_DELEG = (uint8_t)0x01,
	/*! \brief Node is not authoritative (i.e. below a zone cut). */
	DNSLIB_NODE_FLAGS_NONAUTH = (uint8_t)0x02
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
	dnslib_node_t *ret = malloc(sizeof(dnslib_node_t));
	if (ret == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	ret->owner = owner;
	ret->parent = parent;
	ret->prev = NULL;
	ret->nsec3_node = NULL;
	ret->rrsets = skip_create_list(compare_rrset_types);
	ret->rrset_count = 0;
	ret->wildcard_child = NULL;
	ret->flags = 0;

	ret->avl.avl_left = NULL;
	ret->avl.avl_right = NULL;
	ret->avl.avl_height = 0;

	return ret;
}

/*----------------------------------------------------------------------------*/

int dnslib_node_add_rrset(dnslib_node_t *node, dnslib_rrset_t *rrset)
{
	if ((skip_insert(node->rrsets, 
			 (void *)&rrset->type, (void *)rrset, NULL)) != 0) {
		return DNSLIB_ERROR;
	}

	++node->rrset_count;

	return DNSLIB_EOK;
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

void dnslib_node_set_previous(dnslib_node_t *node, dnslib_node_t *prev)
{
	node->prev = prev;
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
}

/*----------------------------------------------------------------------------*/

const dnslib_dname_t *dnslib_node_owner(const dnslib_node_t *node)
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

void dnslib_node_free_rrsets(dnslib_node_t *node, int free_rdata_dnames)
{
	const skip_node_t *skip_node =
		skip_first(node->rrsets);

	if (skip_node != NULL) {
		dnslib_rrset_deep_free((dnslib_rrset_t **)&skip_node->value, 0,
		                       free_rdata_dnames);
		while ((skip_node = skip_next(skip_node)) != NULL) {
			dnslib_rrset_deep_free((dnslib_rrset_t **)
			                        &skip_node->value, 0,
			                        free_rdata_dnames);
		}
	}

	skip_destroy_list(&node->rrsets, NULL, NULL);
	node->rrsets = NULL;
}

/*----------------------------------------------------------------------------*/

void dnslib_node_free(dnslib_node_t **node, int free_owner)
{
	if ((*node)->rrsets != NULL) {
		skip_destroy_list(&(*node)->rrsets, NULL, NULL);
	}
	if (free_owner) {
		dnslib_dname_free(&(*node)->owner);
	}
	free(*node);
	*node = NULL;
}

/*----------------------------------------------------------------------------*/

int dnslib_node_compare(dnslib_node_t *node1, dnslib_node_t *node2)
{
	return dnslib_dname_compare(node1->owner, node2->owner);
}
