/*!
 * \file node.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Structure representing one node in domain name tree and API for
 *        manipulating it.
 *
 * \addtogroup dnslib
 * @{
 */

#ifndef _CUTEDNS_DNSLIB_NODE_H_
#define _CUTEDNS_DNSLIB_NODE_H_

#include "dname.h"
#include "skip-list.h"
#include "rrset.h"
#include "tree.h"

/*----------------------------------------------------------------------------*/
/*!
 * \brief Structure representing one node in a domain name tree, i.e. one domain
 *        name in a zone.
 *
 * RRSets are ordered by type and stored in a skip-list to allow fast lookup.
 *
 * \todo How to return all RRSets?? An array? Or return the skip list and let
 *       the user iterate over it?
 */
struct dnslib_node {
	dnslib_dname_t *owner; /*!< Domain name being the owner of this node. */
	struct dnslib_node *parent; /*!< Parent node in the name hierarchy. */

	/*! \brief Type-ordered list of RRSets belonging to this node. */
	skip_list_t *rrsets;

	/*! \brief Next node in a general list of nodes. Temporary. */
	//struct dnslib_node *next;
	short rrset_count;

	struct dnslib_node *wildcard_child;

	struct dnslib_node *prev;

	/*!
	 * \brief Various flags.
	 *
	 * Currently only two:
	 *   0x01 - node is a delegation point
	 *   0x02 - node is non-authoritative (under a delegation point)
	 */
	uint8_t flags;

	TREE_ENTRY(dnslib_node) avl;
};

typedef struct dnslib_node dnslib_node_t;

/*----------------------------------------------------------------------------*/
/*!
 * \brief Creates and initializes new node structure.
 *
 * \param owner Owner of the created node.
 * \param parent Parent of the created node.
 *
 * \return Newly created node or NULL if an error occured.
 */
dnslib_node_t *dnslib_node_new(dnslib_dname_t *owner, dnslib_node_t *parent);

/*!
 * \brief Adds an RRSet to the node.
 *
 * \param node Node to add the RRSet to.
 * \param rrset RRSet to add.
 *
 * \retval 0 on success.
 * \retval -2 if rrset can not be inserted.
 */
int dnslib_node_add_rrset(dnslib_node_t *node, dnslib_rrset_t *rrset);

/*!
 * \brief Returns the RRSet of the given type from the node.
 *
 * \param node Node to get the RRSet from.
 * \param type Type of the RRSet to retrieve.
 *
 * \return RRSet from node \a node having type \a type, or NULL if no such
 *         RRSet exists in this node.
 */
const dnslib_rrset_t *dnslib_node_rrset(const dnslib_node_t *node,
                                        uint16_t type);

/*!
 * \brief Returns the RRSet of the given type from the node (non-const version).
 *
 * \param node Node to get the RRSet from.
 * \param type Type of the RRSet to retrieve.
 *
 * \return RRSet from node \a node having type \a type, or NULL if no such
 *         RRSet exists in this node.
 */
dnslib_rrset_t *dnslib_node_get_rrset(dnslib_node_t *node, uint16_t type);

short dnslib_node_rrset_count(const dnslib_node_t *node);

const dnslib_rrset_t **dnslib_node_rrsets(const dnslib_node_t *node);

/*!
 * \brief Returns the parent of the node.
 *
 * \param node Node to get the parent of.
 *
 * \return Parent node of the given node or NULL if no parent has been set (e.g.
 *         node in a zone apex has no parent).
 */
const dnslib_node_t *dnslib_node_parent(const dnslib_node_t *node);

/*!
 * \brief Sets the parent of the node.
 *
 * \param node Node to set the parent of.
 * \param parent Parent to set to the node.
 */
void dnslib_node_set_parent(dnslib_node_t *node, dnslib_node_t *parent);

const dnslib_node_t *dnslib_node_previous(const dnslib_node_t *node);

void dnslib_node_set_previous(dnslib_node_t *node, dnslib_node_t *prev);

/*!
 * \brief Returns the owner of the node.
 *
 * \param node Node to get the owner of.
 *
 * \return Owner of the given node.
 */
const dnslib_dname_t *dnslib_node_owner(const dnslib_node_t *node);

/*!
 * \brief Returns the wildcard child of the node.
 *
 * \param node Node to get the owner of.
 *
 * \return Wildcard child of the given node or NULL if it has none.
 */
const dnslib_node_t *dnslib_node_wildcard_child(const dnslib_node_t *node);

/*!
 * \brief Sets the wildcard child of the node.
 *
 * \param node Node to set the wildcard child of.
 * \param parent Wildcard child of the node.
 */
void dnslib_node_set_wildcard_child(dnslib_node_t *node,
                                    dnslib_node_t *wildcard_child);


void dnslib_node_set_deleg_point(dnslib_node_t *node);

int dnslib_node_is_deleg_point(const dnslib_node_t *node);

void dnslib_node_set_non_auth(dnslib_node_t *node);

int dnslib_node_is_non_auth(const dnslib_node_t *node);

/*!
 * \brief Destroys the RRSets within the node structure.
 *
 * \param node Node to be destroyed.
 */
void dnslib_node_free_rrsets(dnslib_node_t *node);

/*!
 * \brief Destroys the node structure.
 *
 * Does not destroy the RRSets within the node.
 * Also sets the given pointer to NULL.
 *
 * \param node Node to be destroyed.
 * \param free_owner Set to 0 if you do not want the owner domain name to be
 *                   destroyed also. Set to <> 0 otherwise.
 */
void dnslib_node_free(dnslib_node_t **node, int free_owner);

void dnslib_node_free_tmp(dnslib_node_t **node, int free_rrsets);

/*!
 * \brief Compares two nodes according to their owner.
 *
 * \param node1 First node.
 * \param node2 Second node.
 *
 * \retval -1 if \a node1 goes before \a node2 according to canonical order
 *         of their owner names.
 * \retval 0 if they are equal.
 * \retval 1 if \a node1 goes after \a node2.
 */
int dnslib_node_compare(dnslib_node_t *node1, dnslib_node_t *node2);

#endif /* _CUTEDNS_DNSLIB_NODE_H_ */

/*! @} */
