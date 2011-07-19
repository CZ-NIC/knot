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

#ifndef _KNOT_DNSLIB_NODE_H_
#define _KNOT_DNSLIB_NODE_H_

#include "dnslib/dname.h"
#include "common/skip-list.h"
#include "dnslib/rrset.h"
#include "common/tree.h"

/*----------------------------------------------------------------------------*/
/*!
 * \brief Structure representing one node in a domain name tree, i.e. one domain
 *        name in a zone.
 *
 * RRSets are ordered by type and stored in a skip-list to allow fast lookup.
 */
struct dnslib_node {
	dnslib_dname_t *owner; /*!< Domain name being the owner of this node. */
	struct dnslib_node *parent; /*!< Parent node in the name hierarchy. */

	/*! \brief Type-ordered list of RRSets belonging to this node. */
	skip_list_t *rrsets;

	unsigned short rrset_count; /*!< Number of RRSets stored in the node. */

	/*! \brief Wildcard node being the direct descendant of this node. */
	struct dnslib_node *wildcard_child;

	/*!
	 * \brief Previous node in canonical order.
	 *
	 * Only authoritative nodes or delegation points are referenced by this,
	 * as only they may contain NSEC records needed for authenticating
	 * negative answers.
	 */
	struct dnslib_node *prev;

	struct dnslib_node *next;

	/*!
	 * \brief NSEC3 node corresponding to this node.
	 *
	 * Such NSEC3 node has owner in form of the hashed domain name of this
	 * node prepended as a single label to the zone name.
	 */
	struct dnslib_node *nsec3_node;

	struct dnslib_node *nsec3_referer;

	/*!
	 * \brief Various flags.
	 *
	 * Currently only two:
	 *   0x01 - node is a delegation point
	 *   0x02 - node is non-authoritative (under a delegation point)
	 *   0x80 - node is old and will be removed (during update)
	 *   0x40 - node is new, should not be used while zone is old
	 */
	uint8_t flags;

	struct dnslib_node *new_node;
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
 * \retval DNSLIB_EOK on success.
 * \retval DNSLIB_ERROR if the RRSet could not be inserted.
 */
int dnslib_node_add_rrset(dnslib_node_t *node, dnslib_rrset_t *rrset,
                          int merge);

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

/*!
 * \brief Returns number of RRSets in the node.
 *
 * \param node Node to get the RRSet count from.
 *
 * \return Number of RRSets in \a node.
 */
short dnslib_node_rrset_count(const dnslib_node_t *node);

/*!
 * \brief Returns all RRSets from the node.
 *
 * \param node Node to get the RRSets from.
 *
 * \return Newly allocated array of RRSets or NULL if an error occured.
 */
dnslib_rrset_t **dnslib_node_get_rrsets(const dnslib_node_t *node);

/*!
 * \brief Returns all RRSets from the node.
 *
 * \note This function is identical to dnslib_node_get_rrsets(), only it returns
 *       non-modifiable data.
 *
 * \param node Node to get the RRSets from.
 *
 * \return Newly allocated array of RRSets or NULL if an error occured.
 */
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

/*!
 * \brief Returns the previous authoritative node or delegation point in
 *        canonical order or the first node in zone.
 *
 * \param node Node to get the previous node of.
 *
 * \return Previous authoritative node or delegation point in canonical order or
 *         the first node in zone if \a node is the last node in zone.
 * \retval NULL if previous node is not set.
 */
const dnslib_node_t *dnslib_node_previous(const dnslib_node_t *node);

/*!
 * \brief Returns the previous authoritative node or delegation point in
 *        canonical order or the first node in zone.
 *
 * \note This function is identical to dnslib_node_previous() except that it
 *       returns non-const node.
 *
 * \param node Node to get the previous node of.
 *
 * \return Previous authoritative node or delegation point in canonical order or
 *         the first node in zone if \a node is the last node in zone.
 * \retval NULL if previous node is not set.
 */
dnslib_node_t *dnslib_node_get_previous(const dnslib_node_t *node);

/*!
 * \brief Sets the previous node of the given node.
 *
 * \param node Node to set the previous node to.
 * \param prev Previous node to set.
 */
void dnslib_node_set_previous(dnslib_node_t *node, dnslib_node_t *prev);

/*!
 * \brief Returns the NSEC3 node corresponding to the given node.
 *
 * \param node Node to get the NSEC3 node for.
 *
 * \return NSEC3 node corresponding to \a node (i.e. node with owner name
 *         created by concatenating the hash of owner domain name of \a node
 *         and the name of the zone \a node belongs to).
 * \retval NULL if the NSEC3 node is not set.
 */
const dnslib_node_t *dnslib_node_nsec3_node(const dnslib_node_t *node);

/*!
 * \brief Sets the corresponding NSEC3 node of the given node.
 *
 * \param node Node to set the NSEC3 node to.
 * \param nsec3_node NSEC3 node to set.
 */
void dnslib_node_set_nsec3_node(dnslib_node_t *node, dnslib_node_t *nsec3_node);

/*!
 * \brief Returns the owner of the node.
 *
 * \param node Node to get the owner of.
 *
 * \return Owner of the given node.
 */
const dnslib_dname_t *dnslib_node_owner(const dnslib_node_t *node);

dnslib_dname_t *dnslib_node_get_owner(const dnslib_node_t *node);

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
 * \param wildcard_child Wildcard child of the node.
 */
void dnslib_node_set_wildcard_child(dnslib_node_t *node,
                                    dnslib_node_t *wildcard_child);

const dnslib_node_t *dnslib_node_new_node(const dnslib_node_t *node);

void dnslib_node_set_new_node(dnslib_node_t *node,
                              dnslib_node_t *new_node);

/*!
 * \brief Mark the node as a delegation point.
 *
 * \param node Node to mark as a delegation point.
 */
void dnslib_node_set_deleg_point(dnslib_node_t *node);

/*!
 * \brief Checks if the node is a delegation point.
 *
 * \param node Node to check.
 *
 * \retval <> 0 if \a node is marked as delegation point.
 * \retval 0 otherwise.
 */
int dnslib_node_is_deleg_point(const dnslib_node_t *node);

/*!
 * \brief Mark the node as non-authoritative.
 *
 * \param node Node to mark as non-authoritative.
 */
void dnslib_node_set_non_auth(dnslib_node_t *node);

/*!
 * \brief Checks if the node is non-authoritative.
 *
 * \param node Node to check.
 *
 * \retval <> 0 if \a node is marked as non-authoritative.
 * \retval 0 otherwise.
 */
int dnslib_node_is_non_auth(const dnslib_node_t *node);

int dnslib_node_is_auth(const dnslib_node_t *node);

int dnslib_node_is_new(const dnslib_node_t *node);

int dnslib_node_is_old(const dnslib_node_t *node);

void dnslib_node_set_new(dnslib_node_t *node);

void dnslib_node_set_old(dnslib_node_t *node);

void dnslib_node_clear_new(dnslib_node_t *node);

void dnslib_node_clear_old(dnslib_node_t *node);

/*!
 * \brief Destroys the RRSets within the node structure.
 *
 * \param node Node to be destroyed.
 * \param free_rdata_dnames Set to <> 0 if you want to delete ALL domain names
 *                          present in RDATA. Set to 0 otherwise. (See
 *                          dnslib_rdata_deep_free().)
 */
void dnslib_node_free_rrsets(dnslib_node_t *node, int free_rdata_dnames);

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

/*!
 * \brief Compares two nodes according to their owner.
 *
 * \param node1 First node.
 * \param node2 Second node.
 *
 * \retval < 0 if \a node1 goes before \a node2 according to canonical order
 *         of their owner names.
 * \retval 0 if they are equal.
 * \retval > 0 if \a node1 goes after \a node2.
 */
int dnslib_node_compare(dnslib_node_t *node1, dnslib_node_t *node2);

int dnslib_node_deep_copy(const dnslib_node_t *from, dnslib_node_t **to);

#endif /* _KNOT_DNSLIB_NODE_H_ */

/*! @} */
