/*!
 * @file zone-node.h
 *
 * Contains data structure for holding DNS data related to one domain
 * name (node of the notional zone tree) and routines to manipulate
 * the data.
 *
 * @todo CNAME chain should be resolved in advance not only by saving pointer
 *       to the next node in chain, but rather by having all the CNAME RRs
 *       somewhere in one place and saving only a pointer or index to this place
 */
#ifndef ZONE_NODE
#define ZONE_NODE

#include "common.h"
#include "skip-list.h"
#include <sys/types.h>
#include <ldns/rr.h>

/*----------------------------------------------------------------------------*/
/*!
 * @brief Data structure for holding DNS data related to one zone node.
 */
typedef struct zn_node {
	/*! @brief Skip list of RRSets. */
	skip_list *rrsets;

	/*! @brief Owner domain name of the node. */
	ldns_rdf *owner;

	/*! @brief Provide some extra information about the node. */
	uint8_t flags;

	union {
		/*! @brief Node with canonical name for this node's name. */
		struct zn_node *cname;

		/*! @brief Glue RRSets (may be both A and AAAA) */
		skip_list *glues;
	} ref;

	/*! @brief Next zone node (should be in canonical order). */
	struct zn_node *next;

	/*! @brief Previous zone node (should be in canonical order). */
	struct zn_node *prev;
} zn_node;

/*----------------------------------------------------------------------------*/
/*!
 * @brief Create a new zone node.
 *
 * @return Pointer to the created and initialized (empty) zone node. NULL if an
 *         error occured.
 */
zn_node *zn_create();

/*!
 * @brief Returns the owner domain name of the zone node.
 */
ldns_rdf *zn_owner( zn_node *node );

/*!
 * @brief Adds one RR to the given node.
 *
 * @param node Zone node to add the record to.
 * @param rr RR to be added into the zone node.
 *
 * If the node is empty, any RR can be inserted into it. If there are some
 * records present, their owner is always the same and the inserted RR must have
 * this owner as well.
 *
 * The RR is always inserted into proper RRSet. If there is no RRSet it should
 * be part of, a new RRSet is created.
 *
 * @retval 0 On success.
 * @retval TODO
 */
int zn_add_rr( zn_node *node, ldns_rr *rr );

/*!
 * @brief Adds a RRSet to the given node.
 *
 * @param node Zone node to add the record to.
 * @param rrset RRSet to be added into the zone node.
 *
 * If the node is empty, any RRSet can be inserted into it. If there are some
 * records present, their owner is always the same and the inserted RRSet must
 * have this owner as well.
 *
 * @retval 0 On success.
 * @retval TODO
 */
int zn_add_rrset( zn_node *node, ldns_rr_list *rrset );

/*!
 * @brief Finds a RR of the desired type in the node.
 *
 * @param node Zone node to search in.
 * @param type Desired type of the RR to be found.
 *
 * @return Pointer to the RR if found. NULL otherwise.
 */
ldns_rr_list *zn_find_rrset( const zn_node *node, ldns_rr_type type );

/*!
 * @brief Marks the node as delegation point.
 */
void zn_set_delegation_point( zn_node *node );

/*!
 * @brief Returns 1 if @a node is delegation point. Otherwise 0.
 */
int zn_is_delegation_point( const zn_node *node );

/*!
 * @brief Returns 1 if @a node holds a CNAME record. Otherwise 0.
 */
int zn_is_cname( const zn_node *node );

/*!
 * @brief Returns the node which holds the canonical name for @a node's owner.
 *
 * @param node Node which holds a CNAME RR.
 *
 * @retval Node with owner being the canonical name of @a node's owner if there
 *         is such in the zone.
 * @retval NULL otherwise or if @a node does not contain CNAME RR.
 */
zn_node *zn_get_cname( const zn_node *node );

/*!
 * @brief Returns the desired glue RRSet from the node.
 *
 * @param node Node to get the glue RRSet from.
 * @param type Type of the glue RRSet (may be only A or AAAA).
 *
 * @retval Glue RRSet of type @a type if @a node is a delegation point and has
 *         such glue stored.
 * @retval NULL otherwise.
 */
ldns_rr_list *zn_get_glue( const zn_node *node, ldns_rr_type type );

/*!
 * @brief Destroys the zone node, destroying all its RRSets and their RRs.
 *
 * @param node Pointer to pointer to the zone node.
 */
void zn_destroy( zn_node **node );

/*!
 * @brief Generic interface to zn_destroy() to be used from the zone data
 *        structure.
 *
 * @param item Pointer to the zn_node structure to be destroyed.
 */
void zn_destructor( void *item );

/*----------------------------------------------------------------------------*/

#endif
