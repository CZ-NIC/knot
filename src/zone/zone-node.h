/*!
 * @file zone-node.h
 *
 * Contains data structure for holding DNS data related to one domain
 * name (node of the notional zone tree) and routines to manipulate
 * the data.
 *
 * @note This is only a very simple structure. To be modified and expanded in
 *       the future.
 * @todo Add support for adding arbitrary number of items.
 */
#ifndef ZONE_NODE
#define ZONE_NODE

#include "common.h"
#include "dns-simple.h"

/*----------------------------------------------------------------------------*/
/*!
 * @brief Data structure for holding DNS data related to one zone node.
 */
typedef struct zn_node {
	/*! @brief Array of pointers to DNS RRs. */
    dnss_rr **records;

	/*! @brief Count of the actual RRs in the structure. */
    uint count;

	/*! @brief Max allowed count of RRs in the structure */
    uint max_count;
} zn_node;

/*----------------------------------------------------------------------------*/
/*!
 * @brief Create a new zone node for the given @a count of RRs.
 *
 * @param count Count of RRs to be stored in the node. Cannot be
 *              modified later.
 *
 * @return Pointer to the created and initialized (empty) zone node. NULL if an
 *         error occured.
 */
zn_node *zn_create( uint count );

/*!
 * @brief Adds one RR to the given node.
 *
 * @param node Zone node to add the record to.
 * @param rr RR to be added into the zone node.
 *
 * @retval 0 On success.
 * @retval -1 if there is no space left in the zone node.
 */
int zn_add_rr( zn_node *node, dnss_rr *rr );

/*!
 * @brief Finds a RR of the desired type in the node.
 *
 * @param node Zone node to search in.
 * @param type Desired type of the RR to be found.
 *
 * @return Pointer to the RR if found. NULL otherwise.
 */
const dnss_rr *zn_find_rr( const zn_node *node, uint16_t type );

/*!
 * @brief Destroys the zone node, destroying all its RRs.
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
