/*!
 * \file zone.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Zone structure and API for manipulating it.
 *
 * \addtogroup dnslib
 * @{
 */

#ifndef _KNOT_DNSLIB_ZONE_H_
#define _KNOT_DNSLIB_ZONE_H_

#include <time.h>

#include "dnslib/node.h"
#include "dnslib/dname.h"
#include "dnslib/nsec3.h"
#include "dnslib/dname-table.h"
#include "common/tree.h"
#include "common/acl.h"
#include "common/lists.h"
#include "dnslib/hash/cuckoo-hash-table.h"

/*----------------------------------------------------------------------------*/

typedef TREE_HEAD(avl_tree, dnslib_node) avl_tree_t;
struct event_t;

/*----------------------------------------------------------------------------*/
/*!
 * \brief Return values for search functions.
 *
 * Used in dnslib_zone_find_dname() and dnslib_zone_find_dname_hash().
 */
enum dnslib_zone_retvals {
	DNSLIB_ZONE_NAME_FOUND = 1,
	DNSLIB_ZONE_NAME_NOT_FOUND = 0
};

typedef enum dnslib_zone_retvals dnslib_zone_retvals_t;

/*----------------------------------------------------------------------------*/

/*!
 * \brief Structure for holding DNS zone.
 *
 * \warning Make sure not to insert the same nodes using both the normal and
 *          NSEC3 functions. Although this will be successfull, it will produce
 *          double-free errors when destroying the zone.
 */
struct dnslib_zone {
	dnslib_node_t *apex;       /*!< Apex node of the zone (holding SOA) */
	avl_tree_t *tree;          /*!< AVL tree for holding zone nodes. */
	avl_tree_t *nsec3_nodes;   /*!< AVL tree for holding NSEC3 nodes. */
	ck_hash_table_t *table;     /*!< Hash table for holding zone nodes. */
	uint node_count;
	dnslib_nsec3_params_t nsec3_params;

	/*! \brief Access control lists. */
	struct {
		acl_t *xfr_out;    /*!< ACL for xfr-out.*/
		acl_t *notify_in;  /*!< ACL for notify-in.*/
		acl_t *notify_out; /*!< ACL for notify-out.*/
	} acl;

	/*! \brief XFR-IN scheduler. */
	struct {
		list          **ifaces; /*!< List of availabel interfaces. */
		sockaddr_t     master;  /*!< Master server for xfr-in.*/
		struct event_t *timer;  /*!< Timer for REFRESH/RETRY. */
		struct event_t *expire; /*!< Timer for REFRESH. */
		int next_id;            /*!< ID of the next awaited SOA resp.*/
	} xfr_in;

	/*! \brief List of pending NOTIFY events. */
	list notify_pending;

	time_t version;

	dnslib_dname_table_t *dname_table;
};

typedef struct dnslib_zone dnslib_zone_t;

/*----------------------------------------------------------------------------*/
/*!
 * \brief Creates new DNS zone.
 *
 * \param apex Node representing the zone apex.
 * \param node_count Number of authorative nodes in the zone.
 *
 * \return The initialized zone structure or NULL if an error occured.
 */
dnslib_zone_t *dnslib_zone_new(dnslib_node_t *apex, uint node_count);

time_t dnslib_zone_version(const dnslib_zone_t *zone);

void dnslib_zone_set_version(dnslib_zone_t *zone, time_t version);

/*!
 * \brief Adds a node to the given zone.
 *
 * Checks if the node belongs to the zone, i.e. if its owner is a subdomain of
 * the zone's apex. It thus also forbids adding node with the same name as the
 * zone apex.
 *
 * \param zone Zone to add the node into.
 * \param node Node to add into the zone.
 *
 * \retval DNSLIB_EOK
 * \retval DNSLIB_EBADARG
 * \retval DNSLIB_EBADZONE
 * \retval DNSLIB_EHASH
 */
int dnslib_zone_add_node(dnslib_zone_t *zone, dnslib_node_t *node);

/*!
 * \brief Adds a node holding NSEC3 records to the given zone.
 *
 * Checks if the node belongs to the zone, i.e. if its owner is a subdomain of
 * the zone's apex. It does not check if the node really contains any NSEC3
 * records, nor if the name is a hash (as there is actually no way of
 * determining this).
 *
 * \param zone Zone to add the node into.
 * \param node Node to add into the zone.
 *
 * \retval DNSLIB_EOK
 * \retval DNSLIB_EBADARG
 * \retval DNSLIB_EBADZONE
 */
int dnslib_zone_add_nsec3_node(dnslib_zone_t *zone, dnslib_node_t *node);

/*!
 * \brief Tries to find a node with the specified name in the zone.
 *
 * \param zone Zone where the name should be searched for.
 * \param name Name to find.
 *
 * \return Corresponding node if found, NULL otherwise.
 */
dnslib_node_t *dnslib_zone_get_node(const dnslib_zone_t *zone,
                                    const dnslib_dname_t *name);

/*!
 * \brief Tries to find a node with the specified name among the NSEC3 nodes
 *        of the zone.
 *
 * \param zone Zone where the name should be searched for.
 * \param name Name to find.
 *
 * \return Corresponding node if found, NULL otherwise.
 */
dnslib_node_t *dnslib_zone_get_nsec3_node(const dnslib_zone_t *zone,
                                          const dnslib_dname_t *name);

/*!
 * \brief Tries to find a node with the specified name in the zone.
 *
 * \note This function is identical to dnslib_zone_get_node(), only it returns
 *       constant reference.
 *
 * \param zone Zone where the name should be searched for.
 * \param name Name to find.
 *
 * \return Corresponding node if found, NULL otherwise.
 */
const dnslib_node_t *dnslib_zone_find_node(const dnslib_zone_t *zone,
                                           const dnslib_dname_t *name);

/*!
 * \brief Tries to find domain name in the given zone using AVL tree.
 *
 * \param[in] zone Zone to search for the name.
 * \param[in] name Domain name to search for.
 * \param[out] node The found node (if it was found, otherwise it may contain
 *                  arbitrary node).
 * \param[out] closest_encloser Closest encloser of the given name in the zone.
 * \param[out] previous Previous domain name in canonical order.
 *
 * \retval DNSLIB_ZONE_NAME_FOUND if node with owner \a name was found.
 * \retval DNSLIB_ZONE_NAME_NOT_FOUND if it was not found.
 * \retval DNSLIB_EBADARG
 * \retval DNSLIB_EBADZONE
 */
int dnslib_zone_find_dname(const dnslib_zone_t *zone,
                           const dnslib_dname_t *name,
                           const dnslib_node_t **node,
                           const dnslib_node_t **closest_encloser,
                           const dnslib_node_t **previous);

/*!
 * \brief Finds previous name in canonical order to the given name in the zone.
 *
 * \param zone Zone to search for the name.
 * \param name Domain name to find the previous domain name of.
 *
 * \return Previous node in canonical order, or NULL if some parameter is wrong.
 */
const dnslib_node_t *dnslib_zone_find_previous(const dnslib_zone_t *zone,
                                               const dnslib_dname_t *name);

#ifdef USE_HASH_TABLE
/*!
 * \brief Tries to find domain name in the given zone using the hash table.
 *
 * \param[in] zone Zone to search for the name.
 * \param[in] name Domain name to search for.
 * \param[out] node The found node (if it was found, otherwise it may contain
 *                  arbitrary node).
 * \param[out] closest_encloser Closest encloser of the given name in the zone.
 * \param[out] previous Previous domain name in canonical order.
 *
 * \retval DNSLIB_ZONE_NAME_FOUND if node with owner \a name was found.
 * \retval DNSLIB_ZONE_NAME_NOT_FOUND if it was not found.
 * \retval DNSLIB_EBADARG
 * \retval DNSLIB_EBADZONE
 */
int dnslib_zone_find_dname_hash(const dnslib_zone_t *zone,
                                const dnslib_dname_t *name,
                                const dnslib_node_t **node,
                                const dnslib_node_t **closest_encloser);
#endif

/*!
 * \brief Tries to find a node with the specified name among the NSEC3 nodes
 *        of the zone.
 *
 * \note This function is identical to dnslib_zone_get_nsec3_node(), only it
 *       returns constant reference.
 *
 * \param zone Zone where the name should be searched for.
 * \param name Name to find.
 *
 * \return Corresponding node if found, NULL otherwise.
 */
const dnslib_node_t *dnslib_zone_find_nsec3_node(const dnslib_zone_t *zone,
                                                 const dnslib_dname_t *name);

/*!
 * \brief Finds NSEC3 node and previous NSEC3 node in canonical order,
 *        corresponding to the given domain name.
 *
 * This functions creates a NSEC3 hash of \a name and tries to find NSEC3 node
 * with the hashed domain name as owner.
 *
 * \param[in] zone Zone to search in.
 * \param[in] name Domain name to get the corresponding NSEC3 nodes for.
 * \param[out] nsec3_node NSEC3 node corresponding to \a name (if found,
 *                        otherwise this may be an arbitrary NSEC3 node).
 * \param[out] nsec3_previous The NSEC3 node immediately preceding hashed domain
 *                            name corresponding to \a name in canonical order.
 *
 * \retval DNSLIB_ZONE_NAME_FOUND if the corresponding NSEC3 node was found.
 * \retval DNSLIB_ZONE_NAME_NOT_FOUND if it was not found.
 * \retval DNSLIB_EBADARG
 * \retval DNSLIB_ENSEC3PAR
 * \retval DNSLIB_ECRYPTO
 * \retval DNSLIB_ERROR
 */
int dnslib_zone_find_nsec3_for_name(const dnslib_zone_t *zone,
                                    const dnslib_dname_t *name,
                                    const dnslib_node_t **nsec3_node,
                                    const dnslib_node_t **nsec3_previous);
/*!
 * \brief Returns the apex node of the zone.
 *
 * \param zone Zone to get the apex of.
 *
 * \return Zone apex node.
 */
const dnslib_node_t *dnslib_zone_apex(const dnslib_zone_t *zone);

/*!
 * \brief Optimizes zone by replacing domain names in RDATA with references to
 *        domain names present in zone (as node owners).
 *
 * \param zone Zone to adjust domain names in.
 */
void dnslib_zone_adjust_dnames(dnslib_zone_t *zone);

/*!
 * \brief Parses the NSEC3PARAM record stored in the zone.
 *
 * This function properly fills in the nsec3_params field of the zone structure
 * according to data stored in the NSEC3PARAM record. This is necessary to do
 * before any NSEC3 operations on the zone are requested, otherwise they will
 * fail (error DNSLIB_ENSEC3PAR).
 *
 * \note If there is no NSEC3PARAM record in the zone, this function clears
 *       the nsec3_params field of the zone structure (fills it with zeros).
 *
 * \param zone Zone to get the NSEC3PARAM record from.
 */
int dnslib_zone_load_nsec3param(dnslib_zone_t *zone);

/*!
 * \brief Checks if the zone uses NSEC3.
 *
 * This function will return 0 if the NSEC3PARAM record was not parse prior to
 * calling it.
 *
 * \param zone Zone to check.
 *
 * \retval <> 0 if the zone uses NSEC3.
 * \retval 0 if it does not.
 *
 * \see dnslib_zone_load_nsec3param()
 */
int dnslib_zone_nsec3_enabled(const dnslib_zone_t *zone);

/*!
 * \brief Returns the parsed NSEC3PARAM record of the zone.
 *
 * \note You must parse the NSEC3PARAM record prior to calling this function
 *       (dnslib_zone_load_nsec3param()).
 *
 * \param zone Zone to get the NSEC3PARAM record from.
 *
 * \return Parsed NSEC3PARAM from the zone or NULL if the zone does not use
 *         NSEC3 or the record was not parsed before.
 *
 * \see dnslib_zone_load_nsec3param()
 */
const dnslib_nsec3_params_t *dnslib_zone_nsec3params(const dnslib_zone_t *zone);

/*!
 * \brief Applies the given function to each regular node in the zone.
 *
 * This function uses post-order depth-first forward traversal, i.e. the
 * function is first recursively applied to subtrees and then to the root.
 *
 * \param zone Nodes of this zone will be used as parameters for the function.
 * \param function Function to be applied to each node of the zone.
 * \param data Arbitrary data to be passed to the function.
 */
void dnslib_zone_tree_apply_postorder(dnslib_zone_t *zone,
                              void (*function)(dnslib_node_t *node, void *data),
                              void *data);

/*!
 * \brief Applies the given function to each regular node in the zone.
 *
 * This function uses in-order depth-first forward traversal, i.e. the function
 * is first recursively applied to left subtree, then to the root and then to
 * the right subtree.
 *
 * \note This implies that the zone is stored in a binary tree. Is there a way
 *       to make this traversal independent on the underlying structure?
 *
 * \param zone Nodes of this zone will be used as parameters for the function.
 * \param function Function to be applied to each node of the zone.
 * \param data Arbitrary data to be passed to the function.
 */
void dnslib_zone_tree_apply_inorder(dnslib_zone_t *zone,
                              void (*function)(dnslib_node_t *node, void *data),
                              void *data);

/*!
 * \brief Applies the given function to each regular node in the zone.
 *
 * This function uses in-order depth-first reverse traversal, i.e. the function
 * is first recursively applied to right subtree, then to the root and then to
 * the left subtree.
 *
 * \note This implies that the zone is stored in a binary tree. Is there a way
 *       to make this traversal independent on the underlying structure?
 *
 * \param zone Nodes of this zone will be used as parameters for the function.
 * \param function Function to be applied to each node of the zone.
 * \param data Arbitrary data to be passed to the function.
 */
void dnslib_zone_tree_apply_inorder_reverse(dnslib_zone_t *zone,
                              void (*function)(dnslib_node_t *node, void *data),
                              void *data);

/*!
 * \brief Applies the given function to each NSEC3 node in the zone.
 *
 * This function uses post-order depth-first forward traversal, i.e. the
 * function is first recursively applied to subtrees and then to the root.
 *
 * \param zone NSEC3 nodes of this zone will be used as parameters for the
 *             function.
 * \param function Function to be applied to each node of the zone.
 * \param data Arbitrary data to be passed to the function.
 */
void dnslib_zone_nsec3_apply_postorder(dnslib_zone_t *zone,
                              void (*function)(dnslib_node_t *node, void *data),
                              void *data);

/*!
 * \brief Applies the given function to each NSEC3 node in the zone.
 *
 * This function uses in-order depth-first forward traversal, i.e. the function
 * is first recursively applied to left subtree, then to the root and then to
 * the right subtree.
 *
 * \note This implies that the zone is stored in a binary tree. Is there a way
 *       to make this traversal independent on the underlying structure?
 *
 * \param zone NSEC3 nodes of this zone will be used as parameters for the
 *             function.
 * \param function Function to be applied to each node of the zone.
 * \param data Arbitrary data to be passed to the function.
 */
void dnslib_zone_nsec3_apply_inorder(dnslib_zone_t *zone,
                              void (*function)(dnslib_node_t *node, void *data),
                              void *data);

/*!
 * \brief Applies the given function to each NSEC3 node in the zone.
 *
 * This function uses in-order depth-first reverse traversal, i.e. the function
 * is first recursively applied to right subtree, then to the root and then to
 * the left subtree.
 *
 * \note This implies that the zone is stored in a binary tree. Is there a way
 *       to make this traversal independent on the underlying structure?
 *
 * \param zone NSEC3 nodes of this zone will be used as parameters for the
 *             function.
 * \param function Function to be applied to each node of the zone.
 * \param data Arbitrary data to be passed to the function.
 */
void dnslib_zone_nsec3_apply_inorder_reverse(dnslib_zone_t *zone,
                              void (*function)(dnslib_node_t *node, void *data),
                              void *data);

/*!
 * \brief Correctly deallocates the zone structure, without deleting its nodes.
 *
 * Also sets the given pointer to NULL.
 *
 * \param zone Zone to be freed.
 */
void dnslib_zone_free(dnslib_zone_t **zone);

/*!
 * \brief Correctly deallocates the zone structure and all nodes within.
 *
 * Also sets the given pointer to NULL.
 *
 * \param zone Zone to be freed.
 * \param free_rdata_dnames Set to <> 0 if you want to delete ALL domain names
 *                          present in RDATA. Set to 0 otherwise. (See
 *                          dnslib_rdata_deep_free().)
 */
void dnslib_zone_deep_free(dnslib_zone_t **zone, int free_rdata_dnames);

#endif

/*! @} */
