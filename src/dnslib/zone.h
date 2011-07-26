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
#include "dnslib/hash/cuckoo-hash-table.h"

#include "dnslib/zone-tree.h"

#include "dnslib/zone-contents.h"

/*----------------------------------------------------------------------------*/

//typedef TREE_HEAD(avl_tree, dnslib_node) avl_tree_t;
//struct event_t;

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
	dnslib_dname_t *name;

	dnslib_zone_contents_t *contents;

	time_t version;

	void *data; /*!< Pointer to generic zone-related data. */
	int (*dtor)(struct dnslib_zone *); /*!< Data destructor. */
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
dnslib_zone_t *dnslib_zone_new(dnslib_node_t *apex, uint node_count,
                               int use_domain_table);

dnslib_zone_contents_t *dnslib_zone_get_contents(
	const dnslib_zone_t *zone);

const dnslib_zone_contents_t *dnslib_zone_contents(
	const dnslib_zone_t *zone);


time_t dnslib_zone_version(const dnslib_zone_t *zone);

void dnslib_zone_set_version(dnslib_zone_t *zone, time_t version);

const void *dnslib_zone_data(const dnslib_zone_t *zone);

void dnslib_zone_set_data(dnslib_zone_t *zone, void *data);

/*----------------------------------------------------------------------------*/
/* Zone contents functions. TODO: remove                                      */
/*----------------------------------------------------------------------------*/

/*!
 * \brief Adds a node to the given zone.
 *
 * Checks if the node belongs to the zone, i.e. if its owner is a subdomain of
 * the zone's apex. It thus also forbids adding node with the same name as the
 * zone apex.
 *
 * \warning This function may destroy domain names saved in the node, that
 *          are already present in the zone.
 *
 * \param zone Zone to add the node into.
 * \param node Node to add into the zone.
 *
 * \retval DNSLIB_EOK
 * \retval DNSLIB_EBADARG
 * \retval DNSLIB_EBADZONE
 * \retval DNSLIB_EHASH
 *
 * \todo Replace usages of this function by its zone-contents version.
 */
int dnslib_zone_add_node(dnslib_zone_t *zone, dnslib_node_t *node,
                         int create_parents, int use_domain_table);

/*!
 * \todo Replace usages of this function by its zone-contents version.
 */
int dnslib_zone_add_rrsigs(dnslib_zone_t *zone, dnslib_rrset_t *rrsigs,
                           dnslib_rrset_t **rrset, dnslib_node_t **node,
                           dnslib_rrset_dupl_handling_t dupl,
                           int use_domain_table);

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
 *
 * \todo Replace usages of this function by its zone-contents version.
 */
int dnslib_zone_add_nsec3_node(dnslib_zone_t *zone, dnslib_node_t *node,
                               int create_parents, int use_domain_table);

/*!
 * \todo Replace usages of this function by its zone-contents version.
 */
int dnslib_zone_add_nsec3_rrset(dnslib_zone_t *zone, dnslib_rrset_t *rrset,
                                dnslib_node_t **node,
                                dnslib_rrset_dupl_handling_t dupl,
                                int use_domain_table);

/*!
 * \brief Tries to find a node with the specified name in the zone.
 *
 * \param zone Zone where the name should be searched for.
 * \param name Name to find.
 *
 * \return Corresponding node if found, NULL otherwise.
 *
 * \todo Replace usages of this function by its zone-contents version.
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
 *
 * \todo Replace usages of this function by its zone-contents version.
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
 *
 * \todo Replace usages of this function by its zone-contents version.
 */
const dnslib_node_t *dnslib_zone_find_node(const dnslib_zone_t *zone,
                                           const dnslib_dname_t *name);

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
 *
 * \todo Replace usages of this function by its zone-contents version.
 */
const dnslib_node_t *dnslib_zone_find_nsec3_node(const dnslib_zone_t *zone,
                                                 const dnslib_dname_t *name);

/*!
 * \brief Returns the apex node of the zone.
 *
 * \param zone Zone to get the apex of.
 *
 * \return Zone apex node.
 *
 * \todo Replace usages of this function by its zone-contents version.
 */
const dnslib_node_t *dnslib_zone_apex(const dnslib_zone_t *zone);

/*!
 * \todo Replace usages of this function by its zone-contents version.
 */
dnslib_node_t *dnslib_zone_get_apex(const dnslib_zone_t *zone);

/*!
 * \brief Applies the given function to each regular node in the zone.
 *
 * This function uses post-order depth-first forward traversal, i.e. the
 * function is first recursively applied to subtrees and then to the root.
 *
 * \param zone Nodes of this zone will be used as parameters for the function.
 * \param function Function to be applied to each node of the zone.
 * \param data Arbitrary data to be passed to the function.
 *
 * \todo Replace usages of this function by its zone-contents version.
 */
int dnslib_zone_tree_apply_postorder(dnslib_zone_t *zone,
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
 *
 * \todo Replace usages of this function by its zone-contents version.
 */
int dnslib_zone_tree_apply_inorder(dnslib_zone_t *zone,
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
 *
 * \todo Replace usages of this function by its zone-contents version.
 */
int dnslib_zone_tree_apply_inorder_reverse(dnslib_zone_t *zone,
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
 *
 * \todo Replace usages of this function by its zone-contents version.
 */
int dnslib_zone_nsec3_apply_postorder(dnslib_zone_t *zone,
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
 *
 * \todo Replace usages of this function by its zone-contents version.
 */
int dnslib_zone_nsec3_apply_inorder(dnslib_zone_t *zone,
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
 *
 * \todo Replace usages of this function by its zone-contents version.
 */
int dnslib_zone_nsec3_apply_inorder_reverse(dnslib_zone_t *zone,
                              void (*function)(dnslib_node_t *node, void *data),
                              void *data);

/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/

dnslib_zone_contents_t *dnslib_zone_switch_contents(dnslib_zone_t *zone,
                                          dnslib_zone_contents_t *new_contents);

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
