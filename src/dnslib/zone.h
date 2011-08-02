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

#ifndef _KNOTDKNOT_ZONE_H_
#define _KNOTDKNOT_ZONE_H_

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

//typedef TREE_HEAD(avl_tree, knot_node) avl_tree_t;
//struct event_t;

/*----------------------------------------------------------------------------*/
/*!
 * \brief Return values for search functions.
 *
 * Used in knot_zone_find_dname() and knot_zone_find_dname_hash().
 */
enum knot_zone_retvals {
	KNOT_ZONE_NAME_FOUND = 1,
	KNOT_ZONE_NAME_NOT_FOUND = 0
};

typedef enum knot_zone_retvals knot_zone_retvals_t;

/*----------------------------------------------------------------------------*/

/*!
 * \brief Structure for holding DNS zone.
 *
 * \warning Make sure not to insert the same nodes using both the normal and
 *          NSEC3 functions. Although this will be successfull, it will produce
 *          double-free errors when destroying the zone.
 */
struct knot_zone {
	knot_dname_t *name;

	knot_zone_contents_t *contents;

	time_t version;

	void *data; /*!< Pointer to generic zone-related data. */
	int (*dtor)(struct knot_zone *); /*!< Data destructor. */
};

typedef struct knot_zone knot_zone_t;

/*----------------------------------------------------------------------------*/
/*!
 * \brief Creates new DNS zone.
 *
 * \param apex Node representing the zone apex.
 * \param node_count Number of authorative nodes in the zone.
 *
 * \return The initialized zone structure or NULL if an error occured.
 */
knot_zone_t *knot_zone_new(knot_node_t *apex, uint node_count,
                               int use_domain_table);

knot_zone_contents_t *knot_zone_get_contents(
	const knot_zone_t *zone);

const knot_zone_contents_t *knot_zone_contents(
	const knot_zone_t *zone);


time_t knot_zone_version(const knot_zone_t *zone);

void knot_zone_set_version(knot_zone_t *zone, time_t version);

const void *knot_zone_data(const knot_zone_t *zone);

void knot_zone_set_data(knot_zone_t *zone, void *data);

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
 * \retval KNOT_EOK
 * \retval KNOT_EBADARG
 * \retval KNOT_EBADZONE
 * \retval KNOT_EHASH
 *
 * \todo Replace tests of this function by tests of its zone-contents version.
 */
int knot_zone_add_node(knot_zone_t *zone, knot_node_t *node,
                         int create_parents, int use_domain_table);

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
 * \retval KNOT_EOK
 * \retval KNOT_EBADARG
 * \retval KNOT_EBADZONE
 *
 * \todo Replace tests of this function by tests of its zone-contents version.
 */
int knot_zone_add_nsec3_node(knot_zone_t *zone, knot_node_t *node,
                               int create_parents, int use_domain_table);

/*!
 * \brief Tries to find a node with the specified name in the zone.
 *
 * \param zone Zone where the name should be searched for.
 * \param name Name to find.
 *
 * \return Corresponding node if found, NULL otherwise.
 *
 * \todo Replace tests of this function by tests of its zone-contents version.
 */
knot_node_t *knot_zone_get_node(const knot_zone_t *zone,
                                    const knot_dname_t *name);

/*!
 * \brief Tries to find a node with the specified name among the NSEC3 nodes
 *        of the zone.
 *
 * \param zone Zone where the name should be searched for.
 * \param name Name to find.
 *
 * \return Corresponding node if found, NULL otherwise.
 *
 * \todo Replace tests of this function by tests of its zone-contents version.
 */
knot_node_t *knot_zone_get_nsec3_node(const knot_zone_t *zone,
                                          const knot_dname_t *name);

/*!
 * \brief Tries to find a node with the specified name in the zone.
 *
 * \note This function is identical to knot_zone_get_node(), only it returns
 *       constant reference.
 *
 * \param zone Zone where the name should be searched for.
 * \param name Name to find.
 *
 * \return Corresponding node if found, NULL otherwise.
 *
 * \todo Replace tests of this function by tests of its zone-contents version.
 */
const knot_node_t *knot_zone_find_node(const knot_zone_t *zone,
                                           const knot_dname_t *name);

/*!
 * \brief Tries to find a node with the specified name among the NSEC3 nodes
 *        of the zone.
 *
 * \note This function is identical to knot_zone_get_nsec3_node(), only it
 *       returns constant reference.
 *
 * \param zone Zone where the name should be searched for.
 * \param name Name to find.
 *
 * \return Corresponding node if found, NULL otherwise.
 *
 * \todo Replace tests of this function by tests of its zone-contents version.
 */
const knot_node_t *knot_zone_find_nsec3_node(const knot_zone_t *zone,
                                                 const knot_dname_t *name);

/*!
 * \brief Returns the apex node of the zone.
 *
 * \param zone Zone to get the apex of.
 *
 * \return Zone apex node.
 *
 * \todo Replace tests of this function by tests of its zone-contents version.
 */
const knot_node_t *knot_zone_apex(const knot_zone_t *zone);

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
 * \todo Replace tests of this function by tests of its zone-contents version.
 */
int knot_zone_tree_apply_postorder(knot_zone_t *zone,
                              void (*function)(knot_node_t *node, void *data),
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
 * \todo Replace tests of this function by tests of its zone-contents version.
 */
int knot_zone_tree_apply_inorder(knot_zone_t *zone,
                              void (*function)(knot_node_t *node, void *data),
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
 * \todo Replace tests of this function by tests of its zone-contents version.
 */
int knot_zone_tree_apply_inorder_reverse(knot_zone_t *zone,
                              void (*function)(knot_node_t *node, void *data),
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
 * \todo Replace tests of this function by tests of its zone-contents version.
 */
int knot_zone_nsec3_apply_postorder(knot_zone_t *zone,
                              void (*function)(knot_node_t *node, void *data),
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
 * \todo Replace tests of this function by tests of its zone-contents version.
 */
int knot_zone_nsec3_apply_inorder(knot_zone_t *zone,
                              void (*function)(knot_node_t *node, void *data),
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
 * \todo Replace tests of this function by tests of its zone-contents version.
 */
int knot_zone_nsec3_apply_inorder_reverse(knot_zone_t *zone,
                              void (*function)(knot_node_t *node, void *data),
                              void *data);

/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/

knot_zone_contents_t *knot_zone_switch_contents(knot_zone_t *zone,
                                          knot_zone_contents_t *new_contents);

/*!
 * \brief Correctly deallocates the zone structure, without deleting its nodes.
 *
 * Also sets the given pointer to NULL.
 *
 * \param zone Zone to be freed.
 */
void knot_zone_free(knot_zone_t **zone);

/*!
 * \brief Correctly deallocates the zone structure and all nodes within.
 *
 * Also sets the given pointer to NULL.
 *
 * \param zone Zone to be freed.
 * \param free_rdata_dnames Set to <> 0 if you want to delete ALL domain names
 *                          present in RDATA. Set to 0 otherwise. (See
 *                          knot_rdata_deep_free().)
 */
void knot_zone_deep_free(knot_zone_t **zone, int free_rdata_dnames);

#endif

/*! @} */
