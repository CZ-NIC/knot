/*!
 * \file dname-table.h
 *
 * \author Jan Kadlec <jan.kadlec.@nic.cz>
 *
 * \brief Structures representing dname table and functions for
 *        manipulating these structures.
 *
 * \addtogroup dnslib
 * @{
 */

#ifndef _KNOT_DNSLIB_DNAME_TABLE_H_
#define _KNOT_DNSLIB_DNAME_TABLE_H_

#include <config.h>

#include "common/tree.h"

#include "dnslib/dname.h"
#include "dnslib/dnslib-common.h"


/*!
 * \brief Structure encapsulating
 */
struct dname_table_node {
	dnslib_dname_t *dname; /*!< Dname stored in node. */
	TREE_ENTRY(dname_table_node) avl; /*!< Tree variables. */
};

/*!
 * \brief Tree structure.
 */
typedef TREE_HEAD(avl, dname_table_node) table_tree_t;

/*!
 * \brief Structure holding tree together with dname ID counter.
 */
struct dnslib_dname_table {
	unsigned int id_counter; /*!< ID counter (starts from 1) */
	table_tree_t *tree;  /*!< AVL tree */
};

typedef struct dnslib_dname_table dnslib_dname_table_t;

/*!
 * \brief Creates new empty domain name table.
 *
 * \retval Created table on success.
 * \retval NULL on memory error.
 */
dnslib_dname_table_t *dnslib_dname_table_new();

/*!
 * \brief Finds name in the domain name table.
 *
 * \param table Domain name table to be searched.
 * \param dname Dname to be searched.
 *
 * \retval Pointer to found dname when dname is present in the table.
 * \retval NULL when dname is not present.
 */
dnslib_dname_t *dnslib_dname_table_find_dname(const dnslib_dname_table_t *table,
					      dnslib_dname_t *dname);

/*!
 * \brief Adds domain name to domain name table.
 *
 * \param table Domain name table to be added to.
 * \param dname Domain name to be added.
 *
 * \warning Function does not check for duplicates!
 *
 * \note This function encapsulates dname in a structure and saves it to a tree.
 *
 * \retval DNSLIB_EOK on success.
 * \retval DNSLIB_ENOMEM when memory runs out.
 */
int dnslib_dname_table_add_dname(dnslib_dname_table_t *table,
				 dnslib_dname_t *dname);

/*!
 * \brief Frees dname table without its nodes. Sets pointer to NULL.
 *
 * \param table Table to be freed.
 */
void dnslib_dname_table_free(dnslib_dname_table_t **table);

/*!
 * \brief Frees dname table and all its nodes (including dnames in the nodes)
 *        Sets pointer to NULL.
 *
 * \param table Table to be freed.
 */
void dnslib_dname_table_deep_free(dnslib_dname_table_t **table);

void dnslib_dname_table_tree_inorder_apply(const dnslib_dname_table_t *table,
            void (*applied_function)(struct dname_table_node *node,
                                     void *data),
            void *data);


#endif // _KNOT_DNSLIB_DNAME_TABLE_H_

/*! @} */

