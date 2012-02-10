/*!
 * \file dname-table.h
 *
 * \author Jan Kadlec <jan.kadlec.@nic.cz>
 *
 * \brief Structures representing dname table and functions for
 *        manipulating these structures.
 *
 * \addtogroup libknot
 * @{
 */
/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _KNOT_DNAME_TABLE_H_
#define _KNOT_DNAME_TABLE_H_

#include <config.h>

#include "common/tree.h"

#include "dname.h"
#include "common.h"


/*!
 * \brief Structure encapsulating
 */
struct dname_table_node {
	knot_dname_t *dname; /*!< Dname stored in node. */
	TREE_ENTRY(dname_table_node) avl; /*!< Tree variables. */
};

/*!
 * \brief Tree structure.
 */
typedef TREE_HEAD(avl, dname_table_node) table_tree_t;

/*!
 * \brief Structure holding tree together with dname ID counter.
 */
struct knot_dname_table {
	unsigned int id_counter; /*!< ID counter (starts from 1) */
	table_tree_t *tree;  /*!< AVL tree */
};

typedef struct knot_dname_table knot_dname_table_t;

/*!
 * \brief Creates new empty domain name table.
 *
 * \retval Created table on success.
 * \retval NULL on memory error.
 */
knot_dname_table_t *knot_dname_table_new();

/*!
 * \brief Finds name in the domain name table.
 *
 * \note Reference count to dname will be incremented, caller is responsible
 *       for releasing it.
 *
 * \param table Domain name table to be searched.
 * \param dname Dname to be searched.
 *
 * \retval Pointer to found dname when dname is present in the table.
 * \retval NULL when dname is not present.
 */
knot_dname_t *knot_dname_table_find_dname(const knot_dname_table_t *table,
					      knot_dname_t *dname);

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
 * \retval KNOT_EOK on success.
 * \retval KNOT_ENOMEM when memory runs out.
 */
int knot_dname_table_add_dname(knot_dname_table_t *table,
                               knot_dname_t *dname);

/*!
 * \brief Adds domain name to domain name table and checks for duplicates.
 *
 * \param table Domain name table to be added to.
 * \param dname Domain name to be added.
 *
 * \note This function encapsulates dname in a structure and saves it to a tree.
 * \note If a duplicate is found, \a dname is replaced by the name from table.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_ENOMEM when memory runs out.
 */
int knot_dname_table_add_dname_check(knot_dname_table_t *table,
                                     knot_dname_t **dname);

/*!
 * \brief Creates a shallow copy of the domain name table.
 *
 * Expects an existing knot_dname_table_t structure to be passed via \a to,
 * and fills it with the same data (domain names) as the original. Actual
 * tree nodes are created, but domain names are not copied (just referenced).
 *
 * \param from Original domain name table.
 * \param to Copy of the domain name table.
 */
int knot_dname_table_shallow_copy(knot_dname_table_t *from,
                                    knot_dname_table_t *to);

/*!
 * \brief Frees dname table without its nodes. Sets pointer to NULL.
 *
 * \param table Table to be freed.
 */
void knot_dname_table_free(knot_dname_table_t **table);

/*!
 * \brief Frees dname table and all its nodes (and release dnames in the nodes)
 *        Sets pointer to NULL.
 *
 * \param table Table to be freed.
 */
void knot_dname_table_deep_free(knot_dname_table_t **table);

/*!
 * \brief Frees dname table and all its nodes (including dnames in the nodes)
 *        Sets pointer to NULL.
 *
 * \param table Table to be freed.
 */
void knot_dname_table_destroy(knot_dname_table_t **table);

/*!
 * \brief Encapsulation of domain name table tree traversal function.
 *
 * \param table Table containing tree to be traversed.
 * \param applied_function Function to be used to process nodes.
 * \param data Data to be passed to processing function.
 */
void knot_dname_table_tree_inorder_apply(const knot_dname_table_t *table,
            void (*applied_function)(knot_dname_t *dname,
                                     void *data),
            void *data);


/*!
 * \brief Dumps dname table to stderr.
 *
 * \param table Table to be dumped.
 */
void knot_dname_table_dump(const knot_dname_table_t *table);


#endif // _KNOT_DNAME_TABLE_H_

/*! @} */

