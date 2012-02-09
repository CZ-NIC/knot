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

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>

#include "zone/dname-table.h"
#include "util/error.h"

/*!< Tree functions. */
TREE_DEFINE(dname_table_node, avl);

struct knot_dname_table_fnc_data {
	void (*func)(knot_dname_t *dname, void *data);
	void *data;
};

static void knot_dname_table_apply(struct dname_table_node *node, void *data)
{
	assert(data != NULL);
	assert(node != NULL);
	struct knot_dname_table_fnc_data *d =
			(struct knot_dname_table_fnc_data *)data;
	d->func(node->dname, d->data);
}

/*!
 * \brief Comparison function to be used with tree.
 *
 * \param n1 First dname to be compared.
 * \param n2 Second dname to be compared.
 *
 * \return strncmp of dname's wireformats.
 */
static int compare_dname_table_nodes(struct dname_table_node *n1,
				     struct dname_table_node *n2)
{
	assert(n1 && n2);
	return (strncmp((char *)n1->dname->name, (char *)n2->dname->name,
			(n1->dname->size < n2->dname->size) ?
			(n1->dname->size):(n2->dname->size)));
}

/*!
 * \brief Deletes tree node along with its domain name.
 *
 * \param node Node to be deleted.
 * \param data If <> 0, dname in the node will be freed as well.
 */
static void delete_dname_table_node(struct dname_table_node *node, void *data)
{
	if ((ssize_t)data == 1) {
		knot_dname_release(node->dname);
	} else if ((ssize_t)data == 2) {
		knot_dname_free(&node->dname);
	}

	/*!< \todo it would be nice to set pointers to NULL. */
	free(node);
}

static void knot_dname_table_delete_subtree(struct dname_table_node *root)
{
	if (root == NULL) {
		return;
	}

	knot_dname_table_delete_subtree(root->avl.avl_left);
	knot_dname_table_delete_subtree(root->avl.avl_right);
	free(root);
}

static int knot_dname_table_copy_node(const struct dname_table_node *from,
                                        struct dname_table_node **to)
{
	if (from == NULL) {
		return KNOT_EOK;
	}

	*to = (struct dname_table_node *)
	      malloc(sizeof(struct dname_table_node));
	if (*to == NULL) {
		return KNOT_ENOMEM;
	}
	memset(*to, 0, sizeof(struct dname_table_node));

	(*to)->dname = from->dname;
	knot_dname_retain((*to)->dname);
	(*to)->avl.avl_height = from->avl.avl_height;

	int ret = knot_dname_table_copy_node(from->avl.avl_left,
	                                       &(*to)->avl.avl_left);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = knot_dname_table_copy_node(from->avl.avl_right,
	                                   &(*to)->avl.avl_right);
	if (ret != KNOT_EOK) {
		knot_dname_table_delete_subtree((*to)->avl.avl_left);
		(*to)->avl.avl_left = NULL;
		return ret;
	}

	return KNOT_EOK;
}

knot_dname_table_t *knot_dname_table_new()
{
	knot_dname_table_t *ret = malloc(sizeof(knot_dname_table_t));
	CHECK_ALLOC_LOG(ret, NULL);

	ret->tree = malloc(sizeof(table_tree_t));
	if (ret->tree == NULL) {
		ERR_ALLOC_FAILED;
		free(ret);
		return NULL;
	}

	TREE_INIT(ret->tree, compare_dname_table_nodes);

	ret->id_counter = 1;

	return ret;
}

knot_dname_t *knot_dname_table_find_dname(const knot_dname_table_t *table,
					      knot_dname_t *dname)
{
	if (table == NULL || dname == NULL) {
		return NULL;
	}

	struct dname_table_node *node = NULL;
	struct dname_table_node sought;
	sought.dname = dname;

	node = TREE_FIND(table->tree, dname_table_node, avl, &sought);

	if (node == NULL) {
		return NULL;
	} else {
		/* Increase reference counter. */
		knot_dname_retain(node->dname);

		return node->dname;
	}
}

int knot_dname_table_add_dname(knot_dname_table_t *table,
                               knot_dname_t *dname)
{
	if (dname == NULL || table == NULL) {
		return KNOT_EBADARG;
	}

	/* Node for insertion has to be created */
	struct dname_table_node *node =
		malloc(sizeof(struct dname_table_node));
	CHECK_ALLOC_LOG(node, KNOT_ENOMEM);
	
	// convert the dname to lowercase
	knot_dname_to_lower(dname);

	node->dname = dname;
	node->avl.avl_height = 0;
	node->avl.avl_left = NULL;
	node->avl.avl_right = NULL;

	node->dname->id = table->id_counter++;
	assert(node->dname->id != 0);

	/* Increase reference counter. */
	knot_dname_retain(dname);

	TREE_INSERT(table->tree, dname_table_node, avl, node);
	return KNOT_EOK;
}

int knot_dname_table_add_dname_check(knot_dname_table_t *table,
                                     knot_dname_t **dname)
{
	knot_dname_t *found_dname = NULL;

	if (table == NULL || dname == NULL || *dname == NULL) {
		return KNOT_EBADARG;
	}

	/* Fetch dname, need to release it later. */
	found_dname = knot_dname_table_find_dname(table ,*dname);

	if (!found_dname) {
		/* Store reference in table. */
		return knot_dname_table_add_dname(table, *dname);
	} else {
		/*! \todo Remove the check for equality. */
		if (found_dname != *dname) {
			/* Replace dname with found. */
			knot_dname_release(*dname);
			*dname = found_dname;
			return 1; /*! \todo Error code? */

		} else {
			/* If the dname is already in the table, there is already
			 * a reference to it.
			 */
			knot_dname_release(found_dname);
		}
	}

	return KNOT_EOK;
}

int knot_dname_table_shallow_copy(knot_dname_table_t *from,
                                    knot_dname_table_t *to)
{
	to->id_counter = from->id_counter;

	if (to->tree == NULL) {
		to->tree = malloc(sizeof(table_tree_t));
		if (to->tree == NULL) {
			ERR_ALLOC_FAILED;
			return KNOT_ENOMEM;
		}

		TREE_INIT(to->tree, compare_dname_table_nodes);
	}

	return knot_dname_table_copy_node(from->tree->th_root,
	                                    &to->tree->th_root);
}

void knot_dname_table_free(knot_dname_table_t **table)
{
	if (table == NULL || *table == NULL) {
		return;
	}

	/* Walk the tree and free each node, but not the dnames. */
	TREE_POST_ORDER_APPLY((*table)->tree, dname_table_node, avl,
			      delete_dname_table_node, 0);
	
	free((*table)->tree);

	free(*table);
	*table = NULL;
}

void knot_dname_table_deep_free(knot_dname_table_t **table)
{
	if (table == NULL || *table == NULL) {
		return;
	}

	/* Walk the tree and free each node, but free the dnames. */
	TREE_POST_ORDER_APPLY((*table)->tree, dname_table_node, avl,
			      delete_dname_table_node, (void *) 1);

	free((*table)->tree);

	free(*table);
	*table = NULL;
}

void knot_dname_table_destroy(knot_dname_table_t **table)
{
	if (table == NULL || *table == NULL) {
		return;
	}

	/* Walk the tree and free each node, but free the dnames. */
	TREE_POST_ORDER_APPLY((*table)->tree, dname_table_node, avl,
			      delete_dname_table_node, (void *) 2);

	free((*table)->tree);

	free(*table);
	*table = NULL;
}

void knot_dname_table_tree_inorder_apply(const knot_dname_table_t *table,
            void (*applied_function)(knot_dname_t *node,
                                     void *data),
            void *data)
{
	struct knot_dname_table_fnc_data d;
	d.data = data;
	d.func = applied_function;

	TREE_FORWARD_APPLY(table->tree, dname_table_node, avl,
	                   knot_dname_table_apply, &d);
}

static void knot_dump_node_of_table(knot_dname_t *dname, void *data)
{
	UNUSED(data);
	char *name = knot_dname_to_str(dname);
	fprintf(stderr, "%s (%p)\n", name, dname);
	free(name);
}

void knot_dname_table_dump(const knot_dname_table_t *table)
{
	fprintf(stderr, "-------DNAME TABLE-------\n");
	knot_dname_table_tree_inorder_apply(table, knot_dump_node_of_table,
	                                    NULL);
	fprintf(stderr, "-----END DNAME TABLE-----\n");
}

