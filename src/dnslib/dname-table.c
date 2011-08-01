#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "dnslib/dname-table.h"
#include "dnslib/error.h"

/*!< Tree functions. */
TREE_DEFINE(dname_table_node, avl);

struct dnslib_dname_table_fnc_data {
	void (*func)(dnslib_dname_t *dname, void *data);
	void *data;
};

static void dnslib_dname_table_apply(struct dname_table_node *node, void *data)
{
	assert(data != NULL);
	assert(node != NULL);
	struct dnslib_dname_table_fnc_data *d =
			(struct dnslib_dname_table_fnc_data *)data;
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
	if (data) {
		dnslib_dname_release(node->dname);
	}

	/*!< \todo it would be nice to set pointers to NULL. */
	free(node);
}

static void dnslib_dname_table_delete_subtree(struct dname_table_node *root)
{
	if (root == NULL) {
		return;
	}

	dnslib_dname_table_delete_subtree(root->avl.avl_left);
	dnslib_dname_table_delete_subtree(root->avl.avl_right);
	free(root);
}

static int dnslib_dname_table_copy_node(const struct dname_table_node *from,
                                        struct dname_table_node **to)
{
	if (from == NULL) {
		return DNSLIB_EOK;
	}

	*to = (struct dname_table_node *)
	      malloc(sizeof(struct dname_table_node));
	if (*to == NULL) {
		return DNSLIB_ENOMEM;
	}

	(*to)->dname = from->dname;
	dnslib_dname_retain((*to)->dname);
	(*to)->avl.avl_height = from->avl.avl_height;

	int ret = dnslib_dname_table_copy_node(from->avl.avl_left,
	                                       &(*to)->avl.avl_left);
	if (ret != DNSLIB_EOK) {
		return ret;
	}

	ret = dnslib_dname_table_copy_node(from->avl.avl_right,
	                                   &(*to)->avl.avl_right);
	if (ret != DNSLIB_EOK) {
		dnslib_dname_table_delete_subtree((*to)->avl.avl_left);
		(*to)->avl.avl_left = NULL;
		return ret;
	}

	return DNSLIB_EOK;
}

dnslib_dname_table_t *dnslib_dname_table_new()
{
	dnslib_dname_table_t *ret = malloc(sizeof(dnslib_dname_table_t));
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

dnslib_dname_t *dnslib_dname_table_find_dname(const dnslib_dname_table_t *table,
					      dnslib_dname_t *dname)
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
		dnslib_dname_retain(node->dname);

		return node->dname;
	}
}

int dnslib_dname_table_add_dname(dnslib_dname_table_t *table,
				 dnslib_dname_t *dname)
{
	if (dname == NULL || table == NULL) {
		return DNSLIB_EBADARG;
	}

	/* Node for insertion has to be created */
	struct dname_table_node *node =
		malloc(sizeof(struct dname_table_node));
	CHECK_ALLOC_LOG(node, DNSLIB_ENOMEM);

	node->dname = dname;
	node->avl.avl_height = 0;
	node->avl.avl_left = NULL;
	node->avl.avl_right = NULL;

	node->dname->id = table->id_counter++;
//	printf("Inserted dname got id %d\n", node->dname->id);
	assert(node->dname->id != 0);

	/* Increase reference counter. */
	dnslib_dname_retain(dname);

	TREE_INSERT(table->tree, dname_table_node, avl, node);
	return DNSLIB_EOK;
}

int dnslib_dname_table_add_dname2(dnslib_dname_table_t *table,
                                  dnslib_dname_t **dname)
{
	dnslib_dname_t *found_dname = NULL;

	if (table == NULL || dname == NULL || *dname == NULL) {
		return DNSLIB_EBADARG;
	}

//	char *name = dnslib_dname_to_str(*dname);
//	printf("Inserting name %s to dname table.\n", name);
//	free(name);

	/* Fetch dname, need to release it later. */
	found_dname = dnslib_dname_table_find_dname(table ,*dname);

	if (!found_dname) {
		/* Store reference in table. */
		return dnslib_dname_table_add_dname(table, *dname);
	} else {
		/*! \todo Remove the check for equality. */
		if (found_dname != *dname) {
			//name = dnslib_dname_to_str(found_dname);
			//printf("Already there: %s (%p)\n", name, found_dname);
			//free(name);

			/* Replace dname with found. */
			dnslib_dname_release(*dname);
			*dname = found_dname;
			return 1; /*! \todo Error code? */

		} else {

			/* If the dname is already in the table, there is already
			 * a reference to it.
			 */
			dnslib_dname_release(found_dname);
		}
	}

//	printf("Done.\n");

	return DNSLIB_EOK;
}

int dnslib_dname_table_shallow_copy(dnslib_dname_table_t *from,
                                    dnslib_dname_table_t *to)
{
	to->id_counter = from->id_counter;

	if (to->tree == NULL) {
		to->tree = malloc(sizeof(table_tree_t));
		if (to->tree == NULL) {
			ERR_ALLOC_FAILED;
			return DNSLIB_ENOMEM;
		}

		TREE_INIT(to->tree, compare_dname_table_nodes);
	}

	return dnslib_dname_table_copy_node(from->tree->th_root,
	                                    &to->tree->th_root);
}

void dnslib_dname_table_free(dnslib_dname_table_t **table)
{
	if (table == NULL || *table == NULL) {
		return;
	}

	/* Walk the tree and free each node, but not the dnames. */
	TREE_POST_ORDER_APPLY((*table)->tree, dname_table_node, avl,
			      delete_dname_table_node, 0);

	free(*table);
	*table = NULL;
}

void dnslib_dname_table_deep_free(dnslib_dname_table_t **table)
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

void dnslib_dname_table_tree_inorder_apply(const dnslib_dname_table_t *table,
            void (*applied_function)(dnslib_dname_t *node,
                                     void *data),
            void *data)
{
	struct dnslib_dname_table_fnc_data d;
	d.data = data;
	d.func = applied_function;

	TREE_FORWARD_APPLY(table->tree, dname_table_node, avl,
	                   dnslib_dname_table_apply, &d);
}

