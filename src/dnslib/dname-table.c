#include <assert.h>
#include <string.h>
#include <malloc.h>

#include "dnslib/dname-table.h"
#include "dnslib/error.h"

/*!< Tree functions. */
TREE_DEFINE(dname_table_node, avl);

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
		dnslib_dname_free(&node->dname);
	}

	/*!< \todo it would be nice to set pointers to NULL. */
	free(node);
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
	assert(node->dname->id != 0);

	TREE_INSERT(table->tree, dname_table_node, avl, node);
	return DNSLIB_EOK;
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
            void (*applied_function)(struct dname_table_node *node,
                                     void *data),
            void *data)
{
	TREE_FORWARD_APPLY(table->tree, dname_table_node, avl,
	                   applied_function, data);
}

