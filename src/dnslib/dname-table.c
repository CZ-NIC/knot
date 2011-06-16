#include <assert.h>
#include <string.h>
#include <malloc.h>

#include "dnslib/dname-table.h"
#include "dnslib/node.h"
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
	assert(n1 && n2 && n1->dname && n2->dname);
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
		if (((int)data > 1) && (node->dname->node != NULL) &&
			(node->dname->node->owner == node->dname)) {
			dnslib_node_t *wildcard_child =
				(dnslib_node_t *)
				dnslib_node_wildcard_child(node->dname->node);

			if (wildcard_child != NULL) {
				/* Set the reference in wildcard to NULL
				 * double free prevention. */
				assert(wildcard_child->owner);
				wildcard_child->owner->node = NULL;
				fprintf(stderr,
				        "Setting null node for wildcard: %s\n"
				        "(from node: %s)\n",
			        dnslib_dname_to_str(wildcard_child->owner),
				        dnslib_dname_to_str(node->dname));
			}

//			fprintf(stderr, "Freeing node %p (dname: %s (%p) \n"
//			       "owner: %s (%p)\n",
//			       node->dname->node,
//			       dnslib_dname_to_str(node->dname),
//			       node->dname,
//			       dnslib_dname_to_str(node->dname->node->owner),
//			       node->dname->node->owner);
//			dnslib_node_free_rrsets(node->dname->node, 0);
//			dnslib_node_free(&node->dname->node, 0);
		} else if (node->dname && node->dname->node &&
		           node->dname->node->owner != node->dname) {
			fprintf(stderr, "not the same owner! %p %s owner %s "
			       "node adress: %p\n", node->dname->node,
			       dnslib_dname_to_str(node->dname),
			       dnslib_dname_to_str(node->dname->node->owner),
			       node->dname->node);
		}
//		dnslib_dname_free(&node->dname);
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
	assert(dname);
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

void dnslib_dname_table_deep_free(dnslib_dname_table_t **table,
                                  int destroy_nodes)
{
	if (table == NULL || *table == NULL) {
		return;
	}

	/* Walk the tree and free each node, but free the dnames. */
	TREE_POST_ORDER_APPLY((*table)->tree, dname_table_node, avl,
			      delete_dname_table_node,
	                      (void *) (1 + destroy_nodes));

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

