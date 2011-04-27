#include <assert.h>
#include <string.h>
#include <malloc.h>

#include "dnslib/dname-table.h"
#include "dnslib/error.h"

/* Tree functions. */
TREE_DEFINE(dname_table_node, avl);

static int compare_dname_table_nodes(struct dname_table_node *n1,
                                     struct dname_table_node *n2)
{
	assert(n1 && n2);
	return (strncmp((char *)n1->dname->name, (char *)n2->dname->name,
	                (n1->dname->size < n2->dname->size) ?
	                (n1->dname->size):(n2->dname->size)));
}

static void delete_dname_table_node(struct dname_table_node *node, void *data)
{
	UNUSED(data);
	/*!< \todo it would be nice to set pointers to NULL, too. */
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
	return ret;
}

const dnslib_dname_t *dnslib_dname_table_find_dname(
	const dnslib_dname_table_t *table,
	const dnslib_dname_t *dname)
{
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

int dnslib_dname_table_add_dname(const dnslib_dname_table_t *table,
                                 const dnslib_dname_t *dname)
{
	/* Node for insertion has to be created */
	struct dname_table_node *node =
		malloc(sizeof(struct dname_table_node));
	CHECK_ALLOC_LOG(node, DNSLIB_ENOMEM);

	node->dname = dname;

	TREE_INSERT(table->tree, dname_table_node, avl, node);
	return DNSLIB_EOK;
}

void dnslib_dname_table_free(dnslib_dname_table_t **table)
{
	if (table == NULL || *table == NULL) {
		return;
	}

	/* Walk the tree and free each node, but not the dnames. */
	TREE_FORWARD_APPLY((*table)->tree, dname_table_node, avl,
	                   delete_dname_table_node, NULL);

	free(*table);
	*table = NULL;
}
