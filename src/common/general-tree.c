#include <stdlib.h>
#include <assert.h>
#include "common/general-tree.h"
#include "common/errors.h"

TREE_DEFINE(general_tree_node, avl);

static int gen_cmp_func(struct general_tree_node *n1,
                        struct general_tree_node *n2)
{
	void *data1 = n1->data;
	void *data2 = n2->data;
	assert(n1->cmp_func == n2->cmp_func);
	return n1->cmp_func(data1, data2);
}

static void gen_tree_init(general_tree_t *tree)
{
	TREE_INIT(tree->tree, gen_cmp_func);
}

general_tree_t *gen_tree_new(int (*comp_func)(void *, void *))
{
	general_tree_t *ret = malloc(sizeof(general_tree_t));
	CHECK_ALLOC_LOG(ret, NULL);
	ret->cmp_func = comp_func;
	gen_tree_init(ret);
}

int gen_tree_add(general_tree_t *tree,
                 void *node)
{
	struct general_tree_node *tree_node =
		malloc(sizeof(struct general_tree_node));
	CHECK_ALLOC_LOG(tree, -1);
	tree_node->data = node;
	tree_node->cmp_func = tree->cmp_func;
	TREE_INSERT(tree->tree, general_tree, avl, tree_node);
	return 0;
}

void *gen_tree_find(general_tree_t *tree,
                    void *what)
{
	struct general_tree_node tree_node;
	tree_node.data = what;
	struct general_tree_node *found_node =
		TREE_FIND(tree->tree, general, avl, &tree_node);
	return found_node->data;
}

void gen_tree_apply_inorder(general_tree_t *tree,
                            void (*app_func)
                            (void *node, void *data), void *data)
{
	TREE_FORWARD_APPLY(tree->tree, avl, tree_node,
	                   app_func, data);
}

