#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include "common/general-tree.h"
#include "common/errors.h"

MOD_TREE_DEFINE(general_tree_node, avl);

static int gen_cmp_func(struct general_tree_node *n1,
                        struct general_tree_node *n2)
{
	void *data1 = n1->data;
	void *data2 = n2->data;
	assert(n1->cmp_func == n2->cmp_func);
	assert(n1->cmp_func);
	return n1->cmp_func(data1, data2);
}

static int gen_mrg_func(struct general_tree_node **n1,
                        struct general_tree_node **n2)
{
	void *data1 = (*n1)->data;
	void *data2 = (*n2)->data;
	assert((*n1)->mrg_func == (*n2)->mrg_func);
	return (*n1)->mrg_func(&data1, &data2);
}

static void gen_app_func(struct general_tree_node *n1, void *data)
{
	void *data_from_node = n1->data;
	assert(n1->app_func);
	n1->app_func(data_from_node, data);
}

static void gen_rem_func(struct general_tree_node *n1)
{
	free(n1);
}

static void gen_tree_init(general_tree_t *tree)
{
	MOD_TREE_INIT(tree->tree, gen_cmp_func, gen_mrg_func);
}

general_tree_t *gen_tree_new(int (*comp_func)(void *, void *),
                             int (*mrg_func)(void **, void **))
{
	general_tree_t *ret = malloc(sizeof(general_tree_t));
	printf("new %p\n", ret);
	ret->tree = malloc(sizeof(general_avl_tree_t));
//	CHECK_ALLOC_LOG(ret, NULL);
	ret->cmp_func = comp_func;
	ret->mrg_func = mrg_func;

	gen_tree_init(ret);
	return ret;
}

int gen_tree_add(general_tree_t *tree,
                 void *node)
{
	struct general_tree_node *tree_node =
		malloc(sizeof(struct general_tree_node));
//	CHECK_ALLOC_LOG(tree, -1);
	memset(tree_node, 0, sizeof(struct general_tree_node));
	tree_node->data = node;
	tree_node->cmp_func = tree->cmp_func;
	tree_node->mrg_func = tree->mrg_func;
	MOD_TREE_INSERT(tree->tree, general_tree_node, avl, tree_node);
	return 0;
}

void gen_tree_remove(general_tree_t *tree,
                     void *node)
{
	struct general_tree_node *tree_node =
		malloc(sizeof(struct general_tree_node));
//	CHECK_ALLOC_LOG(tree, -1);
	tree_node->data = node;
	tree_node->cmp_func = tree->cmp_func;
	tree_node->mrg_func = tree->mrg_func;
	MOD_TREE_REMOVE(tree->tree, general_tree_node, avl, tree_node,
	                gen_rem_func);
}

void *gen_tree_find(general_tree_t *tree,
                    void *what)
{
	assert(tree && what && tree->tree && tree->cmp_func);
	struct general_tree_node tree_node;
	tree_node.data = what;
	tree_node.cmp_func = tree->cmp_func;
	tree_node.mrg_func = tree->mrg_func;
	struct general_tree_node *found_node =
		MOD_TREE_FIND(tree->tree, general_tree_node, avl, &tree_node);
	if (found_node) {
		return found_node->data;
	} else {
		return NULL;
	}
}

void gen_tree_apply_inorder(general_tree_t *tree,
                            void (*app_func)
                            (void *node, void *data), void *data)
{
	MOD_TREE_FORWARD_APPLY(tree->tree, general_tree_node, avl,
	                   app_func, data);
}

