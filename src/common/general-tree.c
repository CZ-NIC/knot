#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "common/general-tree.h"
#include "common/errors.h"

MOD_TREE_DEFINE(general_tree_node, avl);

static void gen_rem_func(struct general_tree_node *n1)
{
	free(n1);
}

general_tree_t *gen_tree_new(int (*comp_func)(void *, void *))
{
	general_tree_t *ret = malloc(sizeof(general_tree_t));
	if (ret == NULL) {
		return NULL;
	}
	ret->tree = malloc(sizeof(general_avl_tree_t));
	if (ret->tree == NULL) {
		free(ret);
		return NULL;
	}
	MOD_TREE_INIT(ret->tree, comp_func);
	return ret;
}

int gen_tree_add(general_tree_t *tree,
                 void *node, int (*mrg_func)(void **n1, void **n2))
{
	struct general_tree_node *tree_node =
		malloc(sizeof(struct general_tree_node));
	if (tree_node == NULL) {
		return -1;
	}
	memset(tree_node, 0, sizeof(struct general_tree_node));
	tree_node->data = node;
	MOD_TREE_INSERT(tree->tree, general_tree_node, avl,
	                tree_node, mrg_func);
	return 0;
}

void gen_tree_remove(general_tree_t *tree,
                     void *what)
{
	struct general_tree_node tree_node;
	tree_node.data = what;
	MOD_TREE_REMOVE(tree->tree, general_tree_node, avl, &tree_node,
	                gen_rem_func);
}

void *gen_tree_find(general_tree_t *tree,
                    void *what)
{
	struct general_tree_node tree_node;
	tree_node.data = what;
	struct general_tree_node *found_node =
		MOD_TREE_FIND(tree->tree, general_tree_node, avl, &tree_node);
	if (found_node) {
		return found_node->data;
	} else {
		return NULL;
	}
}

int gen_tree_find_less_or_equal(general_tree_t *tree,
                                void *what,
                                void **found)
{
	struct general_tree_node *f = NULL, *prev = NULL;
	struct general_tree_node tree_node;
	tree_node.data = what;
	int exact_match =
		MOD_TREE_FIND_LESS_EQUAL(tree->tree, general_tree_node, avl,
	                                 &tree_node, &f, &prev);
	if (exact_match < 0) {
		*found = NULL;
		exact_match = 0;
	} else if (exact_match == 0) {
		assert(prev != NULL);
		*found = prev->data;
	} else {
		assert(f != NULL);
		*found = f->data;
	}
//	*found = (exact_match > 0) ? f->data : prev->data;
	return exact_match;
}

void gen_tree_apply_inorder(general_tree_t *tree,
                            void (*app_func)
                            (void *node, void *data), void *data)
{
	MOD_TREE_FORWARD_APPLY(tree->tree, general_tree_node, avl,
	                   app_func, data);
}

void gen_tree_destroy(general_tree_t **tree,
                      void (*dest_func)(void *node, void *data), void *data)
{
	MOD_TREE_DESTROY((*tree)->tree, general_tree_node, avl, dest_func,
	                 gen_rem_func, data);
	free((*tree)->tree);
	free(*tree);
	*tree = NULL;
}

void gen_tree_clear(general_tree_t *tree)
{
	MOD_TREE_DESTROY(tree->tree, general_tree_node, avl, NULL,
	                 gen_rem_func, NULL);
}

static void add_node_to_tree(void *n, void *data)
{
	general_tree_t *tree = (general_tree_t *)data;
	gen_tree_add(tree, n, NULL);
}

//static void print_node(void *n, void *data)
//{
//	printf("node: %p\n", n);
//}

static int gen_tree_copy_node(const struct general_tree_node *from,
                              struct general_tree_node **to)
{
	if (from == NULL) {
		return 0;
	}

	*to = malloc(sizeof(struct general_tree_node));
	if (*to == NULL) {
	       return -1;
	}
	memset(*to, 0, sizeof(struct general_tree_node));

	(*to)->data = from->data;
	(*to)->avl.avl_height = from->avl.avl_height;

	int ret = gen_tree_copy_node(from->avl.avl_left,
	                             &(*to)->avl.avl_left);
	if (ret != 0) {
		return ret;
	}

	ret = gen_tree_copy_node(from->avl.avl_right,
	                         &(*to)->avl.avl_right);
	if (ret != 0) {
		/*! \todo Partially cleaunp tree! */
	       (*to)->avl.avl_left = NULL;
	       return ret;
	}

	return 0;
}

general_tree_t *gen_tree_shallow_copy(general_tree_t *tree)
{
	general_tree_t *new_tree = malloc(sizeof(general_tree_t));
	if (new_tree == NULL) {
		return NULL;
	}
	new_tree->tree = malloc(sizeof(general_avl_tree_t));
	if (new_tree->tree == NULL) {
		free(new_tree);
		return NULL;
	}

	MOD_TREE_INIT(new_tree->tree, tree->tree->th_cmp);
	assert(new_tree->tree->th_cmp == tree->tree->th_cmp);

//	gen_tree_apply_inorder(tree, add_node_to_tree, new_tree);

	if (gen_tree_copy_node(tree->tree->th_root,
	                       &new_tree->tree->th_root) != 0) {
		return NULL;
	}

//	gen_tree_apply_inorder(tree, print_node, NULL);
//	printf("--------------------------\n");
//	gen_tree_apply_inorder(new_tree, print_node, NULL);

	/* XXX */

//	printf("new tree: %p from old tree: %p\n",
//	       new_tree, tree);

	return new_tree;
}

