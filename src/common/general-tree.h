#ifndef _KNOT_COMMON_GENERAL_TREE_H_
#define _KNOT_COMMON_GENERAL_TREE_H_

#include "common/modified_tree.h"

typedef MOD_TREE_HEAD(tree, general_tree_node) general_avl_tree_t;

/* Define tree with void * nodes */
struct general_tree_node {
	MOD_TREE_ENTRY(general_tree_node) avl;
//	int (*cmp_func)(void *n1,
//	                void *n2);
//	int (*mrg_func)(void **n1,
//	                void **n2);
//	void (*app_func)(void *n,
//	                 void *data);
	void *data;
};

struct general_tree {
//	int (*cmp_func)(void *n1,
//	                void *n2);
//	int (*mrg_func)(void **n1,
//	                void **n2);
	general_avl_tree_t *tree;
};

typedef struct general_tree general_tree_t;

general_tree_t *gen_tree_new(int (*cmp_func)(void *p1, void *p2));

int gen_tree_add(general_tree_t *tree,
                 void *node,
                 int (*mrg_func)(void **n1, void **n2));

void *gen_tree_find(general_tree_t *tree,
                    void *what);

void gen_tree_remove(general_tree_t *tree,
                      void *what);

void gen_tree_apply_inorder(general_tree_t *tree,
                            void (*app_func)(void *node, void *data),
                            void *data);

void gen_tree_destroy(general_tree_t **tree,
                      void (*dest_func)(void *node, void *data), void *data);

int gen_tree_find_less_or_equal(general_tree_t *tree,
                                void *what,
                                void **found);

general_tree_t *gen_tree_shallow_copy(general_tree_t *tree);

#endif // _KNOT_COMMON_GENERAL_TREE_H_
