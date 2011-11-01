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

#ifndef _KNOTD_COMMON_GENERAL_TREE_H_
#define _KNOTD_COMMON_GENERAL_TREE_H_

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

void gen_tree_clear(general_tree_t *tree);

int gen_tree_find_less_or_equal(general_tree_t *tree,
                                void *what,
                                void **found);

general_tree_t *gen_tree_shallow_copy(general_tree_t *tree);

#endif // _KNOTD_COMMON_GENERAL_TREE_H_
