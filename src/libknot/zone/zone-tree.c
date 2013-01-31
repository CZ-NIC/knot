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
#include <stdlib.h>
#include <stdio.h>

#include "common/hattrie/hat-trie.h"
#include "zone-tree.h"
#include "zone/node.h"
#include "util/debug.h"

/*----------------------------------------------------------------------------*/
/* Non-API functions                                                          */
/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

knot_zone_tree_t* knot_zone_tree_create()
{
	return hattrie_create();
}

/*----------------------------------------------------------------------------*/

size_t knot_zone_tree_weight(knot_zone_tree_t* tree)
{
	return hattrie_weight(tree);
}

/*----------------------------------------------------------------------------*/

int knot_zone_tree_insert(knot_zone_tree_t *tree, knot_node_t *node)
{
	char *tmp = knot_dname_to_str(node->owner);
	free(tmp);
	assert(tree && node && node->owner);
	knot_dname_t* owner = node->owner;
	*hattrie_get(tree, owner->name, owner->size) = node;
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_zone_tree_find(knot_zone_tree_t *tree, const knot_dname_t *owner,
                          const knot_node_t **found)
{
	if (tree == NULL || owner == NULL || found == NULL) {
		return KNOT_EINVAL;
	}
	
	knot_node_t *f = NULL;
	int ret = knot_zone_tree_get(tree, owner, &f);
	*found = f;
	return ret;
}

/*----------------------------------------------------------------------------*/

int knot_zone_tree_get(knot_zone_tree_t *tree, const knot_dname_t *owner,
                         knot_node_t **found)
{
	if (tree == NULL || owner == NULL) {
		return KNOT_EINVAL;
	}

	value_t *val = hattrie_tryget(tree, owner->name, owner->size);
	if (val == NULL) {
		*found = NULL;
//		return KNOT_ENOENT;
	} else {
		*found = *val;
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_zone_tree_find_less_or_equal(knot_zone_tree_t *tree,
                                        const knot_dname_t *owner,
                                        const knot_node_t **found,
                                        const knot_node_t **previous)
{
	if (tree == NULL || owner == NULL || found == NULL || previous == NULL) {
		return KNOT_EINVAL;
	}
	
	knot_node_t *f, *p;
	int ret = knot_zone_tree_get_less_or_equal(tree, owner, &f, &p);

	*found = f;
	*previous = p;

	return ret;
}

/*----------------------------------------------------------------------------*/

int knot_zone_tree_get_less_or_equal(knot_zone_tree_t *tree,
                                       const knot_dname_t *owner,
                                       knot_node_t **found,
                                       knot_node_t **previous)
{
	assert(0);
	if (tree == NULL || owner == NULL || found == NULL
	    || previous == NULL) {
		return KNOT_EINVAL;
	}

	value_t* fval = NULL;
	int ret = hattrie_find_leq(tree, owner->name, owner->size, &fval);
	*found = *fval;
	if (ret == 0) {
		*previous = knot_node_get_previous(*found);
	}
	if (ret < 0) {
		*previous = *found;
		*found = NULL;
		ret = 0; /*! \todo why? */
	}
	if (ret > 0) {
		/* node is before first node in the trie */
		assert(0);
	}
	
	/*! \todo handle non-terminals ? */
	assert(!*previous || knot_node_rrset_count(*previous) > 0);

dbg_zone_exec_detail(
		char *name = knot_dname_to_str(owner);
		char *name_f = (*found != NULL)
			? knot_dname_to_str(knot_node_owner(*found))
			: "none";

		dbg_zone_detail("Searched for owner %s in zone tree.\n",
				name);
		dbg_zone_detail("Exact match: %d\n", ret);
		dbg_zone_detail("Found node: %p: %s.\n", *found, name_f);
		dbg_zone_detail("Previous node: %p.\n", *previous);

		free(name);
		if (*found != NULL) {
			free(name_f);
		}
);

	return ret;
}

/*----------------------------------------------------------------------------*/

int knot_zone_tree_remove(knot_zone_tree_t *tree,
                            const knot_dname_t *owner,
                          knot_zone_tree_node_t **removed)
{
	if (tree == NULL || owner == NULL) {
		return KNOT_EINVAL;
	}

	*removed = hattrie_tryget(tree, owner->name, owner->size);
	if (*removed == NULL) {
		return KNOT_ENOENT;
	}
	
	hattrie_del(tree, owner->name, owner->size);
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_zone_tree_apply_inorder(knot_zone_tree_t *tree,
                                 void (*function)(knot_zone_tree_node_t *node,
                                                  void *data),
                                 void *data)
{
	if (tree == NULL || function == NULL) {
		return KNOT_EINVAL;
	}

	hattrie_iter_t *i = hattrie_iter_begin(tree, 1);
	while(!hattrie_iter_finished(i)) {
		function(*hattrie_iter_val(i), data);
		hattrie_iter_next(i);
	}
	hattrie_iter_free(i);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_zone_tree_apply_recursive(knot_zone_tree_t *tree,
                                           void (*function)(
                                               knot_node_t *node,
                                               void *data),
                                           void *data)
{
	if (tree == NULL || function == NULL) {
		return KNOT_EINVAL;
	}
	
	hattrie_apply_rev(tree, function, data);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_zone_tree_apply(knot_zone_tree_t *tree,
                         void (*function)(knot_node_t *node, void *data),
                         void *data)
{
	hattrie_iter_t *i = hattrie_iter_begin(tree, 0);
	while(!hattrie_iter_finished(i)) {
		function(*hattrie_iter_val(i), data);
		hattrie_iter_next(i);
	}
	hattrie_iter_free(i);
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_zone_tree_shallow_copy(knot_zone_tree_t *from,
                                  knot_zone_tree_t **to)
{
	if (to == NULL || from == NULL) {
		return KNOT_EINVAL;
	}

	*to = hattrie_dup(from);
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_zone_tree_deep_copy(knot_zone_tree_t *from,
                             knot_zone_tree_t **to)
{
	if (to == NULL || from == NULL) {
		return KNOT_EINVAL;
	}

	*to = hattrie_dup(from);
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

void knot_zone_tree_free(knot_zone_tree_t **tree)
{
	if (tree == NULL || *tree == NULL) {
		return;
	}
	hattrie_free(*tree);
	*tree = NULL;
}

/*----------------------------------------------------------------------------*/

void knot_zone_tree_deep_free(knot_zone_tree_t **tree)
{
	if (tree == NULL || *tree == NULL) {
		return;
	}
	
	/*! \todo free node data */

	hattrie_free(*tree);
	*tree = NULL;
}

/*----------------------------------------------------------------------------*/
