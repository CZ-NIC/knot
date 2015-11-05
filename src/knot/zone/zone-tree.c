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

#include "knot/zone/zone-tree.h"
#include "knot/zone/node.h"
#include "common/debug.h"
#include "common-knot/hattrie/hat-trie.h"

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

zone_tree_t* zone_tree_create()
{
	return hattrie_create();
}

/*----------------------------------------------------------------------------*/

size_t zone_tree_weight(const zone_tree_t* tree)
{
	return hattrie_weight(tree);
}

int zone_tree_is_empty(const zone_tree_t *tree)
{
	return zone_tree_weight(tree) == 0;
}

/*----------------------------------------------------------------------------*/

int zone_tree_insert(zone_tree_t *tree, zone_node_t *node)
{
	if (tree == NULL) {
		return KNOT_EINVAL;
	}

	assert(tree && node && node->owner);
	uint8_t lf[KNOT_DNAME_MAXLEN];
	knot_dname_lf(lf, node->owner, NULL);

	*hattrie_get(tree, (char*)lf+1, *lf) = node;
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int zone_tree_find(zone_tree_t *tree, const knot_dname_t *owner,
                          const zone_node_t **found)
{
	if (owner == NULL || found == NULL) {
		return KNOT_EINVAL;
	}

	return zone_tree_get(tree, owner, (zone_node_t **)found);
}

/*----------------------------------------------------------------------------*/

int zone_tree_get(zone_tree_t *tree, const knot_dname_t *owner,
                         zone_node_t **found)
{
	if (owner == NULL) {
    //    printf("zone_tree_get: no owner **************************\n");
		return KNOT_EINVAL;
	}

	if (zone_tree_is_empty(tree)) {
    //    printf("zone_tree_get: no tree **************************\n");
		return KNOT_ENONODE;
	}
    //int siss = knot_dname_size(owner);
    
	uint8_t lf[KNOT_DNAME_MAXLEN];
	knot_dname_lf(lf, owner, NULL);
    /*printf("===========================================\n");
    printf("-------------OWNER in ASCII----------\n");
    for (int i =0; i < siss; i++)
    {
        printf("\\%d",owner[i]);
    }
    printf("\n");
    printf("------------OWNER-----------\n");
    
    for (int i =0; i < siss; i++)
    {
        printf("%c",owner[i]);
    }
    printf("\n");
    
    
    printf("===========================================\n");
    printf("-------------LF in ASCII----------\n");
    for (int i =0; i < KNOT_DNAME_MAXLEN; i++)
    {
        printf("\\%d",lf[i]);
    }
    printf("\n");
    printf("-------------LF----------\n");
    
    for (int i =0; i < KNOT_DNAME_MAXLEN; i++)
    {
        printf("%c",lf[i]);
    }
    printf("\n");
    printf("===========================================\n");
     */
	value_t *val = hattrie_tryget(tree, (char*)lf+1, *lf);
	if (val == NULL) {
		*found = NULL;
        //printf("Found NULL\n");
	} else {
        //printf("Found Something\n");
		*found = (zone_node_t*)(*val);
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int zone_tree_find_less_or_equal(zone_tree_t *tree,
                                 const knot_dname_t *owner,
                                 const zone_node_t **found,
                                 const zone_node_t **previous)
{
	if (owner == NULL || found == NULL || previous == NULL) {
		return KNOT_EINVAL;
	}

	zone_node_t *f = NULL, *p = NULL;
	int ret = zone_tree_get_less_or_equal(tree, owner, &f, &p);

	*found = f;
	*previous = p;

	return ret;
}

/*----------------------------------------------------------------------------*/

int zone_tree_get_less_or_equal(zone_tree_t *tree,
                                const knot_dname_t *owner,
                                zone_node_t **found,
                                zone_node_t **previous)
{
	if (owner == NULL || found == NULL || previous == NULL) {
		return KNOT_EINVAL;
	}

	if (zone_tree_is_empty(tree)) {
		return KNOT_ENONODE;
	}

	uint8_t lf[KNOT_DNAME_MAXLEN];
	knot_dname_lf(lf, owner, NULL);

	value_t *fval = NULL;
	int ret = hattrie_find_leq(tree, (char*)lf+1, *lf, &fval);
	if (fval) {
		*found = (zone_node_t *)(*fval);
	}
	int exact_match = 0;
	if (ret == 0) {
		if (fval) {
			*previous = (*found)->prev;
		}
		exact_match = 1;
	} else if (ret < 0) {
		*previous = *found;
		*found = NULL;
	} else if (ret > 0) {
		/* Previous should be the rightmost node.
		 * For regular zone it is the node left of apex, but for some
		 * cases like NSEC3, there is no such sort of thing (name wise).
		 */
		/*! \todo We could store rightmost node in zonetree probably. */
		hattrie_iter_t *i = hattrie_iter_begin(tree, 1);
		*previous = *(zone_node_t **)hattrie_iter_val(i); /* leftmost */
		*previous = (*previous)->prev; /* rightmost */
		*found = NULL;
		hattrie_iter_free(i);
	}

	/* Previous node for proof must be non-empty and authoritative. */
	if (*previous &&
	    ((*previous)->rrset_count == 0 || (*previous)->flags & NODE_FLAGS_NONAUTH)) {
		*previous = (*previous)->prev;
	}

dbg_zone_exec_detail(
		char *name = knot_dname_to_str_alloc(owner);
		char *name_f = (*found != NULL)
			? knot_dname_to_str_alloc((*found)->owner)
			: "none";

		dbg_zone_detail("Searched for owner %s in zone tree.\n",
				name);
		dbg_zone_detail("Exact match: %d\n", exact_match);
		dbg_zone_detail("Found node: %p: %s.\n", *found, name_f);
		dbg_zone_detail("Previous node: %p.\n", *previous);

		free(name);
		if (*found != NULL) {
			free(name_f);
		}
);

	return exact_match;
}

/*----------------------------------------------------------------------------*/

zone_node_t *zone_tree_get_next(zone_tree_t *tree,
                                const knot_dname_t *owner)
{
	if (tree == NULL || owner == NULL) {
		return NULL;
	}

	uint8_t lf[KNOT_DNAME_MAXLEN];
	knot_dname_lf(lf, owner, NULL);

	value_t *fval = NULL;
	zone_node_t *n = NULL;
	(void)hattrie_find_next(tree, (char*)lf + 1, *lf, &fval);
	if (fval == NULL) {
		/* Return first node. */
		hattrie_iter_t *it = hattrie_iter_begin(tree, true);
		if (it == NULL) {
			return NULL;
		}
		fval = hattrie_iter_val(it);
		hattrie_iter_free(it);
	}

	n = (zone_node_t *)*fval;
	/* Next node must be non-empty and auth. */
	if (n->rrset_count == 0 || n->flags & NODE_FLAGS_NONAUTH) {
		return zone_tree_get_next(tree, n->owner);
	} else {
		return n;
	}
}

/*----------------------------------------------------------------------------*/

int zone_tree_remove(zone_tree_t *tree,
                     const knot_dname_t *owner,
                     zone_node_t **removed)
{
	if (owner == NULL) {
		return KNOT_EINVAL;
	}

	if (zone_tree_is_empty(tree)) {
		return KNOT_ENONODE;
	}

	uint8_t lf[KNOT_DNAME_MAXLEN];
	knot_dname_lf(lf, owner, NULL);

	value_t *rval = hattrie_tryget(tree, (char*)lf+1, *lf);
	if (rval == NULL) {
		return KNOT_ENOENT;
	} else {
		*removed = (zone_node_t *)(*rval);
	}


	hattrie_del(tree, (char*)lf+1, *lf);
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int zone_tree_apply_inorder(zone_tree_t *tree,
                            zone_tree_apply_cb_t function,
                            void *data)
{
	if (function == NULL) {
		return KNOT_EINVAL;
	}

	if (zone_tree_is_empty(tree)) {
		return KNOT_EOK;
	}

	int result = KNOT_EOK;

	hattrie_iter_t *i = hattrie_iter_begin(tree, 1);
	while(!hattrie_iter_finished(i)) {
		result = function((zone_node_t **)hattrie_iter_val(i), data);
		if (result != KNOT_EOK) {
			break;
		}
		hattrie_iter_next(i);
	}
	hattrie_iter_free(i);

	return result;
}

/*----------------------------------------------------------------------------*/

int zone_tree_apply(zone_tree_t *tree,
                    zone_tree_apply_cb_t function,
                    void *data)
{
	if (function == NULL) {
		return KNOT_EINVAL;
	}

	if (zone_tree_is_empty(tree)) {
        //printf("mesa sto zone tree apply to dentro adiase......\n");
		return KNOT_EOK;
	}

	return hattrie_apply_rev(tree, (int (*)(value_t*,void*))function, data);
}

/*----------------------------------------------------------------------------*/

void zone_tree_free(zone_tree_t **tree)
{
	if (tree == NULL || *tree == NULL) {
		return;
	}
	hattrie_free(*tree);
	*tree = NULL;
}

/*----------------------------------------------------------------------------*/

static int zone_tree_free_node(zone_node_t **node, void *data)
{
	UNUSED(data);
	if (node) {
		node_free(node, NULL);
	}
	return KNOT_EOK;
}

void zone_tree_deep_free(zone_tree_t **tree)
{
	if (tree == NULL || *tree == NULL) {
		return;
	}

	zone_tree_apply(*tree, zone_tree_free_node, NULL);
	zone_tree_free(tree);
}
