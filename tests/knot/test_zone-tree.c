/*  Copyright (C) 2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <tap/basic.h>

#include "libknot/errcode.h"
#include "knot/zone/zone-tree.h"

#define NCOUNT 4
static knot_dname_t* NAME[NCOUNT];
static zone_node_t NODEE[NCOUNT];
static knot_dname_t* ORDER[NCOUNT];
static void ztree_init_data(void)
{
	NAME[0] = knot_dname_from_str_alloc(".");
	NAME[1] = knot_dname_from_str_alloc("master.ac.");
	NAME[2] = knot_dname_from_str_alloc("ac.");
	NAME[3] = knot_dname_from_str_alloc("ns.");

	knot_dname_t *order[NCOUNT] = {
	        NAME[0], NAME[2], NAME[1], NAME[3]
	};
	memcpy(ORDER, order, NCOUNT * sizeof(knot_dname_t*));

	for (unsigned i = 0; i < NCOUNT; ++i) {
		memset(NODEE + i, 0, sizeof(zone_node_t));
		NODEE[i].owner = NAME[i];
		NODEE[i].prev = NODEE + ((NCOUNT + i - 1) % NCOUNT);
		NODEE[i].rrset_count = 1; /* required for ordered search */
	}
}

static void ztree_free_data(void)
{
	for (unsigned i = 0; i < NCOUNT; ++i) {
		knot_dname_free(NAME[i], NULL);
	}
}

static int ztree_iter_data(zone_node_t *node, void *data)
{
	unsigned *i = (unsigned *)data;
	knot_dname_t *owner = node->owner;
	int result = KNOT_EOK;
	if (owner != ORDER[*i]) {
		result = KNOT_ERROR;
		char *exp_s = knot_dname_to_str_alloc(ORDER[*i]);
		char *owner_s = knot_dname_to_str_alloc(owner);
		diag("ztree: at index: %u expected '%s' got '%s'\n", *i, exp_s, owner_s);
		free(exp_s);
		free(owner_s);
	}
	++(*i);
	return result;
}

static int ztree_node_counter(zone_node_t *node, void *data)
{
	(void)node;
	int *counter = data;
	(*counter)++;
	return KNOT_EOK;
}

int main(int argc, char *argv[])
{
	plan_lazy();

	ztree_init_data();

	/* 1. create test */
	zone_tree_t* t = zone_tree_create(false);
	ok(t != NULL, "ztree: created");

	/* 2. insert test */
	unsigned passed = 1;
	for (unsigned i = 0; i < NCOUNT; ++i) {
		zone_node_t *node = NODEE + i;
		if (zone_tree_insert(t, &node) != KNOT_EOK) {
			passed = 0;
			break;
		}
	}
	ok(passed, "ztree: insertion");

	/* 3. check data test */
	passed = 1;
	for (unsigned i = 0; i < NCOUNT; ++i) {
		zone_node_t *node = zone_tree_get(t, NAME[i]);
		if (node == NULL || node != NODEE + i) {
			passed = 0;
			break;
		}
	}
	ok(passed, "ztree: lookup");

	/* 4. ordered lookup */
	zone_node_t *node = NULL;
	zone_node_t *prev = NULL;
	knot_dname_t *tmp_dn = knot_dname_from_str_alloc("z.ac.");
	zone_tree_get_less_or_equal(t, tmp_dn, &node, &prev);
	knot_dname_free(tmp_dn, NULL);
	ok(prev == NODEE + 1, "ztree: ordered lookup");

	/* 5. ordered traversal */
	unsigned i = 0;
	int ret = zone_tree_apply(t, ztree_iter_data, &i);
	ok (ret == KNOT_EOK, "ztree: ordered traversal");

	/* 6. subtree apply */
	int counter = 0;
	ret = zone_tree_sub_apply(t, (const knot_dname_t *)"\x02""ac", false, ztree_node_counter, &counter);
	ok(ret == KNOT_EOK && counter == 2, "ztree: subtree iteration");
	counter = 0;
	ret = zone_tree_sub_apply(t, (const knot_dname_t *)"\x02""ac", true, ztree_node_counter, &counter);
	ok(ret == KNOT_EOK && counter == 1, "ztree: subtree iteration excluding root");

	zone_tree_free(&t);
	ztree_free_data();
	return 0;
}
