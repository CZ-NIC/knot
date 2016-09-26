/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <tap/basic.h>

#include "libknot/errcode.h"
#include "knot/zone/zone-tree.h"

#define NCOUNT 4
static knot_dname_t* NAME[NCOUNT];
static zone_node_t NODE[NCOUNT];
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
		memset(NODE + i, 0, sizeof(zone_node_t));
		NODE[i].owner = NAME[i];
		NODE[i].prev = NODE + ((NCOUNT + i - 1) % NCOUNT);
		NODE[i].rrset_count = 1; /* required for ordered search */
	}
}

static void ztree_free_data(void)
{
	for (unsigned i = 0; i < NCOUNT; ++i)
		knot_dname_free(NAME + i, NULL);
}

static int ztree_iter_data(zone_node_t **node, void *data)
{
	unsigned *i = (unsigned *)data;
	knot_dname_t *owner = (*node)->owner;
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

int main(int argc, char *argv[])
{
	plan(5);

	ztree_init_data();

	/* 1. create test */
	zone_tree_t* t = zone_tree_create();
	ok(t != NULL, "ztree: created");

	/* 2. insert test */
	unsigned passed = 1;
	for (unsigned i = 0; i < NCOUNT; ++i) {
		if (zone_tree_insert(t, NODE + i) != KNOT_EOK) {
			passed = 0;
			break;
		}
	}
	ok(passed, "ztree: insertion");

	/* 3. check data test */
	passed = 1;
	zone_node_t *node = NULL;
	for (unsigned i = 0; i < NCOUNT; ++i) {
		int r = zone_tree_get(t, NAME[i], &node);
		if (r != KNOT_EOK || node != NODE + i) {
			passed = 0;
			break;
		}
	}
	ok(passed, "ztree: lookup");

	/* heal index for ordered lookup */
	hattrie_build_index(t);

	/* 4. ordered lookup */
	node = NULL;
	zone_node_t *prev = NULL;
	knot_dname_t *tmp_dn = knot_dname_from_str_alloc("z.ac.");
	zone_tree_get_less_or_equal(t, tmp_dn, &node, &prev);
	knot_dname_free(&tmp_dn, NULL);
	ok(prev == NODE + 1, "ztree: ordered lookup");

	/* 5. ordered traversal */
	unsigned i = 0;
	int ret = zone_tree_apply(t, ztree_iter_data, &i);
	ok (ret == KNOT_EOK, "ztree: ordered traversal");

	zone_tree_free(&t);
	ztree_free_data();
	return 0;
}
