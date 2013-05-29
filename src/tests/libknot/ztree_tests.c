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

#include <config.h>
#include "tests/libknot/ztree_tests.h"
#include "libknot/zone/zone-tree.h"

#define NCOUNT 4
static knot_dname_t* NAME[NCOUNT];
static knot_node_t NODE[NCOUNT];
static knot_dname_t* ORDER[NCOUNT];
static void ztree_init_data()
{
	NAME[0] = knot_dname_new_from_str(".", 1, NULL);
	NAME[1] = knot_dname_new_from_str("master.ac.", 10, NULL);
	NAME[2] = knot_dname_new_from_str("ac.", 3, NULL);
	NAME[3] = knot_dname_new_from_str("ns.", 3, NULL);

	knot_dname_t *order[NCOUNT] = {
	        NAME[0], NAME[2], NAME[1], NAME[3]
	};
	memcpy(ORDER, order, NCOUNT * sizeof(knot_dname_t*));

	for (unsigned i = 0; i < NCOUNT; ++i) {
		memset(NODE + i, 0, sizeof(knot_node_t));
		NODE[i].owner = NAME[i];
		NAME[i]->node = NODE + i;
		NODE[i].prev = NODE + ((NCOUNT + i - 1) % NCOUNT);
		NODE[i].rrset_count = 1; /* required for ordered search */
	}
}

static void ztree_free_data()
{
	for (unsigned i = 0; i < NCOUNT; ++i)
		knot_dname_free(NAME + i);
}

struct ztree_iter {
	int ret;
	unsigned i;
};

static void ztree_iter_data(knot_node_t **node, void *data)
{
	struct ztree_iter *it = (struct ztree_iter*)data;
	knot_dname_t *owner = (*node)->owner;
	if (owner != ORDER[it->i]) {
		it->ret = KNOT_ERROR;
		char *exp_s = knot_dname_to_str(ORDER[it->i]);
		char *owner_s = knot_dname_to_str(owner);
		diag("ztree: at index: %u expected '%s' got '%s'\n", it->i, exp_s, owner_s);
		free(exp_s);
		free(owner_s);
	}
	++it->i;
}

static int ztree_tests_count(int argc, char *argv[]);
static int ztree_tests_run(int argc, char *argv[]);

unit_api ztree_tests_api = {
	"zone tree",
	&ztree_tests_count,
	&ztree_tests_run
};

static int ztree_tests_count(int argc, char *argv[])
{
	return 5;
}

static int ztree_tests_run(int argc, char *argv[])
{
	ztree_init_data();

	/* 1. create test */
	knot_zone_tree_t* t = knot_zone_tree_create();
	ok(t != NULL, "ztree: created");

	/* 2. insert test */
	unsigned passed = 1;
	for (unsigned i = 0; i < NCOUNT; ++i) {
		if (knot_zone_tree_insert(t, NODE + i) != KNOT_EOK) {
			passed = 0;
			break;
		}
	}
	ok(passed, "ztree: insertion");

	/* 3. check data test */
	passed = 1;
	const knot_node_t *node = NULL;
	for (unsigned i = 0; i < NCOUNT; ++i) {
		int r = knot_zone_tree_find(t, NAME[i], &node);
		if (r != KNOT_EOK || node != NODE + i) {
			passed = 0;
			break;
		}
	}
	ok(passed, "ztree: lookup");

	/* heal index for ordered lookup */
	hattrie_build_index(t);

	/* 4. ordered lookup */
	passed = 1;
	node = NULL;
	const knot_node_t *prev = NULL;
	knot_dname_t *tmp_dn = knot_dname_new_from_str("z.ac.", 5, NULL);
	knot_zone_tree_find_less_or_equal(t, tmp_dn, &node, &prev);
	knot_dname_free(&tmp_dn);
	ok(prev == NODE + 1, "ztree: ordered lookup");

	/* 5. ordered traversal */
	struct ztree_iter it = { KNOT_EOK, 0 };
	knot_zone_tree_apply_inorder(t, ztree_iter_data, &it);
	ok (it.ret == KNOT_EOK, "ztree: ordered traversal");

	knot_zone_tree_free(&t);
	ztree_free_data();
	return 0;
}
