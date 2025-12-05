/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <stdlib.h>
#include <tap/basic.h>

#include "libknot/errcode.h"
#include "knot/zone/zone-tree.h"

#define NCOUNT 4
static knot_dname_t* NAME[NCOUNT];
static zone_node_t* NODEE[NCOUNT];
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

	const char *rd = "\x02\x00\x01\x00";
	knot_rrset_t rr = { .rrs = { .count = 1, .size = 4, .rdata = (knot_rdata_t *)&rd } };

	for (unsigned i = 0; i < NCOUNT; ++i) {
		NODEE[i] = node_new(NAME[i], false, false, NULL);
		NODEE[i]->prev = *(NODEE + ((NCOUNT + i - 1) % NCOUNT));

		rr.owner = NAME[i];
		node_add_rrset(NODEE[i], &rr, NULL);
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
	if (!knot_dname_is_equal(owner, ORDER[*i])) {
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
		zone_node_t *node = NODEE[i];
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
		if (node == NULL || node != NODEE[i]) {
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
	ok(prev == NODEE[1], "ztree: ordered lookup");

	/* 5. ordered traversal */
	unsigned i = 0;
	int ret = zone_tree_apply(t, ztree_iter_data, &i);
	ok (ret == KNOT_EOK, "ztree: ordered traversal");

	/* 6. subtree apply */
	int counter = 0;
	ret = zone_tree_sub_apply(t, (const knot_dname_t *)"\x02""bc", false, ztree_node_counter, &counter);
	ok(ret == KNOT_EOK && counter == 0, "ztree: non-existing subtree");
	ret = zone_tree_sub_apply(t, (const knot_dname_t *)"\x02""ac", false, ztree_node_counter, &counter);
	ok(ret == KNOT_EOK && counter == 2, "ztree: subtree iteration");
	counter = 0;
	ret = zone_tree_sub_apply(t, (const knot_dname_t *)"\x02""ac", true, ztree_node_counter, &counter);
	ok(ret == KNOT_EOK && counter == 1, "ztree: subtree iteration excluding root");

	/* 7. subtree deletion */
	ret = zone_tree_del_subtree(t, (const knot_dname_t *)"\x02""ac", true);
	ok(ret == KNOT_EOK && zone_tree_get(t, NAME[1]) == NULL && zone_tree_get(t, NAME[2]) != NULL, "ztree: subtree deletion w/o root");
	ret = zone_tree_del_subtree(t, (const knot_dname_t *)"\x02""ns", false);
	ok(ret == KNOT_EOK && zone_tree_get(t, NAME[3]) == NULL, "ztree: subtree deletion with root");

	zone_tree_free(&t);

	// free exactly what left
	node_free_rrsets(NODEE[0], NULL);
	node_free(NODEE[0], NULL);
	node_free_rrsets(NODEE[2], NULL);
	node_free(NODEE[2], NULL);
	ztree_free_data();
	return 0;
}
