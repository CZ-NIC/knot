/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <assert.h>

#include <tap/basic.h>

#include "contrib/hs_tree.c"

static int hash_uint64_xor(uint8_t *res, uint8_t *childs[], unsigned nchilds, unsigned hash_len, void *ctx, int alg)
{
	*(uint64_t *)res = 0;
	for (unsigned i = 0; i < nchilds; i++) {
		*(uint64_t *)res ^= (*(const uint64_t *)childs[i]);
	}
	return 0;
}

static int check_sorted(hs_tree_t *t, hs_node_t *n, unsigned depth)
{
	uint64_t last = 0;
	for (unsigned i = 0; i < n->size; i++) {
		uint64_t *h = (uint64_t *)(leaf_parent(t, depth) ? n->childs[i] : go_branch(t, n, i)->any_leaf);
		if (!leaf_parent(t, depth)) {
			(void)check_sorted(t, go_branch(t, n, i), depth + 1);
		}
		assert(last < be64toh(*h));
		last = be64toh(*h);
	}
	return 0;
}

static int check_tree(hs_tree_t *t)
{
	return check_sorted(t, child2node(t->rootp, t), 0);
}

int main(int argc, char *argv[])
{
	uint8_t *hash;
	plan_lazy();

	hs_tree_t t = { .hash_len = 8, .width_4bits = 2, .depth = 3 };
	uint8_t first[8] = { 1, 2 };
	ok(0 == hs_tree_add(&t, first), "add first");
	ok(0 == hs_tree_hash(&t, hash_uint64_xor, NULL, &hash), "rehash ok");
	ok(memcmp(hash, first, t.hash_len) == 0, "first is whole");
	check_tree(&t);

	uint8_t second[8] = { 1, 3 };
	ok(0 == hs_tree_add(&t, second), "add second");
	ok(0 == hs_tree_hash(&t, hash_uint64_xor, NULL, &hash), "rehash ok");
	ok(hash[1] == 1, "second byte xored");
	check_tree(&t);

	uint8_t third[8] = { 2, 3 };
	ok(0 == hs_tree_add(&t, third), "add third");
	ok(0 == hs_tree_hash(&t, hash_uint64_xor, NULL, &hash), "rehash ok");
	ok(hash[0] == 2, "third hash first byte");
	check_tree(&t);

	ok(-EEXIST == hs_tree_add(&t, first), "add existing first");
	check_tree(&t);

	ok(0 == hs_tree_rem(&t, first), "remove first");
	ok(0 == hs_tree_hash(&t, hash_uint64_xor, NULL, &hash), "rehash ok");
	ok(hash[1] == 0, "without first hash");
	check_tree(&t);

	ok(-ENOENT == hs_tree_rem(&t, first), "remove removed first");
	check_tree(&t);

	hs_tree_clear(&t);
	return 0;
}
