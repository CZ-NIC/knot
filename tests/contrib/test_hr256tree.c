/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <assert.h>

#include <tap/basic.h>

#include "contrib/hr256tree.c"

static int hash_uint64_xor(uint8_t *res, uint8_t *childs[], unsigned nchilds, unsigned hash_len, void *ctx, int alg)
{
	*(uint64_t *)res = 0;
	for (unsigned i = 0; i < nchilds; i++) {
		*(uint64_t *)res ^= (*(const uint64_t *)childs[i]);
	}
	return 0;
}

static int check_sorted(hr256tree_t *t, hr256node_t *n)
{
	uint64_t last = 0;
	for (unsigned i = 0; isbranch(t, n) && i < n->size; i++) {
		uint64_t *h = (uint64_t *)(any_leaf_hash(t, go_child(t, n, i)));
		(void)check_sorted(t, go_child(t, n, i));
		assert(last < be64toh(*h));
		last = be64toh(*h);
	}
	return 0;
}

static int check_tree(hr256tree_t *t)
{
	if (t->root_h == NULL) {
		return 0;
	}
	return check_sorted(t, hash2node(t, t->root_h));
}

int main(int argc, char *argv[])
{
	uint8_t *hash;
	plan_lazy();

	hr256tree_t t = { .hash_len = 8 };
	check_tree(&t);

	uint8_t first[8] = { 1, 2 };
	ok(0 == hr256tree_add(&t, first), "add first");
	check_tree(&t);
	ok(0 == hr256tree_hash(&t, hash_uint64_xor, NULL, &hash), "rehash ok");
	ok(memcmp(hash, first, t.hash_len) == 0, "first is whole");

	uint8_t second[8] = { 1, 3 };
	ok(0 == hr256tree_add(&t, second), "add second");
	check_tree(&t);
	ok(0 == hr256tree_hash(&t, hash_uint64_xor, NULL, &hash), "rehash ok");
	ok(hash[1] == 1, "second byte xored");
	ok(t.alloc_size == 2 * leaf_size(&t) + branch_size(&t, INIT_CAPACITY), "three nodes alloc size");

	uint8_t third[8] = { 2, 3 };
	ok(0 == hr256tree_add(&t, third), "add third");
	check_tree(&t);
	ok(0 == hr256tree_hash(&t, hash_uint64_xor, NULL, &hash), "rehash ok");
	ok(hash[0] == 2, "third hash first byte");

	ok(-EEXIST == hr256tree_add(&t, first), "add existing first");
	check_tree(&t);

	ok(0 == hr256tree_rem(&t, first), "remove first");
	check_tree(&t);
	ok(0 == hr256tree_hash(&t, hash_uint64_xor, NULL, &hash), "rehash ok");
	ok(hash[1] == 0, "without first hash");

	ok(-ENOENT == hr256tree_rem(&t, first), "remove removed first");
	check_tree(&t);

	hr256tree_clear(&t);
	return 0;
}
