/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <assert.h>

#include <tap/basic.h>

#include "contrib/hr_tree.c"

static const uint32_t zero = 0;

static int hash_uint16_xor(uint8_t *res, const uint8_t *a, const uint8_t *b, void *ctx, int alg)
{
	*(uint16_t *)res = (*(const uint16_t *)a) ^ (*(const uint16_t *)b);
	return 0;
}

static int hash_error(uint8_t *res, const uint8_t *a, const uint8_t *b, void *ctx, int alg)
{
	return -1;
}

static const uint8_t *check_node(hr_tree_t *t, hr_node_t *n)
{
	ok(n != NULL, "check node not NULL");

	if (!isbranch(t, n)) {
		return n->leaf_hash;
	}

	// check recursively
	const uint8_t *leaf_hash0 = check_node(t, n->childs[0]);
	const uint8_t *leaf_hash1 = check_node(t, n->childs[1]);

	// check branch hash
	uint8_t cmp_hash[t->hash_len];
	ok(hash_uint16_xor(cmp_hash, node_hash(t, n->childs[0]), node_hash(t, n->childs[1]), NULL, 0) == 0, "check branch rehash OK");
	if (memcmp(n->branch_hash, &zero, t->hash_len) != 0) {
                ok(memcmp(cmp_hash, n->branch_hash, t->hash_len) == 0, "check branch hash correct");
	}

	// check diff bit
	ok(n->branch_bit == bitarray_diff_idx(leaf_hash0, leaf_hash1, t->hash_len), "check branch bit");

	return leaf_hash0;
}

static void hr_tree_check(hr_tree_t *t)
{
	ok(t != NULL, "check tree not NULL");

	if (t->root != NULL) {
		uint8_t *hash;
		int ret = hr_tree_hash(t, hash_uint16_xor, NULL, &hash);
		ok(ret == 0, "rehash OK");
		(void)check_node(t, t->root);
	}
}

int main(int argc, char *argv[])
{
	uint8_t *hash;
	plan_lazy();

	hr_tree_t t = { .hash_len = 2 };
	hr_tree_check(&t);

	uint8_t first[2] = { 1, 2 };
	ok(0 == hr_tree_add(&t, first), "add first");
	hr_tree_check(&t);
	ok(0 == hr_tree_hash(&t, hash_uint16_xor, NULL, &hash), "rehash ok");
	ok(memcmp(hash, first, t.hash_len) == 0, "first is whole");

	uint8_t second[2] = { 1, 3 };
	ok(0 == hr_tree_add(&t, second), "add second");
	hr_tree_check(&t);
	ok(0 == hr_tree_hash(&t, hash_uint16_xor, NULL, &hash), "rehash ok");
	ok(hash[1] == 1, "second byte xored");
	ok(t.alloc_size == 2 * leaf_size(&t) + branch_size(&t), "three nodes alloc size");

	uint8_t third[2] = { 2, 3 };
	ok(0 == hr_tree_add(&t, third), "add third");
	hr_tree_check(&t);
	ok(0 == hr_tree_hash(&t, hash_uint16_xor, NULL, &hash), "rehash ok");
	ok(hash[0] == 2, "third hash first byte");

	ok(-EEXIST == hr_tree_add(&t, first), "add existing first");
	hr_tree_check(&t);

	ok(0 == hr_tree_rem(&t, first), "remove first");
	hr_tree_check(&t);
	ok(0 == hr_tree_hash(&t, hash_uint16_xor, NULL, &hash), "rehash ok");
	ok(hash[1] == 0, "without first hash");

	ok(-ENOENT == hr_tree_rem(&t, first), "remove removed first");
	hr_tree_check(&t);

	hr_tree_add(&t, first);
	ok(-1 == hr_tree_hash(&t, hash_error, NULL, &hash), "add with hash error");

	hr_tree_clear(&t);
	return 0;
}
