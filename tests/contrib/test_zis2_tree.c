/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <assert.h>

#include <tap/basic.h>

#include "contrib/zis2_tree.c"

static int hash_uint32_add(uint8_t *res, const uint8_t *input, size_t inlen, void *ctx, int alg)
{
	(void)ctx;
	(void)alg;
	assert(inlen % 4 == 0);
	*(uint32_t *)res = 0;
	for (unsigned i = 0; i < inlen / 4; i++) {
		*(uint32_t *)res += (*(const uint32_t *)(input + i * 4));
	}
	return 0;
}

int main(int argc, char *argv[])
{
	uint64_t out_hash = 0;
	uint8_t *oh = (uint8_t *)&out_hash;

	plan_lazy();

	zis2_tree_t *t = zis2_tree_new(3, 4, true, NULL);
	assert(t != NULL);

	uint8_t first[4] = { 1, 2 };
	ok(0 == zis2_tree_add(t, first), "add first");
	ok(0 == zis2_tree_hash(t, hash_uint32_add, NULL, oh), "rehash ok");
	is_int(*(uint32_t *)first + 6 /* bitmaps */, out_hash, "first hash");
	ok(0 == zis2_tree_check(t), "first tree ok");

	uint8_t second[4] = { 1, 3 };
	ok(0 == zis2_tree_add(t, second), "add second");
	ok(0 == zis2_tree_hash(t, hash_uint32_add, NULL, oh), "rehash ok");
	is_int(*(uint32_t *)first + *(uint32_t *)second + 6 + 8, out_hash, "second hash");
	ok(0 == zis2_tree_check(t), "second tree ok");

	uint8_t third[4] = { 2, 3 };
	ok(0 == zis2_tree_add(t, third), "add third");
	ok(0 == zis2_tree_hash(t, hash_uint32_add, NULL, oh), "rehash ok");
	is_int(*(uint32_t *)first + *(uint32_t *)second + *(uint32_t *)third + 6 + 8 + 12, out_hash, "third hash");
	ok(0 == zis2_tree_check(t), "third tree ok");

	uint8_t fourth[4] = { 1, 3, 0, 1 };
	ok(0 == zis2_tree_add(t, fourth), "add fourth");
	ok(0 == zis2_tree_hash(t, hash_uint32_add, NULL, oh), "rehash ok");
	is_int(*(uint32_t *)first + *(uint32_t *)second + *(uint32_t *)third + *(uint32_t *)fourth + 6 + 8 + 12, out_hash, "fourth hash");
	ok(0 == zis2_tree_check(t), "fourth tree ok");

	ok(0 == zis2_tree_add(t, first), "add existing first");
	ok(0 == zis2_tree_hash(t, hash_uint32_add, NULL, oh), "rehash ok");
	is_int(*(uint32_t *)first * 2 + *(uint32_t *)second + *(uint32_t *)third + *(uint32_t *)fourth + 6 + 8 + 12, out_hash, "refirst hash");
	ok(0 == zis2_tree_check(t), "refirst tree ok");

	ok(0 == zis2_tree_rem(t, second), "remove second");
	ok(0 == zis2_tree_hash(t, hash_uint32_add, NULL, oh), "rehash ok");
	ok(*(uint32_t *)first * 2 + *(uint32_t *)third + *(uint32_t *)fourth + 6 + 12, "without second hash");
	ok(0 == zis2_tree_check(t), "without second tree ok");

	ok(-ENOENT == zis2_tree_rem(t, second), "remove removed second");
	ok(0 == zis2_tree_check(t), "removal aborted tree ok");

	zis2_tree_free(t);
	return 0;
}

