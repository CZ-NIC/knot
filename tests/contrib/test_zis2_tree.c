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

	zis2_tree_t *t = zis2_tree_new(4, 4, true, NULL);
	assert(t != NULL);

	uint8_t first[4] = { 1, 2 };
	ok(0 == zis2_tree_add(t, first), "add first");
	ok(0 == zis2_tree_hash(t, hash_uint32_add, NULL, oh), "rehash ok");
	zis2_tree_print(t);
	is_int(*(uint32_t *)first + 4 /* sizes throughout depth */ + 4 /* bitmaps */, out_hash, "first hash");
	ok(0 == zis2_tree_check(t), "first tree ok");

	/*uint8_t second[8] = { 1, 3 };
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
	check_tree(&t);*/

	zis2_tree_free(t);
	return 0;
}

