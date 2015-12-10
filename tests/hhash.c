/*  Copyright (C) 2013 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <string.h>
#include <assert.h>
#include <tap/basic.h>

#include "libknot/libknot.h"
#include "contrib/hhash.h"
#include "contrib/macros.h"
#include "contrib/mempattern.h"
#include "contrib/ucw/mempool.h"

/* Test defines. */
#define ELEM_COUNT 65535
#define KEY_LEN(x) (strlen(x)+1)

/* Random key string generator for tests. */
static const char *alphabet = "0123abcdABCDwxyzWXYZ.-_";
char *test_randstr_mm(knot_mm_t *mm)
{
	unsigned len = (5 + rand() % 251) + 1;
	char *s = mm_alloc(mm, len * sizeof(char));
	for (unsigned i = 0; i < len - 1; ++i) {
		s[i] = alphabet[rand() % strlen(alphabet)];
	}
	s[len - 1] = '\0';
	return s;
}

/*! \brief Return true if 'cur' comes after 'prev'. */
static bool str_check_sort(const char *prev, const char *cur)
{
	if (prev == NULL) {
		return true;
	}

	int l1 = strlen(prev);
	int l2 = strlen(cur);
	int res = memcmp(prev, cur, MIN(l1, l2));
	if (res == 0) { /* Keys may be equal. */
		if (l1 > l2) { /* 'prev' is longer, breaks ordering. */
			return false;
		}
	} else if (res > 0){
		return false; /* Broken lexicographical order */
	}

	return true;
}

int main(int argc, char *argv[])
{
	plan(11);

	/* Create memory pool context. */
	struct mempool *pool = mp_new(64 * 1024);
	knot_mm_t mm;
	mm.ctx = pool;
	mm.alloc = (knot_mm_alloc_t)mp_alloc;
	mm.free = NULL;

	/* Create hashtable */
	int ret = KNOT_EOK;
	uint16_t len = 0;
	const char *key = "mykey", *cur = NULL, *prev = NULL;
	value_t val = (void*)0xdeadbeef, *rval = NULL;
	hhash_iter_t it;
	hhash_t *tbl = hhash_create_mm(ELEM_COUNT, &mm);
	ok(tbl != NULL, "hhash: create");
	if (tbl == NULL) {
		return KNOT_ERROR; /* No point in testing further on. */
	}

	/* Generate random keys. */
	char *keys[ELEM_COUNT];
	unsigned nfilled = 0;
	for (unsigned i = 0; i < ELEM_COUNT; ++i) {
		keys[i] = test_randstr_mm(&mm);
	}

	/* Insert single element. */
	ret = hhash_insert(tbl, key, KEY_LEN(key), val);
	ok(ret == KNOT_EOK, "hhash: insert single element");

	/* Retrieve nonexistent element. */
	cur = "nokey";
	rval = hhash_find(tbl, cur, KEY_LEN(cur));
	ok(rval == NULL, "hhash: find non-existent element");

	/* Retrieve single element. */
	rval = hhash_find(tbl, key, KEY_LEN(key));
	ok(rval != NULL, "hhash: find existing element");

	/* Fill the table. */
	for (unsigned i = 0; i < ELEM_COUNT; ++i) {
		ret = hhash_insert(tbl, keys[i], KEY_LEN(keys[i]), keys[i]);
		if (ret != KNOT_EOK) {
			nfilled = i;
			break;
		}
	}

	/* Check all keys integrity. */
	unsigned nfound = 0;
	for (unsigned i = 0; i < nfilled; ++i) {
		rval = hhash_find(tbl, keys[i], KEY_LEN(keys[i]));
		if (!rval || memcmp(*rval, keys[i], KEY_LEN(keys[i])) != 0) {
			break; /* Mismatch */
		}
		++nfound;
	}
	is_int(nfilled, nfound, "hhash: found all inserted keys");

	/* Test keys order index. */
	hhash_build_index(tbl);
	hhash_iter_begin(tbl, &it, true);
	while (!hhash_iter_finished(&it)) {
		cur = hhash_iter_key(&it, &len);
		if (!str_check_sort(prev, cur)) {
			break;
		}
		prev = cur;
		int strl = strlen(cur);
		assert(strl + 1 == len);
		hhash_iter_next(&it);
	}
	ok(hhash_iter_finished(&it), "hhash: passed order index checks");

	/* Retrieve all keys. */
	nfound = 0;
	hhash_iter_begin(tbl, &it, false);
	while (!hhash_iter_finished(&it)) {
		cur = hhash_iter_key(&it, &len);
		if (hhash_find(tbl, cur, len) == NULL) {
			break;
		} else {
			++nfound;
		}
		hhash_iter_next(&it);
	}
	ok(hhash_iter_finished(&it), "hhash: found all iterated keys");
	is_int(tbl->weight, nfound, "hhash: all iterated keys found");

	/* Test find less or equal. */
	prev = "mykey0"; /* mykey should precede it */
	hhash_find_leq(tbl, prev, KEY_LEN(prev), &rval);
	ok(rval && *rval == val, "hhash: find less or equal");

	/* Delete key and retrieve it. */
	ret = hhash_del(tbl, key, KEY_LEN(key));
	ok(ret == KNOT_EOK, "hhash: remove key");
	rval = hhash_find(tbl, key, KEY_LEN(key));
	ok(rval == NULL, "hhash: find removed element");

	/* Free all memory. */
	mp_delete(mm.ctx);
	return KNOT_EOK;
}
