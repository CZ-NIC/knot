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
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <string.h>
#include <tap/basic.h>

#include "libknot/error.h"
#include "utils/common/lookup.h"

static void check_search_ok(lookup_t *l, const char *in, const char *out)
{
	diag("Search for '%s'", in);
	int ret = lookup_search(l, in, strlen(in));
	is_int(KNOT_EOK, ret, "Check found");
	ok(strcmp(out, l->found.key) == 0, "Compare key");
	ok(strcmp(out, l->found.data) == 0, "Compare data");
	ok(l->iter.first_key == NULL, "Compare no first key");
	ok(l->iter.count == 1, "Compare 1 count");
}

static void check_search_multi(lookup_t *l, const char *in, const char *out,
                               const char *first, size_t count)
{
	diag("Search for '%s'", in);
	int ret = lookup_search(l, in, strlen(in));
	is_int(KNOT_EFEWDATA, ret, "Check found multi");
	ok(strcmp(out, l->found.key) == 0, "Compare key");
	ok(l->found.data == NULL, "Compare no data");
	ok(strcmp(first, l->iter.first_key) == 0, "Compare first key");
	ok(l->iter.count == count, "Compare count");
}

static void check_search_none(lookup_t *l, const char *in)
{
	diag("Search for '%s'", in);
	int ret = lookup_search(l, in, strlen(in));
	is_int(KNOT_ENOENT, ret, "Check not found");
	ok(l->found.key == NULL, "Check no key");
	ok(l->found.data == NULL, "Check no data");
}

static void init(lookup_t *l, const char **table)
{
	int ret = lookup_init(l);
	is_int(KNOT_EOK, ret, "Init");

	while (*table != NULL) {
		ret = lookup_insert(l, *table, (void *)*table);
		is_int(KNOT_EOK, ret, "Insert '%s'", *table);
		table++;
	}
}

static void test_search_basic(void)
{
	const char* table[] = {
		"aa",
		"bb",
		NULL
	};

	lookup_t l;
	init(&l, table);

	check_search_ok(&l, "a",  "aa");
	check_search_ok(&l, "aa", "aa");
	check_search_ok(&l, "b",  "bb");
	check_search_ok(&l, "bb", "bb");

	check_search_none(&l, "0");
	check_search_none(&l, "000");
	check_search_none(&l, "00000000000000000000000000000000000000000000");
	check_search_none(&l, "a0");
	check_search_none(&l, "ab");
	check_search_none(&l, "aaa");
	check_search_none(&l, "bbb");
	check_search_none(&l, "cc");
	check_search_none(&l, "ccc");
	check_search_none(&l, "cccccccccccccccccccccccccccccccccccccccccccc");

	check_search_multi(&l, "", "", "aa", 2);

	lookup_deinit(&l);
}

static void test_search_iter(void)
{
	const char* table[] = {
		"0",
		"ab",
		"abc",
		"abcd",
		"abc-1",
		"abc-99",
		"z",
		NULL
	};

	lookup_t l;
	init(&l, table);

	check_search_multi(&l, "",     "",     "0",     7);
	check_search_multi(&l, "a",    "ab",   "ab",    5);
	check_search_multi(&l, "ab",   "ab",   "ab",    5);
	check_search_multi(&l, "abc",  "abc",  "abc",   4);
	check_search_multi(&l, "abc-", "abc-", "abc-1", 2);

	lookup_deinit(&l);
}

int main(int argc, char *argv[])
{
	plan_lazy();

	diag("Search tests basic");
	test_search_basic();

	diag("Search tests multi-result");
	test_search_iter();

	return 0;
}
