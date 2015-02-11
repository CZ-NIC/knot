/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <stdbool.h>
#include <string.h>
#include <tap/basic.h>

#include "dname.h"

static void ok_length(const char *dname, size_t length, const char *info)
{
	ok(dname_length((uint8_t *)dname) == length,
	   "dname_length() for %s", info);
}

static void test_length(void)
{
	ok_length(NULL, 0, "NULL");
	ok_length("", 1, ".");
	ok_length("\x2""cz", 4, "cz.");
	ok_length("\x7""example""\x3""com", 13, "example.com.");
}

static bool dname_binary_equal(const uint8_t *one, const uint8_t *two)
{
	size_t length_one = dname_length(one);
	size_t length_two = dname_length(two);

	if (length_one != length_two) {
		return false;
	}

	return memcmp(one, two, length_one) == 0;
}

static void test_copy(void)
{
	const uint8_t *dname = (uint8_t *)"\x3""www""\x8""KNOT-DNS""\x2""cz";
	uint8_t *copy = dname_copy(dname);
	ok(dname_binary_equal(dname, copy), "dname_copy()");
	free(copy);
}

static void test_normalize(void)
{
	const uint8_t *norm = (uint8_t *)"\x6""random""\x6""domain""\x4""test";
	uint8_t denorm[] = "\x6""rAnDoM""\x6""doMAIN""\x4""TesT";

	dname_normalize(denorm);
	ok(dname_binary_equal(norm, denorm), "dname_normalize()");

	const char *anorm = "hello.world.domain";
	char adenorm[] = "Hello.World.DOmaIN.";

	dname_ascii_normalize(adenorm);
	ok(strcmp(anorm, adenorm) == 0, "dname_ascii_normalize()");
}

static void test_ascii(void)
{
	{
	const uint8_t *dname = (uint8_t *)"\3""try""\x5""ascii""\xa""conversion";
	const char *expect = "try.ascii.conversion";
	char *converted = dname_to_ascii(dname);
	ok(strcmp(converted, expect) == 0, "dname_to_ascii()");
	free(converted);
	}

	{
	const char *name = "not.very.easy.domain.name.";
	const uint8_t *expect = (uint8_t *)"\x3""not""\x4""very""\x4""easy"
					   "\x6""domain""\x4""name";
	uint8_t *converted = dname_from_ascii(name);
	ok(dname_binary_equal(converted, expect), "dname_from_ascii()");
	free(converted);
	}
}

int main(void)
{
	plan_lazy();

	test_length();
	test_copy();
	test_normalize();
	test_ascii();

	return 0;
}
