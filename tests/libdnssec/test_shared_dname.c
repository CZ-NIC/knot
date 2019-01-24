/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <stdbool.h>
#include <string.h>
#include <tap/basic.h>

#include "dname.c"

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
	return one && two && strcmp((char *)one, (char *)two) == 0;
}

static void test_copy(void)
{
	const uint8_t *dname = (uint8_t *)"\x3""www""\x8""KNOT-DNS""\x2""cz";
	uint8_t *copy = dname_copy(dname);
	ok(dname_binary_equal(dname, copy), "dname_copy()");
	free(copy);
}

static void test_equal(void)
{
	#define eq(a, b) dname_equal((uint8_t *)a, (uint8_t *)b)

	ok(eq("\x4""kiwi""\x4""limo", "\x4""kiwi""\x4""limo") == true,
	   "dname_equal() same");
	ok(eq("\x6""orange", "\x6""ORANGE") == true,
	   "dname_equal() case single label");
	ok(eq("\x6""Banana""\03""Tea", "\x6""bANAna""\x3""tea") == true,
	   "dname_equal() case two labels");
	ok(eq("\x4""Coco""\x4""MILK", "\x3""cow""\x4""milk") == false,
	   "dname_equal() different first");
	ok(eq("\x4""LIME""\x5""syrup", "\x4""LIme""\x4""beer") == false,
	   "dname_equal() different last");
	ok(eq("\x5""apple", "\x5""apple""\x5""shake") == false,
	   "dname_equal() a prefix of b");
	ok(eq("\x5""apple""\x5""juice", "\x5""apple") == false,
	   "dname_equal() b prefix of a");
}

int main(void)
{
	plan_lazy();

	test_length();
	test_copy();
	test_equal();

	return 0;
}
