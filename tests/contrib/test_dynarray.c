/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "contrib/dynarray.h"
#include <tap/basic.h>

#define test_capacity 2

#define test_type(type, prefix) \
	dynarray_define(prefix, type, test_capacity) \
	static void prefix ## _test(type const first, type const second) { \
		struct prefix ## _dynarray array = { 0 }; \
		prefix ## _dynarray_fix(&array); \
		ok(array.capacity == test_capacity && array.size == 0, \
		   "%s: Fix - initial capacity set", #prefix); \
		prefix ## _dynarray_add(&array, &first); \
		ok(array.capacity == test_capacity && array.size == 1 && array.arr[0] == first, \
		   "%s: Add item", #prefix); \
		prefix ## _dynarray_add(&array, &second); \
		ok(array.capacity == test_capacity && array.size == 2 && array.arr[1] == second, \
		   "%s: Array filled (size not changed yet)", #prefix); \
		prefix ## _dynarray_add(&array, &first); \
		ok(array.capacity == 2*test_capacity+1 && array.size == 3 && array.arr[2] == first, \
		   "%s: Array extended", #prefix); \
		prefix ## _dynarray_free(&array); \
		prefix ## _dynarray_add(&array, &first); \
		ok(array.capacity == test_capacity && array.size == 1 && array.arr[0] == first, \
		   "%s: Free & add first- initial capacity set", #prefix); \
	}

test_type(int, int)
test_type(char*, string)

int main (int argc, char *argv[])
{
	plan_lazy();

	int_test(4, 2);
	char a = 'a', b = 'b';
	string_test(&a, &b);

	return 0;
}
