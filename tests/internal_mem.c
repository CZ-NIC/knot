/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <tap/basic.h>

#include <stdlib.h>

#include "libknot/internal/mem.h"

static void test_strstrip(void)
{
	char *c = NULL;

	c = strstrip("hello");
	is_string("hello", c, "strstrip: no whitespace");
	free(c);

	c = strstrip("world \n");
	is_string("world", c, "strstrip: trailing whitespace");
	free(c);

	c = strstrip(" \n banana");
	is_string("banana", c, "strstrip: leading whitespace");
	free(c);

	c = strstrip(" \t hello  world   \n");
	is_string("hello  world", c, "strstrip: leading and trailing");
	free(c);

	c = strstrip("");
	is_string("", c, "strstrip: empty string");
	free(c);

	c = strstrip("   ");
	is_string("", c, "strstrip: just whitespaces");
	free(c);
}

int main(int argc, char *argv[])
{
	plan_lazy();

	test_strstrip();

	return 0;
}
