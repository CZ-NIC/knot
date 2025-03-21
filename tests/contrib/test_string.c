/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <tap/basic.h>

#include <stdlib.h>

#include "contrib/string.h"

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
