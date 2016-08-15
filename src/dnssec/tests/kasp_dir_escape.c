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

#include <stdlib.h>
#include <string.h>
#include <tap/basic.h>

#include "error.h"
#include "kasp/dir/escape.h"

static void test_function(int (*function)(const char *, char **),
			  const char *function_name,
			  const char *input, const char *expected)
{
	char *output = NULL;
	int result = function(input, &output);

	if (result == DNSSEC_EOK) {
		ok(output && expected && strcmp(output, expected) == 0,
		   "%s on '%s' succeeds", function_name, input);
	} else {
		ok(output == NULL && expected == NULL,
		   "%s on '%s' fails", function_name, input);
	}

	free(output);
}

static void test_escape(const char *input, const char *expected)
{
	test_function(escape_entity_name, "escape", input, expected);
}

static void test_unescape(const char *input, const char *expected)
{
	test_function(unescape_entity_name, "unescape", input, expected);
}

int main(int argc, char *argv[])
{
	plan_lazy();

	// escape safe strings

	test_escape("", "");
	test_escape("abc-xyz_012-789.com", "abc-xyz_012-789.com");
	test_escape("EXAMple.com", "example.com");
	test_escape("_.-AZaz09", "_.-azaz09");

	// escape unsafe strings

	test_escape("abc\\def", "abc\\x5cdef");
	test_escape("xyz/jkl", "xyz\\x2fjkl");
	test_escape("aaa?bbb#ccc*ddd", "aaa\\x3fbbb\\x23ccc\\x2addd");
	test_escape("!$%&()", "\\x21\\x24\\x25\\x26\\x28\\x29");

	// test safe unescape

	test_unescape("", "");
	test_unescape("abc-xyz_012-789.com", "abc-xyz_012-789.com");
	test_unescape("examPLE.net", NULL);
	test_unescape("@", NULL);

	// test unsafe unescape

	test_unescape("opq\\x40rst", "opq@rst");
	test_unescape("_\\x40-42\\x2eaz", "_@-42.az");
	test_unescape("\\x3f\\x2a\\x28\\x3d\\x22\\x27\\x5c\\x2f", "?*(=\"\'\\/");
	test_unescape("new\\x0aline", "new\nline");

	// invalid unsafe unescape

	test_unescape("a\\", NULL);
	test_unescape("a\\z", NULL);
	test_unescape("a\\x", NULL);
	test_unescape("a\\x00b", NULL);
	test_unescape("a\\xgg", NULL);

	// unicode escape

	test_escape("křemílek.cz", "k\\xc5\\x99em\\xc3\\xadlek.cz");
	test_escape("www.vochomůrka", "www.vochom\\xc5\\xafrka");

	// unicode unescape

	test_unescape("br\\xc4\\x8d\\xc3\\xa1ln\\xc3\\xadk.eu", "brčálník.eu");
	test_unescape("\\xc4\\x8dty\\xc5\\x99i.\\xc5\\xa1neci", "čtyři.šneci");

	return 0;
}
