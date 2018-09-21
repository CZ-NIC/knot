/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <stdint.h>
#include <string.h>
#include <tap/basic.h>

#include "libknot/yparser/yparser.h"
#include "libknot/libknot.h"

const char *syntax_ok =
	"#comment\n"
	" # comment\n"
	"a:\n"
	"a :\n"
	"a : #comment\n"
	"\n"
	"b: \"b\"\n"
	"b: b #comment\n"
	"b : b\n"
	"b: [ b] # comment\n"
	"b: [b ]\n"
	"b: [ b ]\n"
	"\n"
	" f: \"f\"\n"
	" f: f #comment\n"
	" f : f\n"
	" f: [ f] # comment\n"
	" f: [f ]\n"
	" f: [ f ]\n"
	" f: [ \"f\" ]\n"
	"\n"
	"c: [a,b]\n"
	"c: [a, b]\n"
	"c: [a ,b]\n"
	"c: [a , b]\n"
	"c: [ a , b ]\n"
	"c: [ \"a\" , \"b\" ]\n"
	"\n"
	"- d: d\n"
	"- d : d # comment\n"
	"\n"
	"e: \"a#b' c[d,]\"\n"
	"\n"
	"zone:\n"
	"#comment\n"
	" # comment\n"
	"  -   domain: example. # comment\n"
	"      master: bind\n"
	"  - domain: example.\n"
	"    master: bind\n"
	"zone2:\n"
	"    - a: b # different indentation";

const char *syntax_error1 =
	"f:\n"
	"  -  a: b\n"
	"   - b: c\n";

const char *syntax_error2 =
	"f:\n"
	"  -  a: b\n"
	"      c: d\n";

const char *syntax_error3 =
	"f:\n"
	"   a: b\n"
	"  c: d\n";

const char *dname_ok =
	".:\n"
	"dom-ain:\n"
	"\\070-\\071.\\072.:";

const char *quotes_ok =
	"g: \"\"\n"
	"g: a\\ b\n"
	"g: \"\\# 1 00\"\n"
	"g: \"\\\"\\\"\"\n"
	"g: \" a \\\" b \\\" \\\"c\\\" \"\n"
	"g: \"\\@ \\[ \\# \\, \\]\"\n";

static void test_syntax_ok(yp_parser_t *yp)
{
	// OK input.
	int ret = yp_set_input_string(yp, syntax_ok, strlen(syntax_ok));
	is_int(KNOT_EOK, ret, "set input string");

	size_t line = 3;
	for (int i = 0; i < 3; i++) {
		ret = yp_parse(yp);
		is_int(KNOT_EOK, ret, "parse %i. key0", i);
		ok(yp->key_len == 1 && yp->key[0] == 'a' &&
		   yp->data_len == 0 && yp->event == YP_EKEY0 &&
		   yp->line_count == line + i, "compare %i. key0", i);
	}

	line += 4;
	for (int i = 0; i < 6; i++) {
		ret = yp_parse(yp);
		is_int(KNOT_EOK, ret, "parse %i. key0 with value", i);
		ok(yp->key_len == 1 && yp->key[0] == 'b' &&
		   yp->data_len == 1 && yp->data[0] == 'b' &&
		   yp->event == YP_EKEY0 && yp->line_count == line + i,
		   "compare %i. key0 with value", i);
	}

	line += 7;
	for (int i = 0; i < 7; i++) {
		ret = yp_parse(yp);
		is_int(KNOT_EOK, ret, "parse %i. key1 with value", i);
		ok(yp->key_len == 1 && yp->key[0] == 'f' &&
		   yp->data_len == 1 && yp->data[0] == 'f' &&
		   yp->event == YP_EKEY1 && yp->line_count == line + i,
		   "compare %i. key1 with value", i);
	}

	line += 8;
	for (int i = 0; i < 6; i++) {
		ret = yp_parse(yp);
		is_int(KNOT_EOK, ret, "parse %i. key0 with first value", i);
		ok(yp->key_len == 1 && yp->key[0] == 'c' &&
		   yp->data_len == 1 && yp->data[0] == 'a' &&
		   yp->event == YP_EKEY0 && yp->line_count == line + i,
		   "compare %i. key0 with first value", i);

		ret = yp_parse(yp);
		is_int(KNOT_EOK, ret, "parse %i. key0 with second value", i);
		ok(yp->key_len == 1 && yp->key[0] == 'c' &&
		   yp->data_len == 1 && yp->data[0] == 'b' &&
		   yp->event == YP_EKEY0 && yp->line_count == line + i,
		   "compare %i. key0 with second value", i);
	}

	line += 7;
	for (int i = 0; i < 2; i++) {
		ret = yp_parse(yp);
		is_int(KNOT_EOK, ret, "parse %i. id", i);
		ok(yp->key_len == 1 && yp->key[0] == 'd' &&
		   yp->data_len == 1 && yp->data[0] == 'd' &&
		   yp->event == YP_EID && yp->line_count == line + i,
		   "compare %i. id", i);
	}

	line += 3;
	ret = yp_parse(yp);
	is_int(KNOT_EOK, ret, "parse key0 with quoted value");
	ok(yp->key_len == 1 && yp->key[0] == 'e' && yp->data_len == 10 &&
	   memcmp(yp->data, "a#b' c[d,]", yp->data_len) == 0 &&
	   yp->event == YP_EKEY0 && yp->line_count == line,
	   "compare key0 with quoted value");

	line += 2;
	ret = yp_parse(yp);
	is_int(KNOT_EOK, ret, "parse key0");
	ok(yp->key_len == 4 && strcmp(yp->key, "zone") == 0 &&
	   yp->data_len == 0 &&
	   yp->event == YP_EKEY0 && yp->line_count == line,
	   "compare key0 value");

	line += 3;
	for (int i = 0; i < 2; i++) {
		ret = yp_parse(yp);
		is_int(KNOT_EOK, ret, "parse %i. id", i);
		ok(yp->key_len == 6 && strcmp(yp->key, "domain") == 0 &&
		   yp->data_len == 8 && strcmp(yp->data, "example.") == 0 &&
		   yp->event == YP_EID && yp->line_count == line + 2 * i,
		   "compare id");
		ret = yp_parse(yp);
		is_int(KNOT_EOK, ret, "parse %i. key1", i);
		ok(yp->key_len == 6 && strcmp(yp->key, "master") == 0 &&
		   yp->data_len == 4 && strcmp(yp->data, "bind") == 0 &&
		   yp->event == YP_EKEY1 && yp->line_count == line + 2 * i + 1,
		   "compare key1");
	}

	line += 4;
	ret = yp_parse(yp);
	is_int(KNOT_EOK, ret, "parse key0");
	ok(yp->key_len == 5 && strcmp(yp->key, "zone2") == 0 &&
	   yp->data_len == 0 &&
	   yp->event == YP_EKEY0 && yp->line_count == line,
	   "compare key0 value");
	ret = yp_parse(yp);
	is_int(KNOT_EOK, ret, "parse key1");
	ok(yp->key_len == 1 && strcmp(yp->key, "a") == 0 &&
	   yp->data_len == 1 && strcmp(yp->data, "b") == 0 &&
	   yp->event == YP_EID && yp->line_count == line + 1,
	   "compare key1 value");

	ret = yp_parse(yp);
	is_int(KNOT_EOF, ret, "parse EOF");
}

static void test_syntax_error(yp_parser_t *yp, const char *input)
{
	static int count = 1;

	int ret = yp_set_input_string(yp, input, strlen(input));
	is_int(KNOT_EOK, ret, "set error input string %i", count++);
	ret = yp_parse(yp);
	is_int(KNOT_EOK, ret, "parse key0");
	ret = yp_parse(yp);
	is_int(KNOT_EOK, ret, "parse key1");
	ret = yp_parse(yp);
	is_int(KNOT_YP_EINVAL_INDENT, ret, "parse key1 - invalid indentation");
}

static void test_dname(yp_parser_t *yp)
{
#define CHECK_DNAME(str) \
	ret = yp_parse(yp); \
	is_int(KNOT_EOK, ret, "parse dname " str); \
	ok(yp->key_len == strlen(str) && strcmp(yp->key, str) == 0 && yp->data_len == 0 && \
	   yp->event == YP_EKEY0 && yp->line_count == line++, "compare " str);

	// Dname key value.
	int ret = yp_set_input_string(yp, dname_ok, strlen(dname_ok));
	is_int(KNOT_EOK, ret, "set input string");

	size_t line = 1;
	CHECK_DNAME(".");
	CHECK_DNAME("dom-ain");
	CHECK_DNAME("\\070-\\071.\\072.");

}

static void test_quotes(yp_parser_t *yp)
{
#define CHECK_QUOTE(str) \
	ret = yp_parse(yp); \
	is_int(KNOT_EOK, ret, "parse quoted " str); \
	ok(yp->key_len == 1 && yp->key[0] == 'g' && \
	   yp->data_len == strlen(str) && strcmp(yp->data, str) == 0 && \
	   yp->event == YP_EKEY0 && yp->line_count == line++, "compare " str);

	int ret = yp_set_input_string(yp, quotes_ok, strlen(quotes_ok));
	is_int(KNOT_EOK, ret, "set input string");

	size_t line = 1;
	CHECK_QUOTE("");
	CHECK_QUOTE("a\\ b");
	CHECK_QUOTE("\\# 1 00");
	CHECK_QUOTE("\"\"");
	CHECK_QUOTE(" a \" b \" \"c\" ");
	CHECK_QUOTE("\\@ \\[ \\# \\, \\]");
}

int main(int argc, char *argv[])
{
	plan_lazy();

	yp_parser_t yp;
	yp_init(&yp);

	test_syntax_ok(&yp);
	test_syntax_error(&yp, syntax_error1);
	test_syntax_error(&yp, syntax_error2);
	test_syntax_error(&yp, syntax_error3);
	test_dname(&yp);
	test_quotes(&yp);

	yp_deinit(&yp);

	return 0;
}
