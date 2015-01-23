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

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <tap/basic.h>

#include "libknot/internal/yparser/yparser.h"
#include "libknot/errcode.h"

const char *syntax =
	"a:\n"
	"a :\n"
	"a : #comment\n"
	"\n"
	"b:\"b\"\n"
	"b: \"b\"\n"
	"b:b#comment\n"
	"b: b #comment\n"
	"b :b\n"
	"b : b\n"
	"b: [b]#comment\n"
	"b: [ b] # comment\n"
	"b: [b ]\n"
	"b: [ b ]\n"
	"\n"
	" f:\"f\"\n"
	" f: \"f\"\n"
	" f:f#comment\n"
	" f: f #comment\n"
	" f :f\n"
	" f : f\n"
	" f: [f]#comment\n"
	" f: [ f] # comment\n"
	" f: [f ]\n"
	" f: [ f ]\n"
	"\n"
	"c: a b\n"
	"c: a,b\n"
	"c: a, b\n"
	"c: a ,b\n"
	"c: a , b\n"
	"c: [a b]\n"
	"c: [a,b]\n"
	"c: [a, b]\n"
	"c: [a ,b]\n"
	"c: [a , b]\n"
	"c: [ a , b ]\n"
	"\n"
	"-d:d\n"
	" -d:d\n"
	" - d:d\n"
	" - d: d\n"
	" - d :d\n"
	" - d : d\n"
	"\n"
	"e: \"a#b' c[d,]\"";

int main(int argc, char *argv[])
{
	plan_lazy();

	int ret;
	size_t line;

	yp_parser_t yparser;
	yp_parser_t *yp = &yparser;
	yp_init(yp);

	ret = yp_set_input_string(yp, syntax, strlen(syntax));
	ok(ret == KNOT_EOK, "set input string");

	line = 1;
	for (int i = 0; i < 3; i++) {
		ret = yp_parse(yp);
		ok(ret == KNOT_EOK, "parse %i. key0", i);
		ok(yp->key_len == 1 && yp->key[0] == 'a' &&
		   yp->data_len == 0 && yp->event == YP_EKEY0 &&
		   yp->line_count == line + i, "compare %i. key0", i);
	}

	line = 5;
	for (int i = 0; i < 10; i++) {
		ret = yp_parse(yp);
		ok(ret == KNOT_EOK, "parse %i. key0 with value", i);
		ok(yp->key_len == 1 && yp->key[0] == 'b' &&
		   yp->data_len == 1 && yp->key[0] == 'b' &&
		   yp->event == YP_EKEY0 && yp->line_count == line + i,
		   "compare %i. key0 with value", i);
	}

	line = 16;
	for (int i = 0; i < 10; i++) {
		ret = yp_parse(yp);
		ok(ret == KNOT_EOK, "parse %i. key1 with value", i);
		ok(yp->key_len == 1 && yp->key[0] == 'f' &&
		   yp->data_len == 1 && yp->key[0] == 'f' &&
		   yp->event == YP_EKEY1 && yp->line_count == line + i,
		   "compare %i. key1 with value", i);
	}

	line = 27;
	for (int i = 0; i < 11; i++) {
		ret = yp_parse(yp);
		ok(ret == KNOT_EOK, "parse %i. key0 with first value", i);
		ok(yp->key_len == 1 && yp->key[0] == 'c' &&
		   yp->data_len == 1 && yp->data[0] == 'a' &&
		   yp->event == YP_EKEY0 && yp->line_count == line + i,
		   "compare %i. key0 with first value", i);

		ret = yp_parse(yp);
		ok(ret == KNOT_EOK, "parse %i. key0 with second value", i);
		ok(yp->key_len == 1 && yp->key[0] == 'c' &&
		   yp->data_len == 1 && yp->data[0] == 'b' &&
		   yp->event == YP_EKEY0 && yp->line_count == line + i,
		   "compare %i. key0 with second value", i);
	}

	line = 39;
	for (int i = 0; i < 6; i++) {
		ret = yp_parse(yp);
		ok(ret == KNOT_EOK, "parse %i. id", i);
		ok(yp->key_len == 1 && yp->key[0] == 'd' &&
		   yp->data_len == 1 && yp->key[0] == 'd' &&
		   yp->event == YP_EID && yp->line_count == line + i,
		   "compare %i. id", i);
	}

	line = 46;
	ret = yp_parse(yp);
	ok(ret == KNOT_EOK, "parse key0 with quoted value");
	ok(yp->key_len == 1 && yp->key[0] == 'e' && yp->data_len == 10 &&
	   memcmp(yp->data, "a#b' c[d,]", yp->data_len) == 0 &&
	   yp->event == YP_EKEY0 && yp->line_count == line,
	   "compare key0 with quoted value");

	ret = yp_parse(yp);
	ok(ret == KNOT_EOF, "parse EOF");

	yp_deinit(yp);

	return 0;
}
