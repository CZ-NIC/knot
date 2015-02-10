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

#include "libknot/internal/yparser/ypscheme.h"
#include "libknot/internal/yparser/yptrafo.h"
#include "libknot/errcode.h"

#define C_ID		"\x02""id"
#define C_INT		"\x07""integer"
#define C_BOOL		"\x04""bool"
#define C_OPT		"\x06""option"
#define C_STR		"\x06""string"
#define C_ADDR		"\x07""address"
#define C_NET		"\x07""network"
#define C_DNAME		"\x06""domain"
#define C_BASE64	"\x06""base64"
#define C_REF		"\x09""reference"
#define C_GRP		"\x05""group"
#define C_MULTIGRP	"\x0B""multi-group"

static const yp_item_t group[] = {
	{ C_INT, YP_TINT, YP_VINT = { 0, 100, YP_NIL } },
	{ C_STR, YP_TSTR, YP_VNONE, YP_FMULTI },
	{ NULL }
};

static const yp_item_t multi_group[] = {
	{ C_ID,     YP_TSTR, YP_VNONE },
	{ C_BASE64, YP_TB64, YP_VNONE },
	{ NULL }
};

static const lookup_table_t opts[] = {
	{ 1,   "one" },
	{ 10,  "ten" },
	{ 0, NULL }
	};

static const yp_item_t static_scheme[] = {
	{ C_OPT,      YP_TOPT, YP_VOPT = { opts } },
	{ C_GRP,      YP_TGRP, YP_VGRP = { group } },
	{ C_MULTIGRP, YP_TGRP, YP_VGRP = { multi_group }, YP_FMULTI },
	{ C_REF,      YP_TREF, YP_VREF = { C_MULTIGRP } },
	{ NULL }
};

int main(int argc, char *argv[])
{
	plan_lazy();

	int ret;
	const char *str;
	yp_item_t *scheme;

	ret = yp_scheme_copy(&scheme, static_scheme);
	ok(ret == KNOT_EOK, "scheme copy");

	yp_parser_t yparser;
	yp_parser_t *yp = &yparser;
	yp_init(yp);

	yp_check_ctx_t *ctx = yp_scheme_check_init(scheme);
	ok(ctx != NULL, "create check ctx");

	/* Key0 test. */
	str = "option: one";
	ret = yp_set_input_string(yp, str, strlen(str));
	ok(ret == KNOT_EOK, "set input string");
	ret = yp_parse(yp);
	ok(ret == KNOT_EOK, "parse");
	ret = yp_scheme_check_parser(ctx, yp);
	ok(ret == KNOT_EOK, "check parser");
	ok(ctx->event == YP_EKEY0, "event check");
	ok(strcmp(ctx->key0->name + 1, "option") == 0, "name check");
	ok(ctx->key0->type == YP_TOPT, "type check");
	ok(yp_opt(ctx->data) == 1, "value check");

	/* Group test. */
	str = "group:\n integer: 20\n string: [short, \"long string\"]";
	ret = yp_set_input_string(yp, str, strlen(str));
	ok(ret == KNOT_EOK, "set input string");
	ret = yp_parse(yp);
	ok(ret == KNOT_EOK, "parse");
	ret = yp_scheme_check_parser(ctx, yp);
	ok(ret == KNOT_EOK, "check parser");
	ok(ctx->event == YP_EKEY0, "event check");
	ok(strcmp(ctx->key0->name + 1, "group") == 0, "name check");
	ok(ctx->key0->type == YP_TGRP, "type check");
	ok(ctx->data_len == 0, "value length check");
	ret = yp_parse(yp);
	ok(ret == KNOT_EOK, "parse");
	ret = yp_scheme_check_parser(ctx, yp);
	ok(ret == KNOT_EOK, "check parser");
	ok(ctx->event == YP_EKEY1, "event check");
	ok(strcmp(ctx->key1->name + 1, "integer") == 0, "name check");
	ok(ctx->key1->type == YP_TINT, "type check");
	ok(yp_int(ctx->data, ctx->data_len) == 20, "value check");
	ret = yp_parse(yp);
	ok(ret == KNOT_EOK, "parse");
	ret = yp_scheme_check_parser(ctx, yp);
	ok(ret == KNOT_EOK, "check parser");
	ok(ctx->event == YP_EKEY1, "event check");
	ok(strcmp(ctx->key1->name + 1, "string") == 0, "name check");
	ok(ctx->key1->type == YP_TSTR, "type check");
	ok(strcmp(yp_str(ctx->data), "short") == 0, "value check");
	ret = yp_parse(yp);
	ok(ret == KNOT_EOK, "parse");
	ret = yp_scheme_check_parser(ctx, yp);
	ok(ret == KNOT_EOK, "check parser");
	ok(ctx->event == YP_EKEY1, "event check");
	ok(strcmp(ctx->key1->name + 1, "string") == 0, "name check");
	ok(ctx->key1->type == YP_TSTR, "type check");
	ok(strcmp(yp_str(ctx->data), "long string") == 0, "value check");

	/* Multi-group test. */
	str = "multi-group:\n - id: foo\n   base64: Zm9vYmFy\nreference: foo";
	ret = yp_set_input_string(yp, str, strlen(str));
	ok(ret == KNOT_EOK, "set input string");
	ret = yp_parse(yp);
	ok(ret == KNOT_EOK, "parse");
	ret = yp_scheme_check_parser(ctx, yp);
	ok(ret == KNOT_EOK, "check parser");
	ok(ctx->event == YP_EKEY0, "event check");
	ok(strcmp(ctx->key0->name + 1, "multi-group") == 0, "name check");
	ok(ctx->key0->type == YP_TGRP, "type check");
	ok(ctx->data_len == 0, "value length check");
	ret = yp_parse(yp);
	ok(ret == KNOT_EOK, "parse");
	ret = yp_scheme_check_parser(ctx, yp);
	ok(ret == KNOT_EOK, "check parser");
	ok(ctx->event == YP_EID, "event check");
	ok(strcmp(ctx->key1->name + 1, "id") == 0, "name check");
	ok(ctx->key1->type == YP_TSTR, "type check");
	ok(strcmp(yp_str(ctx->id), "foo") == 0, "value check");
	ret = yp_parse(yp);
	ok(ret == KNOT_EOK, "parse");
	ret = yp_scheme_check_parser(ctx, yp);
	ok(ret == KNOT_EOK, "check parser");
	ok(ctx->event == YP_EKEY1, "event check");
	ok(strcmp(ctx->key1->name + 1, "base64") == 0, "name check");
	ok(ctx->key1->type == YP_TB64, "type check");
	ok(memcmp(ctx->data, "foobar", ctx->data_len) == 0, "value check");
	ret = yp_parse(yp);
	ok(ret == KNOT_EOK, "parse");
	ret = yp_scheme_check_parser(ctx, yp);
	ok(ret == KNOT_EOK, "check parser");
	ok(ctx->event == YP_EKEY0, "event check");
	ok(strcmp(ctx->key0->name + 1, "reference") == 0, "name check");
	ok(ctx->key0->type == YP_TREF, "type check");
	ok(strcmp(yp_str(ctx->data), "foo") == 0, "value check");

	/* Scheme find tests. */
	const yp_item_t *i = yp_scheme_find(C_OPT, NULL, scheme);
	ok(i != NULL, "scheme find");
	ok(strcmp(i->name + 1, "option") == 0, "name check");
	i = yp_scheme_find(C_STR, C_GRP, scheme);
	ok(i != NULL, "scheme find");
	ok(strcmp(i->name + 1, "string") == 0, "name check");

	yp_scheme_check_deinit(ctx);
	yp_deinit(yp);
	yp_scheme_free(scheme);

	return 0;
}
