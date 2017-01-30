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

#include "libknot/yparser/ypscheme.h"
#include "libknot/yparser/yptrafo.h"
#include "libknot/libknot.h"

#define C_ID		"\x02""id"
#define C_INT		"\x07""integer"
#define C_BOOL		"\x04""bool"
#define C_OPT		"\x06""option"
#define C_STR		"\x06""string"
#define C_ADDR		"\x07""address"
#define C_DNAME		"\x05""dname"
#define C_HEX		"\x03""hex"
#define C_BASE64	"\x06""base64"
#define C_DATA		"\x04""data"
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
	{ C_HEX,    YP_THEX, YP_VNONE },
	{ C_BASE64, YP_TB64, YP_VNONE },
	{ NULL }
};

static const knot_lookup_t opts[] = {
	{ 1,   "one" },
	{ 10,  "ten" },
	{ 0, NULL }
	};

static const yp_item_t static_scheme[] = {
	{ C_OPT,      YP_TOPT,   YP_VOPT = { opts } },
	{ C_BOOL,     YP_TBOOL,  YP_VNONE },
	{ C_DNAME,    YP_TDNAME, YP_VNONE },
	{ C_GRP,      YP_TGRP,   YP_VGRP = { group } },
	{ C_MULTIGRP, YP_TGRP,   YP_VGRP = { multi_group }, YP_FMULTI },
	{ C_REF,      YP_TREF,   YP_VREF = { C_MULTIGRP } },
	{ C_DATA,     YP_TDATA,  YP_VNONE },
	{ NULL }
};

static void scheme_find_test(void)
{
	yp_item_t *scheme = NULL;

	int ret = yp_scheme_copy(&scheme, static_scheme);
	is_int(KNOT_EOK, ret, "scheme copy");

	const yp_item_t *i = yp_scheme_find(C_OPT, NULL, scheme);
	ok(i != NULL, "scheme find");
	if (i == NULL) {
		goto error_scheme;
	}
	ok(strcmp(i->name + 1, C_OPT + 1) == 0, "name check");

	i = yp_scheme_find(C_STR, C_GRP, scheme);
	ok(i != NULL, "scheme find with parent");
	if (i == NULL) {
		goto error_scheme;
	}
	ok(strcmp(i->name + 1, C_STR + 1) == 0, "name check");

	i = yp_scheme_find(C_ADDR, NULL, scheme);
	ok(i == NULL, "scheme not find");

	i = yp_scheme_find(C_ADDR, C_GRP, scheme);
	ok(i == NULL, "scheme not find with parent");

error_scheme:
	yp_scheme_free(scheme);
}

#define SET_INPUT_STR(str) \
	ret = yp_set_input_string(yp, str, strlen(str)); \
	is_int(KNOT_EOK, ret, "set input string");

#define PARSER_CHECK(depth) \
	ret = yp_parse(yp); \
	is_int(KNOT_EOK, ret, "parse"); \
	ret = yp_scheme_check_parser(ctx, yp); \
	is_int(KNOT_EOK, ret, "check parser"); \
	node = &ctx->nodes[ctx->current]; \
	parent = node->parent; \
	ok(ctx->current == depth, "depth check");

#define PARSER_RET_CHECK(code) \
	ret = yp_parse(yp); \
	is_int(KNOT_EOK, ret, "parse"); \
	ret = yp_scheme_check_parser(ctx, yp); \
	ok(ret == code, "return check parser");

static void parser_test(void)
{
	yp_parser_t yparser;
	yp_parser_t *yp = &yparser;
	yp_item_t *scheme = NULL;
	yp_check_ctx_t *ctx = NULL;

	yp_init(yp);

	int ret = yp_scheme_copy(&scheme, static_scheme);
	is_int(KNOT_EOK, ret, "scheme copy");
	if (ret != KNOT_EOK) {
		goto error_parser;
	}

	ctx = yp_scheme_check_init(scheme);
	ok(ctx != NULL, "create check ctx");
	if (ctx == NULL) {
		goto error_parser;
	}

	yp_node_t *node;
	yp_node_t *parent;
	const yp_item_t *id;

	diag("parser key0 test");
	SET_INPUT_STR("option: one");
	PARSER_CHECK(0);
	ok(strcmp(node->item->name + 1, "option") == 0, "name check");
	ok(node->item->type == YP_TOPT, "type check");
	ok(yp_opt(node->data) == 1, "value check");

	diag("parser group test");
	SET_INPUT_STR("group:\n integer: 20\n string: [short, \"long string\"]");
	PARSER_CHECK(0);
	ok(strcmp(node->item->name + 1, "group") == 0, "name check");
	ok(node->item->type == YP_TGRP, "type check");
	ok(node->data_len == 0, "value length check");
	PARSER_CHECK(1);
	ok(strcmp(node->item->name + 1, "integer") == 0, "name check");
	ok(node->item->type == YP_TINT, "type check");
	ok(yp_int(node->data) == 20, "value check");
	PARSER_CHECK(1);
	ok(strcmp(node->item->name + 1, "string") == 0, "name check");
	ok(node->item->type == YP_TSTR, "type check");
	ok(strcmp(yp_str(node->data), "short") == 0, "value check");
	PARSER_CHECK(1);
	ok(strcmp(node->item->name + 1, "string") == 0, "name check");
	ok(node->item->type == YP_TSTR, "type check");
	ok(strcmp(yp_str(node->data), "long string") == 0, "value check");

	diag("parser multi-group test");
	SET_INPUT_STR("multi-group:\n - id: foo\n   base64: Zm9vYmFy\nreference: foo");
	PARSER_CHECK(0);
	ok(strcmp(node->item->name + 1, "multi-group") == 0, "name check");
	ok(node->item->type == YP_TGRP, "type check");
	ok(node->data_len == 0, "value length check");
	PARSER_CHECK(0);
	ok(node->id_len > 0, "id check");
	ok(strcmp(node->item->name + 1, "multi-group") == 0, "name check");
	ok(node->item->type == YP_TGRP, "type check");
	ok(node->data_len == 0, "value length check");
	id = node->item->var.g.id;
	ok(strcmp(id->name + 1, "id") == 0, "name check");
	ok(id->type == YP_TSTR, "type check");
	ok(strcmp(yp_str(node->id), "foo") == 0, "value check");
	PARSER_CHECK(1);
	id = parent->item->var.g.id;
	ok(strcmp(parent->item->name + 1, "multi-group") == 0, "name check");
	ok(parent->item->type == YP_TGRP, "type check");
	ok(parent->data_len == 0, "value length check");
	ok(strcmp(yp_str(parent->id), "foo") == 0, "value check");
	ok(strcmp(id->name + 1, "id") == 0, "name check");
	ok(id->type == YP_TSTR, "type check");
	ok(strcmp(node->item->name + 1, "base64") == 0, "name check");
	ok(node->item->type == YP_TB64, "type check");
	ok(memcmp(yp_bin(node->data), "foobar", yp_bin_len(node->data)) == 0,
	   "value check");
	ok(node->id_len == 0, "id length check");
	PARSER_CHECK(0);
	ok(strcmp(node->item->name + 1, "reference") == 0, "name check");
	ok(node->item->type == YP_TREF, "type check");
	ok(strcmp(yp_str(node->data), "foo") == 0, "value check");

	diag("parser check return");
	SET_INPUT_STR("unknown:");
	PARSER_RET_CHECK(KNOT_YP_EINVAL_ITEM);

	SET_INPUT_STR("group:\n unknown:");
	PARSER_RET_CHECK(KNOT_EOK);
	PARSER_RET_CHECK(KNOT_YP_EINVAL_ITEM);

	SET_INPUT_STR("group:\n - unknown: data");
	PARSER_RET_CHECK(KNOT_EOK);
	PARSER_RET_CHECK(KNOT_YP_EINVAL_ITEM);

	SET_INPUT_STR("group:\n - hex: data");
	PARSER_RET_CHECK(KNOT_EOK);
	PARSER_RET_CHECK(KNOT_YP_EINVAL_ITEM);

	SET_INPUT_STR("dname:");
	PARSER_RET_CHECK(KNOT_EINVAL);

	SET_INPUT_STR("group: data");
	PARSER_RET_CHECK(KNOT_YP_ENOTSUP_DATA);

	SET_INPUT_STR("group:\n integer:");
	PARSER_RET_CHECK(KNOT_EOK);
	PARSER_RET_CHECK(KNOT_EINVAL);

	SET_INPUT_STR("multi-group:\n id:");
	PARSER_RET_CHECK(KNOT_EOK);
	PARSER_RET_CHECK(KNOT_YP_ENODATA);

	SET_INPUT_STR("multi-group:\n hex:");
	PARSER_RET_CHECK(KNOT_EOK);
	PARSER_RET_CHECK(KNOT_YP_ENOID);

error_parser:
	yp_scheme_check_deinit(ctx);
	yp_scheme_free(scheme);
	yp_deinit(yp);
}

#define STR_CHECK(depth, key0, key1, id, data) \
	ret = yp_scheme_check_str(ctx, key0, key1, id, data); \
	is_int(KNOT_EOK, ret, "check str"); \
	ok(ctx->current == depth, "depth check"); \
	node = &ctx->nodes[ctx->current]; \
	parent = node->parent;

#define STR_RET_CHECK(code, key0, key1, id, data) \
	ret = yp_scheme_check_str(ctx, key0, key1, id, data); \
	ok(ret == code, "return check str");

static void str_test(void)
{
	yp_item_t *scheme;
	yp_check_ctx_t *ctx = NULL;

	int ret = yp_scheme_copy(&scheme, static_scheme);
	is_int(KNOT_EOK, ret, "scheme copy");
	if (ret != KNOT_EOK) {
		goto error_str;
	}

	ctx = yp_scheme_check_init(scheme);
	ok(ctx != NULL, "create check ctx");
	if (ctx == NULL) {
		goto error_str;
	}

	yp_node_t *node;
	yp_node_t *parent;
	const yp_item_t *id;

	diag("str key0 test");
	STR_CHECK(0, "option", NULL, NULL, "one");
	ok(strcmp(node->item->name + 1, "option") == 0, "name check");
	ok(node->item->type == YP_TOPT, "type check");
	ok(yp_opt(node->data) == 1, "value check");

	diag("str group test");
	STR_CHECK(0, "group", NULL, NULL, NULL);
	ok(strcmp(node->item->name + 1, "group") == 0, "name check");
	ok(node->item->type == YP_TGRP, "type check");
	ok(node->data_len == 0, "value length check");
	STR_CHECK(1, "group", "integer", NULL, "20");
	ok(strcmp(node->item->name + 1, "integer") == 0, "name check");
	ok(node->item->type == YP_TINT, "type check");
	ok(yp_int(node->data) == 20, "value check");
	STR_CHECK(1, "group", "string", NULL, "short");
	ok(strcmp(node->item->name + 1, "string") == 0, "name check");
	ok(node->item->type == YP_TSTR, "type check");
	ok(strcmp(yp_str(node->data), "short") == 0, "value check");
	STR_CHECK(1, "group", "string", NULL, "long string");
	ok(strcmp(node->item->name + 1, "string") == 0, "name check");
	ok(node->item->type == YP_TSTR, "type check");
	ok(strcmp(yp_str(node->data), "long string") == 0, "value check");

	diag("str multi-group test");
	STR_CHECK(0, "multi-group", NULL, NULL, NULL);
	ok(strcmp(node->item->name + 1, "multi-group") == 0, "name check");
	ok(node->item->type == YP_TGRP, "type check");
	ok(node->data_len == 0, "value length check");
	STR_CHECK(0, "multi-group", NULL, "foo", NULL);
	ok(node->id_len > 0, "id check");
	ok(strcmp(node->item->name + 1, "multi-group") == 0, "name check");
	ok(node->item->type == YP_TGRP, "type check");
	ok(node->data_len == 0, "value length check");
	id = node->item->var.g.id;
	ok(strcmp(id->name + 1, "id") == 0, "name check");
	ok(id->type == YP_TSTR, "type check");
	ok(strcmp(yp_str(node->id), "foo") == 0, "value check");
	STR_CHECK(1, "multi-group", "base64", "foo", "Zm9vYmFy");
	id = parent->item->var.g.id;
	ok(strcmp(parent->item->name + 1, "multi-group") == 0, "name check");
	ok(parent->item->type == YP_TGRP, "type check");
	ok(parent->data_len == 0, "value length check");
	ok(strcmp(yp_str(parent->id), "foo") == 0, "value check");
	ok(strcmp(id->name + 1, "id") == 0, "name check");
	ok(id->type == YP_TSTR, "type check");
	ok(strcmp(node->item->name + 1, "base64") == 0, "name check");
	ok(node->item->type == YP_TB64, "type check");
	ok(memcmp(yp_bin(node->data), "foobar", yp_bin_len(node->data)) == 0,
	   "value check");
	ok(node->id_len == 0, "id length check");
	STR_CHECK(0, "reference", NULL, NULL, "foo");
	ok(strcmp(node->item->name + 1, "reference") == 0, "name check");
	ok(node->item->type == YP_TREF, "type check");
	ok(strcmp(yp_str(node->data), "foo") == 0, "value check");

	diag("str check return");
	STR_RET_CHECK(KNOT_YP_EINVAL_ITEM,  "",        "",        "",   "");
	STR_RET_CHECK(KNOT_YP_EINVAL_ITEM,  NULL,      NULL,      NULL, NULL);
	STR_RET_CHECK(KNOT_YP_EINVAL_ITEM,  "unknown", NULL,      NULL, NULL);
	STR_RET_CHECK(KNOT_YP_EINVAL_ITEM,  NULL,      "unknown", NULL, NULL);
	STR_RET_CHECK(KNOT_EINVAL,          "dname",   "",        "",   "");
	STR_RET_CHECK(KNOT_EOK,             "dname",   NULL,      NULL, NULL);
	STR_RET_CHECK(KNOT_EOK,             "dname",   NULL,      NULL, ".");
	STR_RET_CHECK(KNOT_EINVAL,          "dname",   NULL,      NULL, "..");
	STR_RET_CHECK(KNOT_YP_ENOTSUP_ID,   "dname",   NULL,      "id", NULL);
	STR_RET_CHECK(KNOT_YP_EINVAL_ITEM,  "dname",   "unknown", NULL, NULL);

	STR_RET_CHECK(KNOT_EOK,             "group",   "",        "",   "");
	STR_RET_CHECK(KNOT_EOK,             "group",   NULL,      NULL, NULL);
	STR_RET_CHECK(KNOT_YP_ENOTSUP_DATA, "group",   "",        "",   "data");
	STR_RET_CHECK(KNOT_YP_EINVAL_ITEM,  "group",   "unknown", NULL, NULL);
	STR_RET_CHECK(KNOT_EOK,             "group",   "string",  NULL, NULL);
	STR_RET_CHECK(KNOT_EOK,             "group",   "string",  NULL, "data");
	STR_RET_CHECK(KNOT_EOK,             "group",   "string",  NULL, "");
	STR_RET_CHECK(KNOT_YP_ENOTSUP_ID,   "group",   "",        "id", NULL);
	STR_RET_CHECK(KNOT_YP_ENOTSUP_ID,   "group",   "string",  "id", NULL);

	STR_RET_CHECK(KNOT_EOK,             "multi-group", "",    "",      "");
	STR_RET_CHECK(KNOT_EOK,             "multi-group", NULL,  NULL,    NULL);
	STR_RET_CHECK(KNOT_YP_ENOTSUP_DATA, "multi-group", NULL,  NULL,    "data");
	STR_RET_CHECK(KNOT_EOK,             "multi-group", NULL,  "idval", NULL);
	STR_RET_CHECK(KNOT_YP_ENOTSUP_DATA, "multi-group", NULL,  "idval", "data");
	STR_RET_CHECK(KNOT_EOK,             "multi-group", "hex", "idval", NULL);
	STR_RET_CHECK(KNOT_EOK,             "multi-group", "hex", "idval", "data");
	STR_RET_CHECK(KNOT_EOK,             "multi-group", "hex", NULL,    NULL);
	STR_RET_CHECK(KNOT_EOK,             "multi-group", "hex", NULL,    "data");
	STR_RET_CHECK(KNOT_EOK,             "multi-group", "id",  "",      NULL);
	STR_RET_CHECK(KNOT_EOK,             "multi-group", "id",  NULL,    "idval");
	STR_RET_CHECK(KNOT_EOK,             "multi-group", "id",  "idval", NULL);
	STR_RET_CHECK(KNOT_YP_ENOTSUP_DATA, "multi-group", "id",  "idval", "data");

error_str:
	yp_scheme_check_deinit(ctx);
	yp_scheme_free(scheme);
}

int main(int argc, char *argv[])
{
	plan_lazy();

	scheme_find_test();
	parser_test();
	str_test();

	return 0;
}
