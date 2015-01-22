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

#include "libknot/internal/yparser/ypscheme.h"
#include "libknot/internal/yparser/yptrafo.h"
#include "libknot/errcode.h"

/*! Initializes the referenced item. */
static int set_ref_item(
	yp_item_t *dst,
	const yp_item_t *scheme)
{
	if (scheme == NULL) {
		return KNOT_EINVAL;
	}

	// Get reference category.
	const yp_name_t *ref_name = dst->var.r.ref_name;
	const yp_item_t *ref = yp_scheme_find(ref_name, NULL, scheme);
	if (ref == NULL) {
		return KNOT_YP_EINVAL_ITEM;
	}

	dst->var.r.ref = ref;

	return KNOT_EOK;
}

/*! Copies the sub_items list and initializes pointer to the identifier item. */
static int set_grp_item(
	yp_item_t *dst,
	const yp_item_t *src,
	const yp_item_t *scheme)
{
	// Count subitems.
	size_t num = 0;
	while (src->var.g.sub_items[num].name != NULL) {
		num++;
	}

	// Allocate space for subitems + terminal zero item.
	size_t memsize = (num + 1) * sizeof(yp_item_t);
	dst->sub_items = malloc(memsize);
	if (dst->sub_items == NULL) {
		return KNOT_ENOMEM;
	}
	memset(dst->sub_items, 0, memsize);

	// Copy subitems.
	for (size_t i = 0; i < num; i++) {
		// The first item is an identifier if multi group.
		if (i == 0 && (dst->flags & YP_FMULTI)) {
			dst->var.g.id = &dst->sub_items[0];
		}

		// Copy sub-item.
		dst->sub_items[i] = src->var.g.sub_items[i];

		// Initialize sub-item.
		int ret = KNOT_EOK;
		switch (dst->sub_items[i].type) {
		case YP_TREF:
			ret = set_ref_item(dst->sub_items + i, scheme);
			break;
		case YP_TGRP: // Deeper hierarchy is not supported.
			ret = KNOT_ENOTSUP;
			break;
		default:
			break;
		}

		if (ret != KNOT_EOK) {
			free(dst->sub_items);
			dst->sub_items = NULL;
			return ret;
		}
	}

	return KNOT_EOK;
}

static int set_item(
	yp_item_t *dst,
	const yp_item_t *src,
	const yp_item_t *scheme)
{
	// Check maximal item name length.
	if ((uint8_t)src->name[0] > YP_MAX_ITEM_NAME_LEN) {
		return KNOT_ERANGE;
	}

	// Copy the static data.
	*dst = *src;

	// Item type specific preparation.
	switch (src->type) {
	case YP_TREF:
		return set_ref_item(dst, scheme);
	case YP_TGRP:
		return set_grp_item(dst, src, scheme);
	default:
		return KNOT_EOK;
	}
}

static void unset_item(
	yp_item_t *item)
{
	if (item->sub_items != NULL) {
		free(item->sub_items);
	}

	memset(item, 0, sizeof(yp_item_t));
}

int yp_scheme_copy(
	yp_item_t **dst,
	const yp_item_t *src)
{
	if (dst == NULL || src == NULL) {
		return KNOT_EINVAL;
	}

	// Count scheme items.
	size_t scheme_items = 0;
	for (const yp_item_t *item = src; item->name != NULL; item++) {
		scheme_items++;
	}

	// Allocate space for new scheme.
	size_t size = (scheme_items + 1) * sizeof(yp_item_t);
	*dst = malloc(size);
	if (*dst == NULL) {
		return KNOT_ENOMEM;
	}
	memset(*dst, 0, size);

	// Copy the scheme.
	for (int i = 0; i < scheme_items; i++) {
		if (src[i].name == NULL) {
			break;
		}

		int ret = set_item(*dst + i, src + i, *dst);
		if (ret != KNOT_EOK) {
			yp_scheme_free(*dst);
			return ret;
		}
	}

	return KNOT_EOK;
}

void yp_scheme_free(
	yp_item_t *scheme)
{
	if (scheme == NULL) {
		return;
	}

	for (yp_item_t *item = scheme; item->name != NULL; item++) {
		unset_item(item);
	}
	free(scheme);
}

/*! Search the scheme for an item with the given name. */
static const yp_item_t* find_item(
	const char *name,
	size_t name_len,
	const yp_item_t *scheme)
{
	if (name == NULL || scheme == NULL) {
		return NULL;
	}

	for (const yp_item_t *item = scheme; item->name != NULL; item++) {
		if (item->name[0] != name_len) {
			continue;
		}
		if (memcmp(item->name + 1, name, name_len) == 0) {
			return item;
		}
	}

	return NULL;
}

const yp_item_t* yp_scheme_find(
	const yp_name_t *name,
	const yp_name_t *parent_name,
	const yp_item_t *scheme)
{
	if (name == NULL || scheme == NULL) {
		return NULL;
	}

	if (parent_name == NULL) {
		return find_item(name + 1, name[0], scheme);
	} else {
		const yp_item_t *parent = find_item(parent_name + 1,
		                                    parent_name[0], scheme);
		if (parent == NULL) {
			return NULL;
		}
		return find_item(name + 1, name[0], parent->sub_items);
	}
}

yp_check_ctx_t* yp_scheme_check_init(
	const yp_item_t *scheme)
{
	if (scheme == NULL) {
		return NULL;
	}

	yp_check_ctx_t *ctx = malloc(sizeof(yp_check_ctx_t));
	if (ctx == NULL) {
		return NULL;
	}
	memset(ctx, 0, sizeof(yp_check_ctx_t));

	ctx->scheme = scheme;

	return ctx;
}

static int check_key0(
	const char *key,
	size_t key_len,
	const char *data,
	size_t data_len,
	yp_check_ctx_t *ctx)
{
	const yp_item_t *key0 = find_item(key, key_len, ctx->scheme);
	if (key0 == NULL) {
		return KNOT_YP_EINVAL_ITEM;
	}

	// Group cannot have data.
	if (key0->type == YP_TGRP && data_len != 0) {
		return KNOT_YP_ENOTSUP_DATA;
	}

	ctx->key0 = key0;
	ctx->key1 = NULL;
	ctx->id_len = 0;
	ctx->data_len = sizeof(((yp_check_ctx_t *)NULL)->data);

	return yp_item_to_bin(key0, data, data_len, ctx->data, &ctx->data_len);
}

static int check_key1(
	const char *key,
	size_t key_len,
	const char *data,
	size_t data_len,
	yp_check_ctx_t *ctx)
{
	// Sub-item must have a parent item.
	if (ctx->key0 == NULL || ctx->key0->type != YP_TGRP) {
		return KNOT_YP_EINVAL_ITEM;
	}

	const yp_item_t *key1 = find_item(key, key_len, ctx->key0->sub_items);
	if (key1 == NULL) {
		return KNOT_YP_EINVAL_ITEM;
	}

	// Sub-item must not be a group.
	if (key1->type == YP_TGRP) {
		return KNOT_YP_EINVAL_ITEM;
	}

	// Check if the group requires id specification.
	if (ctx->key0->var.g.id != NULL) {
		// Check if key1 is not id item.
		if (key1 == ctx->key0->var.g.id) {
			return KNOT_YP_EINVAL_ITEM;
		}

		if (ctx->id_len == 0) {
			return KNOT_YP_ENOID;
		}
	// Check for id if not supported.
	} else if (ctx->id_len > 0) {
		return KNOT_YP_ENOTSUP_ID;
	}

	ctx->key1 = key1;
	ctx->data_len = sizeof(((yp_check_ctx_t *)NULL)->data);

	return yp_item_to_bin(key1, data, data_len, ctx->data, &ctx->data_len);
}

static int check_id(
	const char *key,
	size_t key_len,
	const char *data,
	size_t data_len,
	yp_check_ctx_t *ctx)
{
	// Id must have a parent item.
	if (ctx->key0 == NULL) {
		return KNOT_YP_EINVAL_ITEM;
	}

	// Only group item can have id.
	if (ctx->key0->type != YP_TGRP) {
		return KNOT_YP_ENOTSUP_ID;
	}

	// Check group item without id support.
	if (ctx->key0->var.g.id == NULL) {
	       return KNOT_YP_ENOTSUP_ID;
	}

	const yp_item_t *id = find_item(key, key_len, ctx->key0->sub_items);
	if (id == NULL) {
		return KNOT_YP_EINVAL_ITEM;
	}

	// Id item must be the first one.
	if (id != ctx->key0->var.g.id) {
		return KNOT_YP_EINVAL_ITEM;
	}

	// Textual id must not be empty.
	if (data_len == 0) {
		return KNOT_YP_ENODATA;
	}

	ctx->key1 = ctx->key0->var.g.id;
	ctx->data_len = 0;
	ctx->id_len = sizeof(((yp_check_ctx_t *)NULL)->data);

	int ret = yp_item_to_bin(ctx->key0->var.g.id, data, data_len, ctx->id,
	                         &ctx->id_len);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Binary id must not be empty.
	if (ctx->id_len == 0) {
		return KNOT_YP_EINVAL_DATA;
	}

	return KNOT_EOK;
}

int yp_scheme_check_parser(
	yp_check_ctx_t *ctx,
	const yp_parser_t *parser)
{
	if (ctx == NULL || parser == NULL) {
		return KNOT_EINVAL;
	}

	int ret;

	switch (parser->event) {
	case YP_EKEY0:
		ret = check_key0(parser->key, parser->key_len,
		                 parser->data, parser->data_len, ctx);
		break;
	case YP_EKEY1:
		ret = check_key1(parser->key, parser->key_len,
		                 parser->data, parser->data_len, ctx);
		break;
	case YP_EID:
		ret = check_id(parser->key, parser->key_len,
		               parser->data, parser->data_len, ctx);
		break;
	default:
		ret = KNOT_EPARSEFAIL;
		break;
	}

	ctx->event = parser->event;

	return ret;
}

void yp_scheme_check_deinit(
	yp_check_ctx_t* ctx)
{
	free(ctx);
}
