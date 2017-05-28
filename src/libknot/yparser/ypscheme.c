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

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "libknot/yparser/ypscheme.h"
#include "libknot/yparser/yptrafo.h"
#include "libknot/attribute.h"
#include "libknot/errcode.h"

static size_t scheme_count(
	const yp_item_t *src)
{
	size_t count = 0;
	for (const yp_item_t *item = src; item->name != NULL; item++) {
		count++;
	}

	return count;
}

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
	size_t count = scheme_count(src->var.g.sub_items);

	// Allocate space for subitems + terminal zero item.
	size_t memsize = (count + 1) * sizeof(yp_item_t);
	dst->sub_items = malloc(memsize);
	if (dst->sub_items == NULL) {
		return KNOT_ENOMEM;
	}
	memset(dst->sub_items, 0, memsize);

	// Copy subitems.
	for (size_t i = 0; i < count; i++) {
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

		// Set the parent item.
		dst->sub_items[i].parent = dst;

		if (ret != KNOT_EOK) {
			free(dst->sub_items);
			dst->sub_items = NULL;
			return ret;
		}
	}

	if (src->flags & YP_FALLOC) {
		dst->var.g.sub_items = malloc(memsize);
		if (dst->var.g.sub_items == NULL) {
			free(dst->sub_items);
			dst->sub_items = NULL;
			return KNOT_ENOMEM;
		}
		memcpy((void *)dst->var.g.sub_items, src->var.g.sub_items, memsize);
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

	// Copy item name into dynamic memory.
	if (src->flags & YP_FALLOC) {
		dst->name = malloc(src->name[0] + 2);
		if (dst->name == NULL) {
			return KNOT_ENOMEM;
		}
		memcpy((void *)dst->name, src->name, src->name[0] + 2);
	}

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
	if (item->flags & YP_FALLOC) {
		free((void *)item->name);
		if (item->flags & YP_FALLOC) {
			free((void *)item->var.g.sub_items);
		}
	}
	if (item->sub_items != NULL) {
		free(item->sub_items);
	}

	memset(item, 0, sizeof(yp_item_t));
}

static int scheme_copy(
	yp_item_t *dst,
	const yp_item_t *src,
	const yp_item_t *scheme)
{
	// Copy the scheme.
	for (int i = 0; src[i].name != NULL; i++) {
		int ret = set_item(dst + i, src + i, scheme);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

_public_
int yp_scheme_copy(
	yp_item_t **dst,
	const yp_item_t *src)
{
	if (dst == NULL || src == NULL) {
		return KNOT_EINVAL;
	}

	// Allocate space for new scheme (+ terminal NULL item).
	size_t size = (scheme_count(src) + 1) * sizeof(yp_item_t);
	*dst = malloc(size);
	if (*dst == NULL) {
		return KNOT_ENOMEM;
	}
	memset(*dst, 0, size);

	// Copy the scheme.
	int ret = scheme_copy(*dst, src, *dst);
	if (ret != KNOT_EOK) {
		yp_scheme_free(*dst);
		return ret;
	}

	return KNOT_EOK;
}

_public_
int yp_scheme_merge(
	yp_item_t **dst,
	const yp_item_t *src1,
	const yp_item_t *src2)
{
	if (dst == NULL || src1 == NULL || src2 == NULL) {
		return KNOT_EINVAL;
	}

	size_t count1 = scheme_count(src1);
	size_t count2 = scheme_count(src2);

	// Allocate space for new scheme (+ terminal NULL item).
	size_t size = (count1 + count2 + 1) * sizeof(yp_item_t);
	*dst = malloc(size);
	if (*dst == NULL) {
		return KNOT_ENOMEM;
	}
	memset(*dst, 0, size);

	// Copy the first scheme.
	int ret = scheme_copy(*dst, src1, *dst);
	if (ret != KNOT_EOK) {
		yp_scheme_free(*dst);
		return ret;
	}

	// Copy the second scheme.
	ret = scheme_copy(*dst + count1, src2, *dst);
	if (ret != KNOT_EOK) {
		yp_scheme_free(*dst);
		return ret;
	}

	return KNOT_EOK;
}

_public_
void yp_scheme_purge_dynamic(
	yp_item_t *scheme)
{
	if (scheme == NULL) {
		return;
	}

	for (yp_item_t *item = scheme; item->name != NULL; item++) {
		if (item->flags & YP_FALLOC) {
			unset_item(item);
		}
	}
}

_public_
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

_public_
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

_public_
yp_check_ctx_t* yp_scheme_check_init(
	yp_item_t **scheme)
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

static void reset_ctx(
	yp_check_ctx_t *ctx,
	size_t index)
{
	assert(index < YP_MAX_NODE_DEPTH);

	yp_node_t *node = &ctx->nodes[index];

	node->parent = (index > 0) ? &ctx->nodes[index - 1] : NULL;
	node->item = NULL;
	node->id_len = 0;
	node->data_len = 0;

	ctx->current = index;
}

static int check_item(
	const char *key,
	size_t key_len,
	const char *data,
	size_t data_len,
	yp_check_ctx_t *ctx,
	bool allow_key1_without_id)
{
	yp_node_t *node = &ctx->nodes[ctx->current];
	yp_node_t *parent = node->parent;
	bool is_id = false;

	if (parent != NULL) {
		// Check for invalid indentation.
		if (parent->item == NULL) {
			return KNOT_YP_EINVAL_INDENT;
		}

		// Check if valid group parent.
		if (parent->item->type != YP_TGRP) {
			return KNOT_YP_EINVAL_ITEM;
		}

		// Check if valid subitem.
		node->item = find_item(key, key_len, parent->item->sub_items);
	} else {
		node->item = find_item(key, key_len, *ctx->scheme);
	}
	if (node->item == NULL) {
		return KNOT_YP_EINVAL_ITEM;
	}

	// Check if the parent requires id specification.
	if (parent != NULL && parent->item->var.g.id != NULL) {
		// Check if id.
		if (node->item == parent->item->var.g.id) {
			is_id = true;
			// Move current to the parent.
			--(ctx->current);
		// Check for missing id.
		} else if (parent->id_len == 0 && !allow_key1_without_id) {
			return KNOT_YP_ENOID;
		}
	}

	// Return if no data provided.
	if (data == NULL) {
		return KNOT_EOK;
	}

	// Group cannot have data.
	if (data_len != 0 && node->item->type == YP_TGRP) {
		return KNOT_YP_ENOTSUP_DATA;
	}

	// Convert item data to binary format.
	const yp_item_t *item = (node->item->type != YP_TREF) ?
	                        node->item : node->item->var.r.ref->var.g.id;
	if (is_id) {
		// Textual id must not be empty.
		if (data_len == 0) {
			return KNOT_YP_ENODATA;
		}

		parent->id_len = sizeof(((yp_node_t *)NULL)->id);
		int ret = yp_item_to_bin(item, data, data_len, parent->id,
		                         &parent->id_len);

		// Binary id must not be empty.
		if (ret == KNOT_EOK && parent->id_len == 0) {
			return KNOT_YP_EINVAL_DATA;
		}

		return ret;
	} else {
		node->data_len = sizeof(((yp_node_t *)NULL)->data);
		int ret = yp_item_to_bin(item, data, data_len, node->data,
		                         &node->data_len);
		return ret;
	}
}

_public_
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
		reset_ctx(ctx, 0);
		ret = check_item(parser->key, parser->key_len, parser->data,
		                 parser->data_len, ctx, false);
		break;
	case YP_EKEY1:
		reset_ctx(ctx, 1);
		ret = check_item(parser->key, parser->key_len, parser->data,
		                 parser->data_len, ctx, false);
		if (ret != KNOT_EOK) {
			break;
		}

		// Check for KEY1 event with id item.
		if (ctx->current != 1) {
			return KNOT_YP_ENOTSUP_ID;
		}

		break;
	case YP_EID:
		reset_ctx(ctx, 1);
		ret = check_item(parser->key, parser->key_len, parser->data,
		                 parser->data_len, ctx, false);
		if (ret != KNOT_EOK) {
			break;
		}

		// Check for ID event with nonid item.
		if (ctx->current != 0) {
			return KNOT_YP_EINVAL_ID;
		}

		break;
	default:
		ret = KNOT_EPARSEFAIL;
		break;
	}

	return ret;
}

_public_
int yp_scheme_check_str(
	yp_check_ctx_t *ctx,
	const char *key0,
	const char *key1,
	const char *id,
	const char *data)
{
	if (ctx == NULL) {
		return KNOT_EINVAL;
	}

	size_t key0_len = (key0 != NULL) ? strlen(key0) : 0;
	size_t key1_len = (key1 != NULL) ? strlen(key1) : 0;
	size_t id_len   = (id   != NULL) ? strlen(id)   : 0;
	size_t data_len = (data != NULL) ? strlen(data) : 0;

	// Key0 must always be non-empty.
	if (key0_len == 0) {
		return KNOT_YP_EINVAL_ITEM;
	}

	// Process key0.
	reset_ctx(ctx, 0);
	if (key1_len == 0) {
		int ret = check_item(key0, key0_len, data, data_len, ctx, false);
		if (ret != KNOT_EOK) {
			return ret;
		}
	} else {
		int ret = check_item(key0, key0_len, NULL, 0, ctx, false);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	// Process id.
	if (id_len != 0) {
		if (ctx->nodes[0].item->type != YP_TGRP ||
		    ctx->nodes[0].item->var.g.id == NULL) {
			return KNOT_YP_ENOTSUP_ID;
		}
		const yp_name_t *name = ctx->nodes[0].item->var.g.id->name;

		reset_ctx(ctx, 1);
		int ret = check_item(name + 1, name[0], id, id_len, ctx, true);
		if (ret != KNOT_EOK) {
			return ret;
		}

		// Check for non-id item (should not happen).
		assert(ctx->current == 0);

		// Check for group id with data.
		if (key1_len == 0 && data != NULL) {
			return KNOT_YP_ENOTSUP_DATA;
		}
	}

	// Process key1.
	if (key1_len != 0) {
		reset_ctx(ctx, 1);
		int ret = check_item(key1, key1_len, data, data_len, ctx, true);
		if (ret != KNOT_EOK) {
			return ret;
		}

		// Check for id in key1 with extra data.
		if (ctx->current != 1 && id_len != 0 && data != NULL) {
			return KNOT_YP_ENOTSUP_DATA;
		}
	}

	return KNOT_EOK;
}

_public_
void yp_scheme_check_deinit(
	yp_check_ctx_t* ctx)
{
	free(ctx);
}
