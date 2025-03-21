/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <stdio.h>

#include "libknot/yparser/yptrafo.h"
#include "libknot/attribute.h"
#include "libknot/errcode.h"

static int format_item(
	const yp_item_t *item,
	const uint8_t *data,
	size_t data_len,
	char *out,
	size_t out_len,
	yp_style_t style,
	const char *prefix,
	bool first_value,
	bool last_value)
{
	if (item == NULL || out == NULL || prefix == NULL) {
		return KNOT_EINVAL;
	}

	// Format key part.
	int ret = snprintf(out, out_len, "%s%s%s%s",
	                   first_value ? prefix : "",
	                   first_value ? item->name + 1 : "",
	                   first_value ? ":" : "",
	                   item->type == YP_TGRP ?
	                     "\n" : (first_value && !last_value ? " [ " : " "));
	if (ret < 0 || ret >= out_len) {
		return KNOT_ESPACE;
	}
	out     += ret;
	out_len -= ret;

	// Finish if group.
	if (item->type == YP_TGRP) {
		return KNOT_EOK;
	}

	// Format data part.
	size_t aux_len = out_len;
	ret = yp_item_to_txt(item, data, data_len, out, &aux_len, style);
	if (ret != KNOT_EOK) {
		return ret;
	}
	out     += aux_len;
	out_len -= aux_len;

	// Format data end.
	ret = snprintf(out, out_len, "%s%s",
	               last_value && !first_value ? " ]" : "",
	               last_value ? "\n" : ",");
	if (ret < 0 || ret >= out_len) {
		return KNOT_ESPACE;
	}

	return KNOT_EOK;
}

_public_
int yp_format_key0(
	const yp_item_t *item,
	const uint8_t *data,
	size_t data_len,
	char *out,
	size_t out_len,
	yp_style_t style,
	bool first_value,
	bool last_value)
{
	return format_item(item, data, data_len, out, out_len, style, "",
	                   first_value, last_value);
}

_public_
int yp_format_id(
	const yp_item_t *item,
	const uint8_t *data,
	size_t data_len,
	char *out,
	size_t out_len,
	yp_style_t style)
{
	if (data == NULL) {
		return KNOT_EINVAL;
	}

	return format_item(item, data, data_len, out, out_len, style, "  - ",
	                   true, true);
}

_public_
int yp_format_key1(
	const yp_item_t *item,
	const uint8_t *data,
	size_t data_len,
	char *out,
	size_t out_len,
	yp_style_t style,
	bool first_value,
	bool last_value)
{
	return format_item(item, data, data_len, out, out_len, style, "    ",
	                   first_value, last_value);
}
