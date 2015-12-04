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

#include "libknot/internal/macros.h"
#include "libknot/yparser/yptrafo.h"
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
