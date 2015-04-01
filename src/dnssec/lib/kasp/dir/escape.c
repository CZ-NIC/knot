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

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "error.h"
#include "kasp/dir/escape.h"
#include "wire.h"

/*!
 * Convert ASCII upper case character to lowercase one.
 */
static char ascii_tolower(char chr)
{
	if ('A' <= chr && chr <= 'Z') {
		return chr - 'A' + 'a';
	} else {
		return chr;
	}
}

/*!
 * Check if char is safe and should be written without escaping.
 */
static bool is_safe(char chr)
{
	return ('a' <= chr && chr <= 'z') ||
	       ('0' <= chr && chr <= '9') ||
	       (chr == '.' || chr == '-' || chr == '_');
}

/*!
 * Write one safe byte.
 */
static int write_safe(wire_ctx_t *dest, char chr)
{
	if (wire_available(dest) < 1) {
		return DNSSEC_ENOMEM;
	}

	wire_write_u8(dest, chr);

	return DNSSEC_EOK;
}

/*!
 * Escape one unsafe byte.
 */
static int write_unsafe(wire_ctx_t *dest, char chr)
{
	if (wire_available(dest) < 4) {
		return DNSSEC_ENOMEM;
	}

	char buffer[5] = { 0 };
	int written = snprintf(buffer, sizeof(buffer), "\\x%02x", (unsigned char)chr);
	if (written != 4) {
		return DNSSEC_ERROR;
	}

	wire_write(dest, (uint8_t *)buffer, written);

	return DNSSEC_EOK;
}

/*!
 * Read one safe byte during unescaping.
 */
static int read_safe(wire_ctx_t *dest, char chr)
{
	if (!is_safe(chr)) {
		return DNSSEC_MALFORMED_DATA;
	}

	return write_safe(dest, chr);
}

/*!
 * Unescape one unsafe byte.
 *
 * Initial slash is already processed.
 */
static int read_unsafe(wire_ctx_t *dest, wire_ctx_t *src)
{
	if (wire_available(dest) < 1 || wire_available(src) < 3) {
		return DNSSEC_ENOMEM;
	}

	char buffer[3] = { 0 };
	wire_read(src, (uint8_t *)buffer, sizeof(buffer));

	unsigned value = 0;
	int read = sscanf(buffer, "x%02x", &value);
	if (read != 1 || value == 0) {
		return DNSSEC_MALFORMED_DATA;
	}

	assert(value <= UINT8_MAX);
	wire_write_u8(dest, value);

	return DNSSEC_EOK;
}

/*!
 * Filtering function type signature.
 */
typedef int (*filter_cb)(wire_ctx_t *, wire_ctx_t *);

/*!
 * Escaping filter.
 */
static int filter_escape(wire_ctx_t *src, wire_ctx_t *dest)
{
	char chr = wire_read_u8(src);
	chr = ascii_tolower(chr);

	if (is_safe(chr)) {
		return write_safe(dest, chr);
	} else {
		return write_unsafe(dest, chr);
	}
}

/*!
 * Unescaping filter.
 */
static int filter_unescape(wire_ctx_t *src, wire_ctx_t *dest)
{
	char chr = wire_read_u8(src);

	if (chr != '\\') {
		return read_safe(dest, chr);
	} else {
		return read_unsafe(dest, src);
	}
}

/*!
 * Convert one buffer to another using filtering function.
 */
static int filter_ctx(wire_ctx_t *src, wire_ctx_t *dest, filter_cb filter)
{
	while (wire_available(src) > 0) {
		int result = filter(src, dest);
		if (result != DNSSEC_EOK) {
			return result;
		}
	}

	return DNSSEC_EOK;
}

/*!
 * Create string from wire context.
 */
static int ctx_to_str(wire_ctx_t *src, char **result)
{
	size_t len = wire_tell(src);

	char *str = malloc(len + 1);
	if (!str) {
		return DNSSEC_ENOMEM;
	}

	memcpy(str, src->wire, len);
	str[len] = '\0';

	*result = str;
	return DNSSEC_EOK;
}

/*!
 * Convert string to another using a filtering function.
 */
static int filter_str(const char *input, char **output, filter_cb filter)
{
	assert(input);
	assert(output);
	assert(filter);

	uint8_t buffer[256] = { 0 };

	wire_ctx_t in_ctx = wire_init((uint8_t *)input, strlen(input));
	wire_ctx_t out_ctx = wire_init(buffer, sizeof(buffer));

	int r = filter_ctx(&in_ctx, &out_ctx, filter);
	if (r != DNSSEC_EOK) {
		return r;
	}

	return ctx_to_str(&out_ctx, output);
}

/* -- internal API --------------------------------------------------------- */

int escape_entity_name(const char *name, char **escaped)
{
	return filter_str(name, escaped, filter_escape);
}

int unescape_entity_name(const char *escaped, char **name)
{
	return filter_str(escaped, name, filter_unescape);
}
