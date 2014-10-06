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

#define BUFFER_SIZE 256

static char ascii_tolower(char chr)
{
	if ('A' <= chr && chr <= 'Z') {
		return chr - 'A' + 'a';
	} else {
		return chr;
	}
}

static bool is_safe(char chr)
{
	return ('a' <= chr && chr <= 'z') ||
	       ('0' <= chr && chr <= '9') ||
	       (chr == '.' || chr == '-' || chr == '_');
}

static int write_safe(wire_ctx_t *dest, char chr)
{
	if (wire_available(dest) < 1) {
		return DNSSEC_ENOMEM;
	}

	wire_write_u8(dest, chr);

	return DNSSEC_EOK;
}

static int write_unsafe(wire_ctx_t *dest, char chr)
{
	if (wire_available(dest) < 4) {
		return DNSSEC_ENOMEM;
	}

	char buffer[5] = { 0 };
	int written = snprintf(buffer, sizeof(buffer), "\\x%02x", chr);
	if (written != 4) {
		return DNSSEC_ERROR;
	}

	wire_write(dest, (uint8_t *)buffer, written);

	return DNSSEC_EOK;
}

static int read_unsafe(wire_ctx_t *dest, wire_ctx_t *src)
{
	if (wire_available(dest) < 1 || wire_available(src) < 3) {
		return DNSSEC_ENOMEM;
	}

	char buffer[3] = { 0 };
	wire_read(src, (uint8_t *)buffer, sizeof(buffer));

	int value = 0;
	int read = sscanf(buffer, "x%02x", &value);
	if (read != 1) {
		return DNSSEC_MALFORMED_DATA;
	}

	assert(SCHAR_MIN <= value && value <= SCHAR_MAX);
	wire_write_u8(dest, value);

	return DNSSEC_EOK;
}

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

static int filter_unescape(wire_ctx_t *src, wire_ctx_t *dest)
{
	char chr = wire_read_u8(src);

	if (chr != '\\') {
		return write_safe(dest, chr);
	} else {
		return read_unsafe(dest, src);
	}
}

static int filter(wire_ctx_t *src, wire_ctx_t *dest,
		  int (*filter_cb)(wire_ctx_t *, wire_ctx_t *))
{
	while (wire_available(src) > 0) {
		int result = filter_cb(src, dest);
		if (result != DNSSEC_EOK) {
			return result;
		}
	}

	return DNSSEC_EOK;
}

static int buffer_to_string(wire_ctx_t *src, char **result)
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

/* -- internal API --------------------------------------------------------- */

int escape_zone_name(const char *name, char **escaped)
{
	assert(name);
	assert(escaped);

	wire_ctx_t name_ctx = wire_init((uint8_t *)name, strlen(name));

	uint8_t buffer[BUFFER_SIZE] = { 0 };
	wire_ctx_t buffer_ctx = wire_init(buffer, sizeof(buffer));

	int r = filter(&name_ctx, &buffer_ctx, filter_escape);
	if (r != DNSSEC_EOK) {
		return r;
	}

	return buffer_to_string(&buffer_ctx, escaped);
}

int unescape_zone_name(const char *escaped, char **name)
{
	assert(escaped);
	assert(name);

	wire_ctx_t escaped_ctx = wire_init((uint8_t *)escaped, strlen(escaped));

	uint8_t buffer[BUFFER_SIZE] = { 0 };
	wire_ctx_t buffer_ctx = wire_init(buffer, sizeof(buffer));

	int r = filter(&escaped_ctx, &buffer_ctx, filter_unescape);
	if (r != DNSSEC_EOK) {
		return r;
	}

	return buffer_to_string(&buffer_ctx, name);
}
