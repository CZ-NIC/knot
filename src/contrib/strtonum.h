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
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#include "libknot/errcode.h"
#include "contrib/ctype.h"

inline static int intmax_from_str(const char *src, intmax_t *dest,
                                  intmax_t min, intmax_t max)
{
	if (!is_digit(*src) && *src != '-' && *src != '+') {
		return KNOT_EINVAL;
	}

	errno = 0;
	char *end = NULL;
	intmax_t result = strtoimax(src, &end, 10);

	if (errno == ERANGE) {
		return KNOT_ERANGE;
	}

	if (src == end || *end != '\0') {
		return KNOT_EINVAL;
	}

	if (result < min || result > max) {
		return KNOT_ERANGE;
	}

	*dest = result;
	return KNOT_EOK;
}

inline static int uintmax_from_str(const char *src, uintmax_t *dest,
                                   uintmax_t min, uintmax_t max)
{
	if (!is_digit(*src) && *src != '+') {
		return KNOT_EINVAL;
	}

	errno = 0;
	char *end = NULL;
	uintmax_t result = strtoumax(src, &end, 10);

	if (errno == ERANGE) {
		return KNOT_ERANGE;
	}

	if (src == end || *end != '\0') {
		return KNOT_EINVAL;
	}

	if (result < min || result > max) {
		return KNOT_ERANGE;
	}

	*dest = result;
	return KNOT_EOK;
}

#define CONVERT(prefix, type, min, max, src, dest)                \
{                                                                 \
	prefix##max_t value;                                      \
	int result = prefix##max_from_str(src, &value, min, max); \
	if (result != KNOT_EOK) {                                 \
		return result;                                    \
	}                                                         \
	*dest = (type)value;                                      \
	return KNOT_EOK;                                          \
}

inline static int str_to_int(const char *src, int *dest, int min, int max)
{
	CONVERT(int, int, min, max, src, dest);
}

inline static int str_to_u8(const char *src, uint8_t *dest)
{
	CONVERT(uint, uint8_t, 0, UINT8_MAX, src, dest);
}

inline static int str_to_u16(const char *src, uint16_t *dest)
{
	CONVERT(uint, uint16_t, 0, UINT16_MAX, src, dest);
}

inline static int str_to_u32(const char *src, uint32_t *dest)
{
	CONVERT(uint, uint32_t, 0, UINT32_MAX, src, dest);
}

inline static int str_to_size(const char *src, size_t *dest, size_t min, size_t max)
{
	CONVERT(uint, size_t, min, max, src, dest);
}

#undef CONVERT
