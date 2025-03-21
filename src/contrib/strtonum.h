/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#include "libknot/errcode.h"
#include "contrib/ctype.h"

inline static int intmax_from_str(const char *src, intmax_t *dst,
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

	*dst = result;
	return KNOT_EOK;
}

inline static int uintmax_from_str(const char *src, uintmax_t *dst,
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

	*dst = result;
	return KNOT_EOK;
}

#define CONVERT(prefix, type, min, max, src, dst)                 \
{                                                                 \
	assert(src && dst);                                       \
	prefix##max_t value;                                      \
	int result = prefix##max_from_str(src, &value, min, max); \
	if (result != KNOT_EOK) {                                 \
		return result;                                    \
	}                                                         \
	*dst = (type)value;                                       \
	return KNOT_EOK;                                          \
}

inline static int str_to_int(const char *src, int *dst, int min, int max)
{
	CONVERT(int, int, min, max, src, dst);
}

inline static int str_to_u8(const char *src, uint8_t *dst)
{
	CONVERT(uint, uint8_t, 0, UINT8_MAX, src, dst);
}

inline static int str_to_u16(const char *src, uint16_t *dst)
{
	CONVERT(uint, uint16_t, 0, UINT16_MAX, src, dst);
}

inline static int str_to_u32(const char *src, uint32_t *dst)
{
	CONVERT(uint, uint32_t, 0, UINT32_MAX, src, dst);
}

inline static int str_to_u64(const char *src, uint64_t *dst)
{
	CONVERT(uint, uint64_t, 0, UINT64_MAX, src, dst);
}

inline static int str_to_size(const char *src, size_t *dst, size_t min, size_t max)
{
	CONVERT(uint, size_t, min, max, src, dst);
}

#undef CONVERT
