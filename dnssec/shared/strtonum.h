#pragma once

#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>

#include "error.h"

inline static int str_to_intmax(const char *src, intmax_t *dest)
{
	char *end = NULL;
	intmax_t result = strtoimax(src, &end, 10);

	if (errno == ERANGE) {
		return DNSSEC_OUT_OF_RANGE;
	}

	if (src == end || *end != '\0') {
		return DNSSEC_MALFORMED_DATA;
	}

	*dest = result;
	return DNSSEC_EOK;
}

inline static int str_to_uintmax(const char *src, uintmax_t *dest)
{
	char *end = NULL;
	uintmax_t result = strtoumax(src, &end, 10);

	if (errno == ERANGE) {
		return DNSSEC_OUT_OF_RANGE;
	}

	if (src == end || *end != '\0') {
		return DNSSEC_MALFORMED_DATA;
	}

	*dest = result;
	return DNSSEC_EOK;
}

#define CONVERT(function, maxtype, type, min, max, src, dest) \
{                                                             \
	maxtype value;                                        \
	int result = function(src, &value);                   \
	if (result != DNSSEC_EOK) {                           \
		return result;                                \
	}                                                     \
	if (value < (min) || value > (max)) {                 \
		return DNSSEC_OUT_OF_RANGE;                   \
	}                                                     \
	*dest = (type)value;                                  \
	return DNSSEC_EOK;                                    \
}

inline static int str_to_int(const char *src, int *dest)
{
	CONVERT(str_to_uintmax, uintmax_t, int, INT_MIN, INT_MAX, src, dest);
}

inline static int str_to_u8(const char *src, uint8_t *dest)
{
	CONVERT(str_to_uintmax, uintmax_t, uint8_t, 0, UINT8_MAX, src, dest);
}

inline static int str_to_u16(const char *src, uint16_t *dest)
{
	CONVERT(str_to_uintmax, uintmax_t, uint16_t, 0, UINT16_MAX, src, dest);
}

#undef CONVERT
