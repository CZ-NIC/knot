/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
/*!
 * \file strtonum.h
 *
 * \brief Universal interface for safe conversion of strings to numbers.
 *
 * \author Jan Vcelak <jan.vcelak@nic.cz>
 *
 * \addtogroup common_lib
 * @{
 */

#pragma once

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include "libknot/errcode.h"

typedef long long int knot_strtoll_result_t;
typedef unsigned long long int knot_strtoull_result_t;

/*!
 * \brief Convert string to signed integer.
 *
 * \param[in]  src   Input string.
 * \param[out] dest  Output integral value.
 *
 * \return Error code.
 * \retval KNOT_EOK     The conversion was successful.
 * \retval KNOT_ERANGE  The value is outside target type range.
 * \retval KNOT_EMALF   The input value is not terminated.
 */
static int knot_strtoll(const char *src, knot_strtoll_result_t *dest)
{
	char *end;
	knot_strtoll_result_t result = strtoll(src, &end, 10);
	if (errno == ERANGE)
		return KNOT_ERANGE;

	if (src == end || *end != '\0')
		return KNOT_EMALF;

	*dest = result;
	return KNOT_EOK;
}

/*!
 * \brief Convert string to unsigned integer.
 *
 * \see knot_strtoll
 */
static int knot_strtoull(const char *src, knot_strtoull_result_t *dest)
{
	char *end;
	knot_strtoull_result_t result = strtoull(src, &end, 10);
	if (errno == ERANGE)
		return KNOT_ERANGE;

	if (src == end || *end != '\0')
		return KNOT_EMALF;

	*dest = result;
	return KNOT_EOK;
}

/*!
 * \brief Helper macro defining body of individual conversion functions.
 *
 * \param type      Target data type.
 * \param function  Underlying conversion function.
 * \param min       Minimal value valid for given data type.
 * \param max       Maximal value valid for given data type.
 * \param src       Pointer to source string.
 * \param dest      Pointer to destination type.
 *
 * \return Error code.
 * \retval KNOT_EOK     The conversion was successful.
 * \retval KNOT_ERANGE  The value is outside target type range.
 * \retval KNOT_EMALF   The input value is not terminated.
 */
#define KNOT_STR2NUM(type, function, min, max, src, dest) \
{                                                         \
	function##_result_t value;                        \
	errno = 0;                                        \
	int result = function((src), &value);             \
	if (result != KNOT_EOK)                           \
		return result;                            \
	                                                  \
	if (value < (min) || value > (max))               \
		return KNOT_ERANGE;                       \
	                                                  \
	*(dest) = (type)value;                            \
	return KNOT_EOK;                                  \
}

inline static int knot_str2int(const char *src, int *dest)
{
	KNOT_STR2NUM(int, knot_strtoll, INT_MIN, INT_MAX, src, dest)
}

inline static int knot_str2uint8t(const char *src, uint8_t *dest)
{
	KNOT_STR2NUM(uint8_t, knot_strtoull, 0, UINT8_MAX, src, dest)
}

inline static int knot_str2uint16t(const char *src, uint16_t *dest)
{
	KNOT_STR2NUM(uint16_t, knot_strtoull, 0, UINT16_MAX, src, dest)
}

/*! @} */
