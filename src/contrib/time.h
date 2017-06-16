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

#pragma once

#include <stdint.h>
#include <time.h>

/*!
 * \brief Get current time.
 */
struct timespec time_now(void);

/*!
 * \brief Get time elapsed between two events.
 */
struct timespec time_diff(const struct timespec *begin, const struct timespec *end);

/*!
 * \brief Get time elapsed between two events in miliseconds.
 */
double time_diff_ms(const struct timespec *begin, const struct timespec *end);

/*!
 * \brief Data type for keeping UNIX timestamps.
 *
 * This is because time_t can be 32-bit on some systems, which is bad.
 * Zero value represents infinity.
 */
typedef uint64_t knot_time_t;

/*!
 * \brief Data type for keeping time differences.
 */
typedef int64_t knot_timediff_t;

#define KNOT_TIMEDIFF_MIN INT64_MIN
#define KNOT_TIMEDIFF_MAX INT64_MAX

/*!
 * \brief Returns current time sice epoch.
 */
inline static knot_time_t knot_time(void)
{
	return (knot_time_t)time(NULL);
}

/*!
 * \brief Compare two timestamps.
 *
 * \return 0 if equal, -1 if the former is smaller (=earlier), 1 else.
 */
inline static int knot_time_cmp(knot_time_t a, knot_time_t b)
{
	return (a == b ? 0 : 1) * ((a && b) == 0 ? -1 : 1) * (a < b ? -1 : 1);
}

/*!
 * \brief Return the smaller (=earlier) from given two timestamps.
 */
inline static knot_time_t knot_time_min(knot_time_t a, knot_time_t b)
{
	if ((a && b) == 0) {
		return a + b;
	} else {
		return (a < b ? a : b);
	}
}

/*!
 * \brief Return the difference between two timestamps (to "minus" from).
 *
 * \note If both are zero (=infinity), KNOT_TIMEDIFF_MAX is returned.
 */
inline static knot_timediff_t knot_time_diff(knot_time_t to, knot_time_t from)
{
	if ((to && from) == 0) {
		return (to > from ? KNOT_TIMEDIFF_MIN : KNOT_TIMEDIFF_MAX);
	} else {
		return (knot_timediff_t)to - (knot_timediff_t)from;
	}
}

/*!
 * \brief Add a time difference to timestamp.
 */
inline static knot_time_t knot_time_add(knot_time_t since, knot_timediff_t howlong)
{
	return (since != 0 ? since + howlong : since);
}

/*!
 * \brief Convert uint32_t-encoded timestamp to knot_time_t.
 *
 * In RRSIG rdata, there are inception and expiration timestamps in uint32_t format.
 * One shall use 'serial arithmetics' to decode them.
 *
 * \todo However it needs time(now) context which is slow to obtain, so we don't do it
 *       for now. Please fix this in next 100 years.
 */
inline static knot_time_t knot_time_from_u32(uint32_t u32time)
{
	return (knot_time_t)u32time;
}
