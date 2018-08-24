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
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include <stdint.h>
#include <time.h>
#include <inttypes.h>

/*!
 * \brief Specify output format for knot_time_print().
 */
typedef enum {
	TIME_PRINT_UNIX,	// numeric UNIX time
	TIME_PRINT_ISO8601,	// 2016-12-31T23:59:00
	TIME_PRINT_RELSEC,	// relative +6523
	TIME_PRINT_HUMAN_MIXED,	// relative with mixed-case units
	TIME_PRINT_HUMAN_LOWER,	// relative with lower-case units
} knot_time_print_t;

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

#define KNOT_TIME_PRINTF PRIu64
#define KNOT_TIMEDIFF_PRINTF PRId64

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

/*!
 * \brief Parse a text-formatted timestamp to knot_time_t using format specification.
 *
 * \param format    The timestamp text format specification.
 * \param timespec  Text-formatted timestamp.
 * \param time      The parsed timestamp.
 *
 * The format specification basics:
 * <format 1>|<format 2> - The pipe sign separates two time format specifications. Leftmost
 *                         specification matching the timespec is used.
 * '<a string>'          - Matches exactly <a string> (not containing apostrophes) in timespec.
 * #                     - Hashtag matches for a number in timespec, stands for either a UNIX timestamp,
 *                         or, within a context of an unit, as a number of such units.
 * Y, M, D, h, m, s      - Matches a number, stands for a number of years, months, days, hours,
 *                         minutes and seconds, respectively.
 * +, -                  - The + and - signs declaring that following timespec is relative to "now".
 *                         A single sign can be used to limit the timestamp being in future or in past,
 *                         or both +- allow the timestamp to select any (just one) of them.
 * U                     - Matches one of Y, M, D, h, m, s in the timespec standing for a time unit.
 * u                     - Like U, but the unit in the timestamp is from: y, mo, d, h, mi, s.
 *
 * \retval -1  An error occurred, out_time has no sense.
 * \return  0  OK, timestamp parsed successfully.
 */
int knot_time_parse(const char *format, const char *timespec, knot_time_t *time);

/*!
 * \brief Print the timestamp in specified format into a string buffer.
 *
 * \param format   The timestamp text format specification.
 * \param time     The timestamp to be printed.
 * \param dst      The destination buffer pointer with text-formatted timestamp.
 * \param dst_len  The destination buffer length.
 *
 * \retval -1 An error occurred, the buffer may be filled with nonsense.
 * \return  0 OK, timestamp printed successfully.
 */
int knot_time_print(knot_time_print_t format, knot_time_t time, char *dst, size_t dst_len);
