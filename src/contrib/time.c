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

#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "contrib/time.h"
#ifndef HAVE_CLOCK_GETTIME
	#include <sys/time.h>
#endif

struct timespec time_now(void)
{
	struct timespec result = { 0 };

#ifdef HAVE_CLOCK_GETTIME
	clock_gettime(CLOCK_MONOTONIC, &result);
#else // OS X < Sierra fallback.
	struct timeval tmp = { 0 };
	gettimeofday(&tmp, NULL);
	result.tv_sec = tmp.tv_sec;
	result.tv_nsec = 1000 * tmp.tv_usec;
#endif

	return result;
}

struct timespec time_diff(const struct timespec *begin, const struct timespec *end)
{
	struct timespec result = { 0 };

	if (end->tv_nsec >= begin->tv_nsec) {
		result.tv_sec  = end->tv_sec - begin->tv_sec;
		result.tv_nsec = end->tv_nsec - begin->tv_nsec;
	} else {
		result.tv_sec  = end->tv_sec - begin->tv_sec - 1;
		result.tv_nsec = 1000000000 - begin->tv_nsec + end->tv_nsec;
	}

	return result;
}

double time_diff_ms(const struct timespec *begin, const struct timespec *end)
{
	struct timespec result = time_diff(begin, end);

	return (result.tv_sec * 1e3) + (result.tv_nsec / 1e6);
}

typedef struct {
	const char *format;
	const char *timespec;
	const char *parsed;
	knot_timediff_t offset;
	char offset_sign;
	char offset_unit;
	struct tm calendar;
	int error;
} time_ctx_t;

// After casting (struct tm) to (int []), we can use indexes...
static int calendar_index(char ind)
{
	switch (ind) {
	case 'Y': return 5;
	case 'M': return 4;
	case 'D': return 3;
	case 'h': return 2;
	case 'm': return 1;
	case 's': return 0;
	default: assert(0); return 6;
	}
}

static size_t calendar_digits(int index)
{
	return index == 5 ? 4 : 2;
}

static size_t unit_value(char unit)
{
	size_t val = 1;
	switch (unit) {
	case 'M':
		return 3600 * 24 * 30;
	case 'Y':
		val *= 365;
		// FALLTHROUGH
	case 'D':
		val *= 24;
		// FALLTHROUGH
	case 'h':
		val *= 60;
		// FALLTHROUGH
	case 'm':
		val *= 60;
		// FALLTHROUGH
	case 's':
	default:
		return val;
	}
}

static knot_time_t time_ctx_finalize(time_ctx_t *ctx)
{
	if (ctx->offset_sign) {
		ctx->offset *= unit_value(ctx->offset_unit);
		return knot_time_add(knot_time(), (ctx->offset_sign == '-' ? -1 : 1) * ctx->offset);
	} else if (ctx->offset) {
		return (knot_time_t)ctx->offset;
	} else if (ctx->calendar.tm_year != 0) {
		ctx->calendar.tm_isdst = -1;
		ctx->calendar.tm_year -= 1900;
		ctx->calendar.tm_mon -= 1;
		// Set UTC timezone before using mktime
		putenv("TZ=UTC");
		tzset();
		return (knot_time_t)mktime(&ctx->calendar);
	} else {
		return (knot_time_t)0;
	}
}

static void time_ctx_reset(time_ctx_t *ctx)
{
	ctx->parsed = ctx->timespec;
	ctx->offset = 0;
	ctx->offset_sign = 0;
	memset(&ctx->calendar, 0, sizeof(ctx->calendar));
	ctx->error = 0;
}

static void parse_quote(time_ctx_t *ctx)
{
	while (*ctx->format != '|' && *ctx->format != '\0') {
		if (*ctx->format == '\'') {
			ctx->format++;
			return;
		}
		if (*ctx->format++ != *ctx->parsed++) {
			ctx->error = -1;
			return;
		}
	}
	ctx->error = -2;
	return;
}

static void parse_offset(time_ctx_t *ctx)
{
	ctx->offset = 0;
	ctx->error = -1;
	while (isdigit(*ctx->parsed)) {
		ctx->offset *= 10;
		ctx->offset += *ctx->parsed++ - '0';
		ctx->error = 0;
	}
}

static void parse_calendar(time_ctx_t *ctx, int index)
{
	int *cal_arr = (int *)&ctx->calendar;
	cal_arr[index] = 0;
	for (size_t i = 0; i < calendar_digits(index); i++) {
		if (!isdigit(*ctx->parsed)) {
			ctx->error = -1;
			return;
		}
		cal_arr[index] *= 10;
		cal_arr[index] += *ctx->parsed++ - '0';
	}
}

static void parse_sign(time_ctx_t *ctx)
{
	char sign1 = *(ctx->format - 1), sign2 = *ctx->format;

	bool use_sign2 = (sign2 == '+' || sign2 == '-');

	bool allow_plus = (sign1 == '+' || (sign1 == '-' && sign2 == '+'));
	bool allow_minus = (sign1 == '-' || (sign1 == '+' && sign2 == '-'));
	assert(sign1 == '+' || sign1 == '-');

	if ((*ctx->parsed == '+' && allow_plus) || (*ctx->parsed == '-' && allow_minus)) {
		ctx->offset_sign = *ctx->parsed++;
		ctx->format += (use_sign2 ? 1 : 0);
	} else {
		ctx->error = -11;
	}
}

static void parse_unit1(time_ctx_t *ctx)
{
	char u = *ctx->parsed++;
	switch (u) {
	case 'Y':
	case 'M':
	case 'D':
	case 'h':
	case 'm':
	case 's':
		ctx->offset_unit = u;
		break;
	default:
		ctx->error = -1;
	}
}

static void parse_unit2(time_ctx_t *ctx)
{
	char u = *ctx->parsed++;
	switch (u) {
	case 'y':
	case 'd':
		ctx->offset_unit = toupper(u);
		break;
	case 'h':
	case 's':
		ctx->offset_unit = u;
		break;
	case 'm':
		switch (*ctx->parsed++) {
		case 'o':
			ctx->offset_unit = 'M';
			break;
		case 'i':
			ctx->offset_unit = 'm';
			break;
		default:
			ctx->error = -1;
		}
		break;
	default:
		ctx->error = -1;
	}
}

int knot_time_parse(const char *format, const char *timespec, knot_time_t *time)
{
	if (format == NULL || timespec == NULL || time == NULL) {
		return -1;
	}

	time_ctx_t ctx = {
		.format = format,
		.timespec = timespec,
		.parsed = timespec,
		.offset = 0,
		.offset_sign = 0,
		// we hope that .calendar is zeroed by default
		.error = 0,
	};

	while (ctx.error == 0 && *ctx.format != '\0') {
		switch (*ctx.format++) {
		case '|':
			if (*ctx.parsed == '\0') {
				*time = time_ctx_finalize(&ctx);
				return 0;
			} else {
				time_ctx_reset(&ctx);
			}
			break;
		case '\'':
			parse_quote(&ctx);
			break;
		case '#':
			parse_offset(&ctx);
			break;
		case 'Y':
		case 'M':
		case 'D':
		case 'h':
		case 'm':
		case 's':
			parse_calendar(&ctx, calendar_index(*(ctx.format - 1)));
			break;
		case '+':
		case '-':
			parse_sign(&ctx);
			break;
		case 'U':
			parse_unit1(&ctx);
			break;
		case 'u':
			parse_unit2(&ctx);
			break;
		default:
			return -1;
		}

		if (ctx.error < 0) {
			while (*ctx.format != '|' && *ctx.format != '\0') {
				ctx.format++;
			}
			time_ctx_reset(&ctx);
			ctx.error = (*ctx.format == '\0' ? -1 : 0);
		}
	}

	if (ctx.error == 0 && *ctx.parsed == '\0') {
		*time = time_ctx_finalize(&ctx);
		return 0;
	}
	return -1;
}

static char *unit_names_mixed[] = { "Y", "M", "D", "h", "m", "s" };
static char *unit_names_lower[] = { "y", "mo", "d", "h", "mi", "s" };
static size_t unit_sizes[] = { 3600*24*365, 3600*24*30, 3600*24, 3600, 60, 1 };
static const size_t unit_count = 6;

static int print_unit(char *dst, size_t dst_len, char *unit_names[unit_count],
                      size_t max_units, knot_time_t time)
{
	int ret;
	if (time == 0) {
		ret = snprintf(dst, dst_len, "0");
		return (ret < 0 || ret >= dst_len ? -1 : 0);
	}
	knot_timediff_t diff = knot_time_diff(time, knot_time());
	if (dst_len-- < 1) {
		return -1;
	}
	*dst++ = (diff < 0 ? '-' : '+');
	if (diff < 0) {
		diff = -diff;
	} else if (diff == 0) {
		ret = snprintf(dst, dst_len, "0%s", unit_names[unit_count - 1]);
		return (ret < 0 || ret >= dst_len ? -1 : 0);
	}
	size_t curr_unit = 0, used_units = 0;
	while (curr_unit < unit_count && used_units < max_units) {
		if (diff >= unit_sizes[curr_unit]) {
			ret = snprintf(dst, dst_len, "%"KNOT_TIMEDIFF_PRINTF"%s",
			               diff / unit_sizes[curr_unit],
			               unit_names[curr_unit]);
			if (ret < 0 || ret >= dst_len) {
				return -1;
			}
			dst += ret;
			dst_len -= ret;
			used_units++;
			diff %= unit_sizes[curr_unit];
		}
		curr_unit++;
	}
	return 0;
}

int knot_time_print(knot_time_print_t format, knot_time_t time, char *dst, size_t dst_len)
{
	if (dst == NULL) {
		return -1;
	}

	int ret;
	switch (format) {
	case TIME_PRINT_UNIX:
		ret = snprintf(dst, dst_len, "%"KNOT_TIME_PRINTF, time);
		return ((ret >= 0 && ret < dst_len) ? 0 : -1);
	case TIME_PRINT_ISO8601:
		if (time > LONG_MAX) {
			return -1;
		}
		struct tm lt;
		time_t tt = (time_t)time;
		ret = (localtime_r(&tt, &lt) == NULL ? -1 :
		       strftime(dst, dst_len, "%Y-%m-%dT%H:%M:%S", &lt));
		return (ret > 0 ? 0 : -1);
	case TIME_PRINT_RELSEC:
		ret = snprintf(dst, dst_len, "%+"KNOT_TIMEDIFF_PRINTF,
		               knot_time_diff(time, knot_time()));
		return ((ret >= 0 && ret < dst_len) ? 0 : -1);
	case TIME_PRINT_HUMAN_MIXED:
		return print_unit(dst, dst_len, unit_names_mixed, unit_count, time);
	case TIME_PRINT_HUMAN_LOWER:
		return print_unit(dst, dst_len, unit_names_lower, unit_count, time);
	default:
		return -1;
	}
}
