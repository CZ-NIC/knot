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
