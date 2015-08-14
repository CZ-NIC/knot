/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <time.h>

#include "shared.h"

/*
 * POSIX strftime supports '%z', strptime doesn't.
 */
#define TIME_FORMAT "%Y-%m-%dT%H:%M:%S"

/*!
 * Read time zone offset in +hhmm or -hhmm format.
 *
 * Format written by '%z' specifier in \ref strftime.
 */
static bool read_timezone(const char *buffer, int *offset)
{
	assert(buffer);

	if (strlen(buffer) != 5) {
		return false;
	}

	char sign;
	unsigned hours, mins;
	if (sscanf(buffer, "%c%2u%2u", &sign, &hours, &mins) != 3) {
		return false;
	}

	if (sign != '+' && sign != '-') {
		return false;
	}

	if (hours > 23 || mins > 59) {
		return false;
	}

	*offset = (sign == '+' ? 1 : -1) * (hours * 3600 + mins * 60);

	return true;
}

_public_
bool timestamp_write(char *buffer, size_t size, time_t timestamp)
{
	if (!buffer) {
		return false;
	}

	struct tm tm = { 0 };
	if (!gmtime_r(&timestamp, &tm)) {
		return false;
	}

	return strftime(buffer, size, TIME_FORMAT "+0000", &tm) != 0;
}

_public_
bool timestamp_read(const char *buffer, time_t *timestamp_ptr)
{
	if (!buffer || !timestamp_ptr) {
		return false;
	}

	struct tm tm = { 0 };
	const char *timezone = strptime(buffer, TIME_FORMAT, &tm);
	if (timezone == NULL) {
		return false;
	}

	int gmtoff = 0;
	if (!read_timezone(timezone, &gmtoff)) {
		return false;
	}

	*timestamp_ptr = timegm(&tm) - gmtoff;

	return true;
}
