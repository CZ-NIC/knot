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

#include <string.h>
#include <tap/basic.h>

#include "timestamp.h"

int main(int argc, char *argv[])
{
	plan_lazy();

	char buffer[128] = { 0 };

	ok(timestamp_write(NULL, 0, 0) == false,
	   "timestamp_write: no buffer");
	ok(timestamp_write(buffer, 10, 0) == false,
	   "timestamp_write: small buffer");
	ok(timestamp_write(buffer, sizeof(buffer), 0) &&
	   strcmp(buffer, "1970-01-01T00:00:00+0000") == 0,
	   "timestamp_write: epoch begin");
	ok(timestamp_write(buffer, sizeof(buffer), 1439554225) &&
	   strcmp(buffer, "2015-08-14T12:10:25+0000") == 0,
	   "timestamp_write: date in past");
	ok(timestamp_write(buffer, sizeof(buffer), 2147483646) &&
	   strcmp(buffer, "2038-01-19T03:14:06+0000") == 0,
	   "timestamp_write: date in future (likely)");

	time_t ts = 0;

	ok(timestamp_read(NULL, &ts) == false,
	   "timestamp_read: no buffer");
	ok(timestamp_read("", NULL) == false,
	   "timestamp_read: no output");
	ok(timestamp_read("", &ts) == false,
	   "timestamp_read: empty input");
	ok(timestamp_read("1970-01-01T00:00:00", &ts) == false,
	   "timestamp_read: missing time zone");
	ok(timestamp_read("1970-01-01T00:00:00+000", &ts) == false,
	   "timestamp_read: malformed time zone");
	ok(timestamp_read("1970-01-01T00:00:00+2400", &ts) == false,
	   "timestamp_read: malformed time zone hours");
	ok(timestamp_read("1970-01-01T00:00:00+0090", &ts) == false,
	   "timestamp_read: malformed time zone minuts");
	ok(timestamp_read("1970-01-01T00:00:01+0000", &ts) && ts == 1,
	   "timestamp_read: first second since epoch");
	ok(timestamp_read("2009-02-13T23:31:31+0000", &ts) && ts == 1234567891,
	   "timestamp_read: date in past");
	ok(timestamp_read("2034-05-05T01:24:20+0000", &ts) && ts == 2030405060,
	   "timestamp_read: date in future (likely)");

	ok(timestamp_read("2015-08-14T14:25:46+0200", &ts) &&
	   timestamp_write(buffer, sizeof(buffer), ts) &&
	   strcmp(buffer, "2015-08-14T12:25:46+0000") == 0,
	   "timestamp convert time zone (east)");
	ok(timestamp_read("2015-08-14T10:19:17-0230", &ts) &&
	   timestamp_write(buffer, sizeof(buffer), ts) &&
	   strcmp(buffer, "2015-08-14T12:49:17+0000") == 0,
	   "timestamp convert time zone (west)");

	return 0;
}
