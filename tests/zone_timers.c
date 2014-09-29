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

#include <stdlib.h>
#include <time.h>
#include <tap/basic.h>

#include "libknot/common.h"
#include "common/namedb/namedb.h"
#include "knot/zone/timers.h"
#include "knot/zone/zone.h"
#include "knot/zone/events/events.h"

#define SLIP (1024 * 1024)
static const size_t REFRESH_SLIP = SLIP;
static const size_t EXPIRE_SLIP = SLIP + 1;
static const size_t FLUSH_SLIP = SLIP + 2;

int main(int argc, char *argv[])
{
	plan_lazy();

	// Temporary DB identifier.
	char dbid_buf[] = "/tmp/timerdb.XXXXXX";
	const char *dbid = mkdtemp(dbid_buf);
	
	// Mockup zone.
	conf_zone_t zone_conf = { .name = "test." };
	zone_t *zone = zone_new(&zone_conf);
	assert(zone);

	knot_namedb_t *db = open_timers_db(dbid);
	ok(db != NULL, "zone timers: create");

	// Set up events in the future.
	const time_t now = time(NULL);
	const time_t REFRESH_TIME = now + REFRESH_SLIP;
	const time_t EXPIRE_TIME = now + EXPIRE_SLIP;
	const time_t FLUSH_TIME = now + FLUSH_SLIP;

	// Refresh, expire and flush are the permanent events for now.
	zone_events_schedule_at(zone, ZONE_EVENT_REFRESH, REFRESH_TIME);
	zone_events_schedule_at(zone, ZONE_EVENT_EXPIRE, EXPIRE_TIME);
	zone_events_schedule_at(zone, ZONE_EVENT_FLUSH, FLUSH_TIME);

	// Write the timers.
	int ret = write_zone_timers(db, zone);
	ok(ret == KNOT_EOK, "zone timers: write");

	// Read the timers.
	time_t timers[ZONE_EVENT_COUNT];
	ret = read_zone_timers(db, zone, timers);
	ok(ret == KNOT_EOK &&
	   timers[ZONE_EVENT_REFRESH] == REFRESH_TIME &&
	   timers[ZONE_EVENT_EXPIRE] == EXPIRE_TIME &&
	   timers[ZONE_EVENT_FLUSH] == FLUSH_TIME, "zone timers: read");

	// Clean up.
	zone->conf = NULL;
	zone_free(&zone);
	close_timers_db(db);

	return EXIT_SUCCESS;
}

