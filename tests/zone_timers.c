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

#include <dirent.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <tap/basic.h>

#include "libknot/internal/namedb/namedb.h"
#include "libknot/internal/namedb/namedb_lmdb.h"
#include "contrib/string.h"
#include "libknot/libknot.h"
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

	if (namedb_lmdb_api() == NULL) {
		skip("LMDB API not compiled");
		return EXIT_SUCCESS;
	}

	// Temporary DB identifier.
	char dbid_buf[] = "/tmp/timerdb.XXXXXX";
	const char *dbid = mkdtemp(dbid_buf);

	// Mockup zones.
	knot_dname_t *zone_name;
	zone_name = knot_dname_from_str_alloc("test1.");
	zone_t *zone_1 = zone_new(zone_name);
	knot_dname_free(&zone_name, NULL);
	zone_name = knot_dname_from_str_alloc("test2.");
	zone_t *zone_2 = zone_new(zone_name);
	knot_dname_free(&zone_name, NULL);
	assert(zone_1 && zone_2);

	// Mockup zonedb.
	knot_zonedb_t *zone_db = knot_zonedb_new(2);
	assert(zone_db);
	int ret = knot_zonedb_insert(zone_db, zone_1);
	assert(ret == KNOT_EOK);
	ret = knot_zonedb_insert(zone_db, zone_2);
	assert(ret == KNOT_EOK);

	knot_zonedb_build_index(zone_db);

	namedb_t *db = NULL;
	ret = open_timers_db(dbid, &db);
	ok(ret == KNOT_EOK && db != NULL, "zone timers: create");

	// Set up events in the future.
	const time_t now = time(NULL);
	const time_t REFRESH_TIME = now + REFRESH_SLIP;
	const time_t EXPIRE_TIME = now + EXPIRE_SLIP;
	const time_t FLUSH_TIME = now + FLUSH_SLIP;

	// Refresh, expire and flush are the permanent events for now.
	zone_events_schedule_at(zone_1, ZONE_EVENT_REFRESH, REFRESH_TIME);
	zone_events_schedule_at(zone_1, ZONE_EVENT_EXPIRE, EXPIRE_TIME);
	zone_events_schedule_at(zone_1, ZONE_EVENT_FLUSH, FLUSH_TIME);

	// Write the timers.
	ret = write_timer_db(db, zone_db);
	ok(ret == KNOT_EOK, "zone timers: write");

	// Read the timers.
	time_t timers[ZONE_EVENT_COUNT];
	ret = read_zone_timers(db, zone_1, timers);
	ok(ret == KNOT_EOK &&
	   timers[ZONE_EVENT_REFRESH] == REFRESH_TIME &&
	   timers[ZONE_EVENT_EXPIRE] == EXPIRE_TIME &&
	   timers[ZONE_EVENT_FLUSH] == FLUSH_TIME, "zone timers: read set");

	// Sweep and read again - timers should stay the same.
	int s_ret = sweep_timer_db(db, zone_db);
	if (s_ret == KNOT_EOK) {
		ret = read_zone_timers(db, zone_1, timers);
	}
	ok(s_ret == KNOT_EOK && ret == KNOT_EOK &&
	   timers[ZONE_EVENT_REFRESH] == REFRESH_TIME &&
	   timers[ZONE_EVENT_EXPIRE] == EXPIRE_TIME &&
	   timers[ZONE_EVENT_FLUSH] == FLUSH_TIME, "zone timers: sweep no-op");

	// Read timers for unset zone.
	const time_t empty_timers[ZONE_EVENT_COUNT] = { '\0' };
	ret = read_zone_timers(db, zone_2, timers);
	ok(ret == KNOT_EOK &&
	   memcmp(timers, empty_timers, sizeof(timers)) == 0, "zone timers: read unset");

	// Remove first zone from db and sweep.
	ret = knot_zonedb_del(zone_db, zone_1->name);
	assert(ret == KNOT_EOK);

	s_ret = sweep_timer_db(db, zone_db);
	if (s_ret == KNOT_EOK) {
		ret = read_zone_timers(db, zone_1, timers);
	}
	ok(s_ret == KNOT_EOK && ret == KNOT_EOK &&
	   memcmp(timers, empty_timers, sizeof(timers)) == 0, "zone timers: sweep");

	// Clean up.
	zone_free(&zone_1);
	zone_free(&zone_2);
	close_timers_db(db);

	// Cleanup temporary DB.
	char *timers_dir = sprintf_alloc("%s/timers", dbid);
	DIR *dir = opendir(timers_dir);
	struct dirent *dp;
	while ((dp = readdir(dir)) != NULL) {
		if (dp->d_name[0] == '.') {
			continue;
		}
		char *file = sprintf_alloc("%s/%s", timers_dir, dp->d_name);
		remove(file);
		free(file);
	}
	closedir(dir);
	remove(timers_dir);
	free(timers_dir);
	remove(dbid);

	return EXIT_SUCCESS;
}
