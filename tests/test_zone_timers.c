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

#include <assert.h>
#include <stdlib.h>
#include <tap/basic.h>
#include <tap/files.h>

#include "knot/zone/timers.h"
#include "libknot/db/db_lmdb.h"
#include "libknot/dname.h"
#include "libknot/error.h"

static const zone_timers_t MOCK_TIMERS = {
	.soa_expire = 3600,
	.last_refresh = 1474559950,
	.next_refresh = 1474559960,
	.last_flush = 1474559900,
};

static bool keep_all(const knot_dname_t *zone, void *data)
{
	return true;
}

static bool remove_all(const knot_dname_t *zone, void *data)
{
	return false;
}

static bool timers_eq(const zone_timers_t *a, const zone_timers_t *b)
{
	return a->soa_expire == b->soa_expire &&
	       a->last_refresh == b->last_refresh &&
	       a->next_refresh == b->next_refresh &&
	       a->last_flush == b->last_flush;
}

int main(int argc, char *argv[])
{
	plan_lazy();
	assert(knot_db_lmdb_api());

	char *dbid = test_mkdtemp();
	if (!dbid) {
		return EXIT_FAILURE;
	}

	const knot_dname_t *zone = (uint8_t *)"\x7""example""\x3""com";
	struct zone_timers timers = MOCK_TIMERS;

	// Create database
	knot_db_t *db = NULL;
	int ret = zone_timers_open(dbid, &db);
	ok(ret == KNOT_EOK && db != NULL, "zone_timers_open()");

	// Lookup nonexistent
	ret = zone_timers_read(db, zone, &timers);
	ok(ret == KNOT_ENOENT, "zone_timer_read() nonexistent");

	// Write timers
	ret = zone_timers_write(db, zone, &timers, NULL);
	ok(ret == KNOT_EOK, "zone_timers_write()");

	// Read timers
	memset(&timers, 0, sizeof(timers));
	ret = zone_timers_read(db, zone, &timers);
	ok(ret == KNOT_EOK && timers_eq(&timers, &MOCK_TIMERS), "zone_timers_read()");

	// Sweep none
	ret = zone_timers_sweep(db, keep_all, NULL);
	ok(ret == KNOT_EOK, "zone_timers_sweep() none");
	ret = zone_timers_read(db, zone, &timers);
	ok(ret == KNOT_EOK, "zone_timers_read()");

	// Sweep all
	ret = zone_timers_sweep(db, remove_all, NULL);
	ok(ret == KNOT_EOK, "zone_timers_sweep() all");
	ret = zone_timers_read(db, zone, &timers);
	ok(ret == KNOT_ENOENT, "zone_timers_read() nonexistent");

	// Clean up.
	zone_timers_close(db);
	test_rm_rf(dbid);
	free(dbid);

	return EXIT_SUCCESS;
}
