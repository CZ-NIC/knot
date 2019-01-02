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

#include <assert.h>
#include <stdlib.h>
#include <string.h>
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
	.last_flush = 1,
	.last_resalt = 2,
	.next_parent_ds_q = 0,
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
	knot_lmdb_db_t _db = { 0 }, *db = &_db;
	knot_lmdb_init(db, dbid, 1024 * 1024, 0, NULL);
	int ret = knot_lmdb_open(db);
	ok(ret == KNOT_EOK && db != NULL, "open timers");

	// Lookup nonexistent
	ret = zone_timers_read(db, zone, &timers);
	is_int(KNOT_ENOENT, ret, "zone_timer_read() nonexistent");

	// Write timers
	ret = zone_timers_write(db, zone, &timers);
	is_int(KNOT_EOK, ret, "zone_timers_write()");

	// Read timers
	memset(&timers, 0, sizeof(timers));
	ret = zone_timers_read(db, zone, &timers);
	ok(ret == KNOT_EOK, "zone_timers_read()");
	ok(timers_eq(&timers, &MOCK_TIMERS), "timers unmalformed (%u == %u, %ld == %ld etc.)",
	   timers.soa_expire, MOCK_TIMERS.soa_expire, timers.last_refresh, MOCK_TIMERS.last_refresh);

	// Sweep none
	ret = zone_timers_sweep(db, keep_all, NULL);
	is_int(KNOT_EOK, ret, "zone_timers_sweep() none");
	ret = zone_timers_read(db, zone, &timers);
	is_int(KNOT_EOK, ret, "zone_timers_read()");

	// Sweep all
	ret = zone_timers_sweep(db, remove_all, NULL);
	is_int(KNOT_EOK, ret, "zone_timers_sweep() all");
	ret = zone_timers_read(db, zone, &timers);
	is_int(KNOT_ENOENT, ret, "zone_timers_read() nonexistent");

	// Clean up.
	knot_lmdb_deinit(db);
	test_rm_rf(dbid);
	free(dbid);

	return EXIT_SUCCESS;
}
