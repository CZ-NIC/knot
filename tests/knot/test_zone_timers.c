/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
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
	.flags = LAST_SIGNED_SERIAL_FOUND | LAST_SIGNED_SERIAL_VALID | TIMERS_MODIFIED,
	.last_flush     = 1474559960,
	.next_refresh   = 1474559961,
	.last_notified_serial = 123456,
	.next_ds_check  = 1474559962,
	.next_ds_push   = 1474559963,
	.catalog_member = 1474559964,
	.next_expire    = 1474559965,
	.last_master    = { .sin6_family = AF_INET, .sin6_port = 53 },
	.master_pin_hit = 1474559966,
	.last_signed_serial = 12354678,
};

static bool timers_eq(const zone_timers_t *val, const zone_timers_t *ref)
{
	return	val->last_flush == ref->last_flush &&
		val->flags == ref->flags &&
		val->next_refresh == ref->next_refresh &&
		(val->last_notified_serial == ref->last_notified_serial || !(val->flags & LAST_NOTIFIED_SERIAL_VALID)) &&
		val->next_ds_check == ref->next_ds_check &&
		val->next_ds_push == ref->next_ds_push &&
		val->catalog_member == ref->catalog_member &&
		val->next_expire == ref->next_expire &&
		sockaddr_cmp((struct sockaddr_storage *)&val->last_master,
		             (struct sockaddr_storage *)&ref->last_master, false) == 0 &&
		val->master_pin_hit == ref->master_pin_hit &&
		(val->last_signed_serial == ref->last_signed_serial || !(val->flags & LAST_SIGNED_SERIAL_VALID));
}

static bool keep_all(const knot_dname_t *zone, void *data)
{
	return true;
}

static bool remove_all(const knot_dname_t *zone, void *data)
{
	return false;
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
	struct zone_timers timers = MOCK_TIMERS, timers2 = { 0 };

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
	ret = zone_timers_read(db, zone, &timers2);
	ok(ret == KNOT_EOK, "zone_timers_read()");
	ok(timers_eq(&timers2, &timers), "inconsistent timers");

	// Sweep none
	ret = zone_timers_sweep(db, keep_all, NULL);
	is_int(KNOT_EOK, ret, "zone_timers_sweep() none");
	ret = zone_timers_read(db, zone, &timers2);
	is_int(KNOT_EOK, ret, "zone_timers_read()");

	// Sweep all
	ret = zone_timers_sweep(db, remove_all, NULL);
	is_int(KNOT_EOK, ret, "zone_timers_sweep() all");
	ret = zone_timers_read(db, zone, &timers2);
	is_int(KNOT_ENOENT, ret, "zone_timers_read() nonexistent");

	// Clean up.
	knot_lmdb_deinit(db);
	test_rm_rf(dbid);
	free(dbid);

	return EXIT_SUCCESS;
}
