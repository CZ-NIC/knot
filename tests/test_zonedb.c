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

#include <tap/basic.h>

#include "knot/zone/zone.h"
#include "knot/zone/zonedb.h"
#include "contrib/openbsd/strlcat.h"
#include "contrib/openbsd/strlcpy.h"

#define ZONE_COUNT 10
static const char *zone_list[ZONE_COUNT] = {
        ".",
        "com",
        "net",
        "c.com",
        "a.com",
        "a.net",
        "b.net",
        "c.a.com",
        "b.b.b.com",
        "b.b.b.b.net",
};

int main(int argc, char *argv[])
{
	plan_lazy();

	/* Create database. */
	char buf[KNOT_DNAME_MAXLEN];
	const char *prefix = "zzz.";
	size_t nr_passed = 0;
	knot_dname_t *dname = NULL;
	zone_t *zones[ZONE_COUNT] = {0};
	knot_zonedb_t *db = knot_zonedb_new();
	ok(db != NULL, "zonedb: new");

	/* Populate. */
	for (unsigned i = 0; i < ZONE_COUNT; ++i) {
		knot_dname_t *zone_name = knot_dname_from_str_alloc(zone_list[i]);
		zones[i] = zone_new(zone_name);
		knot_dname_free(&zone_name, NULL);

		if (zones[i] == NULL) {
			goto cleanup;
		}
		if (knot_zonedb_insert(db, zones[i]) == KNOT_EOK) {
			++nr_passed;
		} else {
			diag("knot_zonedb_add_zone(%s) failed", zone_list[i]);
		}
	}
	ok(nr_passed == ZONE_COUNT, "zonedb: add zones");

	/* Lookup of exact names. */
	nr_passed = 0;
	for (unsigned i = 0; i < ZONE_COUNT; ++i) {
		dname = knot_dname_from_str_alloc(zone_list[i]);
		if (knot_zonedb_find(db, dname) == zones[i]) {
			++nr_passed;
		} else {
			diag("knot_zonedb_find(%s) failed", zone_list[i]);
		}
		knot_dname_free(&dname, NULL);
	}
	ok(nr_passed == ZONE_COUNT, "zonedb: find exact zones");

	/* Lookup of sub-names. */
	nr_passed = 0;
	for (unsigned i = 0; i < ZONE_COUNT; ++i) {
		strlcpy(buf, prefix, sizeof(buf));
		if (strcmp(zone_list[i], ".") != 0) {
			strlcat(buf, zone_list[i], sizeof(buf));
		}
		dname = knot_dname_from_str_alloc(buf);
		if (knot_zonedb_find_suffix(db, dname) == zones[i]) {
			++nr_passed;
		} else {
			diag("knot_zonedb_find_suffix(%s) failed", buf);
		}
		knot_dname_free(&dname, NULL);
	}
	ok(nr_passed == ZONE_COUNT, "zonedb: find zones for subnames");

	/* Remove all zones. */
	nr_passed = 0;
	for (unsigned i = 0; i < ZONE_COUNT; ++i) {
		dname = knot_dname_from_str_alloc(zone_list[i]);
		if (knot_zonedb_del(db, dname) == KNOT_EOK) {
			zone_free(&zones[i]);
			++nr_passed;
		} else {
			diag("knot_zonedb_remove_zone(%s) failed", zone_list[i]);
		}
		knot_dname_free(&dname, NULL);
	}
	ok(nr_passed == ZONE_COUNT, "zonedb: removed all zones");

cleanup:
	knot_zonedb_deep_free(&db);
	return 0;
}
