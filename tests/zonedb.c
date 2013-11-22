/*  Copyright (C) 2013 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <config.h>
#include <tap/basic.h>

#include "libknot/zone/zonedb.h"
#include "libknot/zone/zone.h"

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
	plan(6);
	
	/* Create database. */
	char buf[KNOT_DNAME_MAX_LENGTH];
	const char *prefix = "zzz.";
	size_t nr_passed = 0;
	knot_dname_t *dname = NULL;
	knot_zone_t *zone = NULL;
	knot_zone_t *zones[ZONE_COUNT] = {0};
	knot_zonedb_t *db = knot_zonedb_new(ZONE_COUNT);
	ok(db != NULL, "zonedb: new");
	
	/* Populate. */
	for (unsigned i = 0; i < ZONE_COUNT; ++i) {
		dname = knot_dname_from_str(zone_list[i]);
		zones[i] = knot_zone_new_empty(dname);
		if (zones[i] == NULL) {
			knot_dname_free(&dname);
			goto cleanup;
		}
		if (knot_zonedb_add_zone(db, zones[i]) == KNOT_EOK) {
			++nr_passed;
		} else {
			diag("knot_zonedb_add_zone(%s) failed", zone_list[i]);
		}
	}
	ok(nr_passed == ZONE_COUNT, "zonedb: add zones");
	
	/* Build search index. */
	ok(knot_zonedb_build_index(db) == KNOT_EOK, "zonedb: build search index");
	
	/* Lookup of exact names. */
	nr_passed = 0;
	for (unsigned i = 0; i < ZONE_COUNT; ++i) {
		dname = knot_dname_from_str(zone_list[i]);
		if (knot_zonedb_find_zone(db, dname) == zones[i]) {
			++nr_passed;
		} else {
			diag("knot_zonedb_find_zone(%s) failed", zone_list[i]);
		}
		knot_dname_free(&dname);
	}
	ok(nr_passed == ZONE_COUNT, "zonedb: find exact zones");
	
	/* Lookup of sub-names. */
	nr_passed = 0;
	for (unsigned i = 0; i < ZONE_COUNT; ++i) {
		strcpy(buf, prefix);
		if (strcmp(zone_list[i], ".") != 0) {
			strncat(buf, zone_list[i], strlen(zone_list[i]));
		}
		dname = knot_dname_from_str(buf);
		if (knot_zonedb_find_zone_for_name(db, dname) == zones[i]) {
			++nr_passed;
		} else {
			diag("knot_zonedb_find_zone(%s) failed", buf);
		}
		knot_dname_free(&dname);
	}
	ok(nr_passed == ZONE_COUNT, "zonedb: find zones for subnames");
	
	/* Remove all zones. */
	nr_passed = 0;
	for (unsigned i = 0; i < ZONE_COUNT; ++i) {
		dname = knot_dname_from_str(zone_list[i]);
		zone = knot_zonedb_remove_zone(db, dname);
		if (zone == zones[i]) {
			knot_zone_free(&zone);
			++nr_passed;
		} else {
			diag("knot_zonedb_remove_zone(%s) failed", zone_list[i]);
		}
	}
	ok(nr_passed == ZONE_COUNT, "zonedb: removed all zones");
	
cleanup:
	knot_zonedb_deep_free(&db);
	return 0;
}
