/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <tap/basic.h>

#include "knot/updates/zone-update.h"
#include "zscanner/scanner.h"
#include "libknot/internal/getline.h"
#include "libknot/internal/macros.h"

#ifdef this_test_is_temporarily_disabled
static const char *zone_str =
"test. 3600 IN SOA a.ns.test. hostmaster.nic.cz. 1406641065 900 300 604800 900 \n"
"test. IN TXT \"test\"\n";

static const char *add_str =
"test. IN TXT \"test2\"\n";

static const char *del_str =
"test. IN TXT \"test\"\n";

static void process_rr(zs_scanner_t *scanner)
{
	// get zone to insert into
	zone_contents_t *zone = scanner->data;

	// create data
	knot_rrset_t *rr = knot_rrset_new(scanner->r_owner,
	                                  scanner->r_type,
	                                  scanner->r_class, NULL);
	assert(rr);

	int ret = knot_rrset_add_rdata(rr, scanner->r_data,
	                               scanner->r_data_length,
	                               scanner->r_ttl, NULL);
	assert(ret == KNOT_EOK);

	// add to zone
	zone_node_t *n = NULL;
	ret = zone_contents_add_rr(zone, rr, &n);
	knot_rrset_free(&rr, NULL);
	UNUSED(n);
	assert(ret == KNOT_EOK);
}

int main(int argc, char *argv[])
{

	plan_lazy();

	knot_dname_t *apex = knot_dname_from_str_alloc("test");
	assert(apex);
	zone_contents_t *zone = zone_contents_new(apex);
	knot_dname_free(&apex, NULL);
	assert(zone);
	zone_t z = { .contents = zone, .name = apex };

	int ret = KNOT_EOK;

	zone_update_t update;
	zone_update_init(&update, &z, UPDATE_INCREMENTAL);
	ok(update.zone == &z && changeset_empty(&update.change) && update.mm.alloc,
	   "zone update: init");

	// Fill zone
	zs_scanner_t *sc = zs_scanner_create("test.", KNOT_CLASS_IN, 3600, process_rr,
	                                     NULL, zone);
	assert(sc);
	ret = zs_scanner_parse(sc, zone_str, zone_str + strlen(zone_str), true);
	assert(ret == 0);

	// Check that old node is returned without changes
	ok(zone->apex == zone_update_get_node(&update, zone->apex->owner),
	   "zone update: no change");

	// Add RRs to add section
	sc->data = update.change.add;
	ret = zs_scanner_parse(sc, add_str, add_str + strlen(add_str), true);
	assert(ret == 0);

	// Check that apex TXT has two RRs now
	const zone_node_t *synth_node = zone_update_get_node(&update, zone->apex->owner);
	ok(synth_node && node_rdataset(synth_node, KNOT_RRTYPE_TXT)->rr_count == 2,
	   "zone update: add change");

	// Add RRs to remove section
	sc->data = update.change.remove;
	ret = zs_scanner_parse(sc, del_str, del_str + strlen(del_str), true);
	assert(ret == 0);

	// Check that apex TXT has one RR again
	synth_node = zone_update_get_node(&update, zone->apex->owner);
	ok(synth_node && node_rdataset(synth_node, KNOT_RRTYPE_TXT)->rr_count == 1,
	   "zone update: del change");

	zone_update_clear(&update);
	ok(update.zone == NULL && changeset_empty(&update.change), "zone update: cleanup");

	zs_scanner_free(sc);
	zone_contents_deep_free(&zone);

	return 0;
}
#endif

int main(int argc, char *argv[])
{
	plan(1);
	ok(1, "test disabled");
	return 0;
}
