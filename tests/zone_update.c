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

#include "contrib/macros.h"
#include "contrib/getline.h"
#include "knot/updates/zone-update.h"
#include "zscanner/scanner.h"

static const char *zone_str =
"test. 3600 IN SOA a.ns.test. hostmaster.nic.cz. 1406641065 900 300 604800 900 \n"
"test. IN TXT \"test\"\n";

static const char *add_str =
"test. IN TXT \"test2\"\n";

static const char *del_str =
"test. IN TXT \"test\"\n";

bool to_zone;
knot_rrset_t rrset;

static void process_rr(zs_scanner_t *scanner)
{
	// get zone to insert into
	zone_contents_t *zc = scanner->data;

	// create data
	knot_rrset_init(&rrset, scanner->r_owner, scanner->r_type, scanner->r_class);

	int ret = knot_rrset_add_rdata(&rrset, scanner->r_data,
	                               scanner->r_data_length,
	                               scanner->r_ttl, NULL);
	assert(ret == KNOT_EOK);

	if (to_zone) {
		// Add initial node to zone
		zone_node_t *n = NULL;
		ret = zone_contents_add_rr(zc, &rrset, &n);
		UNUSED(n);
		knot_rdataset_clear(&rrset.rrs, NULL);
		assert(ret == KNOT_EOK);
	}
}

int main(int argc, char *argv[])
{

	plan_lazy();

	int ret = KNOT_EOK;
	to_zone = true;

	knot_dname_t *apex = knot_dname_from_str_alloc("test");
	assert(apex);
	zone_contents_t *zc = zone_contents_new(apex);
	assert(zc);
	zone_t zone = { .contents = zc, .name = apex };

	// Parse initial node
	zs_scanner_t *sc = zs_scanner_create("test.", KNOT_CLASS_IN, 3600,
	                                     process_rr, NULL, zc);
	assert(sc);
	ret = zs_scanner_parse(sc, zone_str, zone_str + strlen(zone_str), true);
	assert(ret == 0);

	// Initial node added, now just parse the RRs
	to_zone = false;

	zone_update_t update;
	zone_update_init(&update, &zone, UPDATE_INCREMENTAL);
	ok(update.zone == &zone && changeset_empty(&update.change) && update.mm.alloc,
	   "incremental zone update: init");

	// Check that old node is returned without changes
	ok(zc->apex == zone_update_get_node(&update, zc->apex->owner) &&
	   zone_update_no_change(&update),
	   "incremental zone update: no change");

	// Parse RR for addition and add it
	ret = zs_scanner_parse(sc, add_str, add_str + strlen(add_str), true);
	assert(ret == 0);
	ret = zone_update_add(&update, &rrset);
	knot_rdataset_clear(&rrset.rrs, NULL);
	ok(ret == KNOT_EOK, "incremental zone update: addition");

	// Check that apex TXT has two RRs now
	const zone_node_t *synth_node = zone_update_get_node(&update, zc->apex->owner);
	ok(synth_node && node_rdataset(synth_node, KNOT_RRTYPE_TXT)->rr_count == 2,
	   "incremental zone update: add change");

	// Parse RR for removal and remove it
	ret = zs_scanner_parse(sc, del_str, del_str + strlen(del_str), true);
	assert(ret == 0);
	ret = zone_update_remove(&update, &rrset);
	knot_rdataset_clear(&rrset.rrs, NULL);
	ok(ret == KNOT_EOK, "incremental zone update: removal");

	// Check that apex TXT has one RR again
	synth_node = zone_update_get_node(&update, zc->apex->owner);
	ok(synth_node && node_rdataset(synth_node, KNOT_RRTYPE_TXT)->rr_count == 1,
	   "incremental zone update: del change");

	zone_update_clear(&update);
	ok(update.zone == NULL && changeset_empty(&update.change), "incremental zone update: cleanup");

	zs_scanner_free(sc);
	zone_contents_deep_free(&zc);
	knot_dname_free(&apex, NULL);

	return 0;
}
