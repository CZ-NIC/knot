/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <tap/files.h>

#include "test_conf.h"
#include "contrib/macros.h"
#include "contrib/getline.h"
#include "contrib/openbsd/strlcat.h"
#include "knot/updates/zone-update.h"
#include "knot/zone/node.h"
#include "zscanner/scanner.h"

static const char *zone_str1 = "test. 600 IN SOA ns.test. m.test. 1 900 300 4800 900 \n";
static const char *zone_str2 = "test. IN TXT \"test\"\n";
static const char *add_str   = "test. IN TXT \"test2\"\n";
static const char *del_str   = "test. IN TXT \"test\"\n";
static const char *node_str1 = "node.test. IN TXT \"abc\"\n";
static const char *node_str2 = "node.test. IN TXT \"def\"\n";

knot_rrset_t rrset;

/*!< \brief Returns true if node contains given RR in its RRSets. */
static bool node_contains_rr(const zone_node_t *node,
                             const knot_rrset_t *rr)
{
	const knot_rdataset_t *zone_rrs = node_rdataset(node, rr->type);
	if (zone_rrs) {
		for (size_t i = 0; i < rr->rrs.rr_count; ++i) {
			if (!knot_rdataset_member(zone_rrs, knot_rdataset_at(&rr->rrs, i), false)) {
				return false;
			}
		}

		return true;
	} else {
		return false;
	}
}

static void process_rr(zs_scanner_t *scanner)
{
	knot_rrset_init(&rrset, scanner->r_owner, scanner->r_type, scanner->r_class);

	int ret = knot_rrset_add_rdata(&rrset, scanner->r_data,
	                               scanner->r_data_length,
	                               scanner->r_ttl, NULL);
	assert(ret == KNOT_EOK);
}

void test_full(zone_t *zone, zs_scanner_t *sc)
{
	zone_update_t update;
	/* Init update */
	int ret = zone_update_init(&update, zone, UPDATE_FULL);
	ok(ret == KNOT_EOK, "zone update: init full");

	if (zs_set_input_string(sc, zone_str1, strlen(zone_str1)) != 0 ||
	    zs_parse_all(sc) != 0) {
		assert(0);
	}

	/* First addition */
	ret = zone_update_add(&update, &rrset);
	knot_rdataset_clear(&rrset.rrs, NULL);
	ok(ret == KNOT_EOK, "full zone update: first addition");

	if (zs_set_input_string(sc, zone_str2, strlen(zone_str2)) != 0 ||
	    zs_parse_all(sc) != 0) {
		assert(0);
	}

	/* Second addition */
	ret = zone_update_add(&update, &rrset);
	zone_node_t *node = (zone_node_t *) zone_update_get_node(&update, rrset.owner);
	bool rrset_present = node_contains_rr(node, &rrset);
	ok(ret == KNOT_EOK && rrset_present, "full zone update: second addition");

	/* Removal */
	ret = zone_update_remove(&update, &rrset);
	node = (zone_node_t *) zone_update_get_node(&update, rrset.owner);
	rrset_present = node_contains_rr(node, &rrset);
	ok(ret == KNOT_EOK && !rrset_present, "full zone update: removal");

	/* Last addition */
	ret = zone_update_add(&update, &rrset);
	node = (zone_node_t *) zone_update_get_node(&update, rrset.owner);
	rrset_present = node_contains_rr(node, &rrset);
	ok(ret == KNOT_EOK && rrset_present, "full zone update: last addition");

	knot_rdataset_clear(&rrset.rrs, NULL);

	/* Prepare node removal */
	if (zs_set_input_string(sc, node_str1, strlen(node_str1)) != 0 ||
	    zs_parse_all(sc) != 0) {
		assert(0);
	}
	ret = zone_update_add(&update, &rrset);
	assert(ret == KNOT_EOK);
	knot_rdataset_clear(&rrset.rrs, NULL);

	if (zs_set_input_string(sc, node_str2, strlen(node_str2)) != 0 ||
	    zs_parse_all(sc) != 0) {
		assert(0);
	}
	ret = zone_update_add(&update, &rrset);
	assert(ret == KNOT_EOK);
	knot_rdataset_clear(&rrset.rrs, NULL);
	knot_dname_t *rem_node_name = knot_dname_from_str_alloc("node.test");
	node = (zone_node_t *) zone_update_get_node(&update, rem_node_name);
	assert(node && node_rdataset(node, KNOT_RRTYPE_TXT)->rr_count == 2);
	/* Node removal */
	ret = zone_update_remove_node(&update, rem_node_name);
	node = (zone_node_t *) zone_update_get_node(&update, rem_node_name);
	ok(ret == KNOT_EOK && !node, "full zone update: node removal");
	knot_dname_free(&rem_node_name, NULL);

	/* Test iteration */
	zone_update_iter_t it;
	ret = zone_update_iter(&it, &update);
	ok(ret == KNOT_EOK, "full zone update: init iter");

	const zone_node_t *iter_node = zone_update_iter_val(&it);
	assert(iter_node);
	if (zs_set_input_string(sc, zone_str1, strlen(zone_str1)) != 0 ||
	    zs_parse_all(sc) != 0) {
		assert(0);
	}
	rrset_present = node_contains_rr(iter_node, &rrset);
	ok(rrset_present, "full zone update: first iter value check");
	knot_rdataset_clear(&rrset.rrs, NULL);

	if (zs_set_input_string(sc, zone_str2, strlen(zone_str2)) != 0 ||
	    zs_parse_all(sc) != 0) {
		assert(0);
	}
	rrset_present = node_contains_rr(iter_node, &rrset);
	ok(rrset_present, "full zone update: second iter value check");
	knot_rdataset_clear(&rrset.rrs, NULL);

	ret = zone_update_iter_next(&it);
	ok(ret == KNOT_EOK, "full zone update: iter next");

	iter_node = zone_update_iter_val(&it);
	ok(iter_node == NULL, "full zone update: iter val past end");

	zone_update_iter_finish(&it);

	/* Re-add a node for later incremental functionality test */
	if (zs_set_input_string(sc, node_str1, strlen(node_str1)) != 0 ||
	    zs_parse_all(sc) != 0) {
		assert(0);
	}
	ret = zone_update_add(&update, &rrset);
	assert(ret == KNOT_EOK);
	knot_rdataset_clear(&rrset.rrs, NULL);

	/* Commit */
	ret = zone_update_commit(conf(), &update);
	node = zone_contents_find_node_for_rr(zone->contents, &rrset);
	rrset_present = node_contains_rr(node, &rrset);
	ok(ret == KNOT_EOK && rrset_present, "full zone update: commit");

	knot_rdataset_clear(&rrset.rrs, NULL);
}

void test_incremental(zone_t *zone, zs_scanner_t *sc)
{
	int ret = KNOT_EOK;

	/* Init update */
	zone_update_t update;
	zone_update_init(&update, zone, UPDATE_INCREMENTAL);
	ok(update.zone == zone && changeset_empty(&update.change) && update.mm.alloc,
	   "incremental zone update: init");

	ok(zone->contents->apex == zone_update_get_apex(&update) &&
	   zone_update_no_change(&update),
	   "incremental zone update: no change");

	if (zs_set_input_string(sc, add_str, strlen(add_str)) != 0 ||
	    zs_parse_all(sc) != 0) {
		assert(0);
	}

	/* Addition */
	ret = zone_update_add(&update, &rrset);
	knot_rdataset_clear(&rrset.rrs, NULL);
	ok(ret == KNOT_EOK, "incremental zone update: addition");

	const zone_node_t *synth_node = zone_update_get_apex(&update);
	ok(synth_node && node_rdataset(synth_node, KNOT_RRTYPE_TXT)->rr_count == 2,
	   "incremental zone update: add change");

	if (zs_set_input_string(sc, del_str, strlen(del_str)) != 0 ||
	    zs_parse_all(sc) != 0) {
		assert(0);
	}
	/* Removal */
	ret = zone_update_remove(&update, &rrset);
	ok(ret == KNOT_EOK, "incremental zone update: removal");
	knot_rdataset_clear(&rrset.rrs, NULL);

	synth_node = zone_update_get_apex(&update);
	ok(synth_node && node_rdataset(synth_node, KNOT_RRTYPE_TXT)->rr_count == 1,
	   "incremental zone update: del change");

	/* Prepare node removal */
	if (zs_set_input_string(sc, node_str2, strlen(node_str2)) != 0 ||
	    zs_parse_all(sc) != 0) {
		assert(0);
	}
	ret = zone_update_add(&update, &rrset);
	assert(ret == KNOT_EOK);
	knot_rdataset_clear(&rrset.rrs, NULL);

	knot_dname_t *rem_node_name = knot_dname_from_str_alloc("node.test");
	synth_node = zone_update_get_node(&update, rem_node_name);
	assert(synth_node && node_rdataset(synth_node, KNOT_RRTYPE_TXT)->rr_count == 2);
	/* Node Removal */
	ret = zone_update_remove_node(&update, rem_node_name);
	synth_node = zone_update_get_node(&update, rem_node_name);
	ok(ret == KNOT_EOK && synth_node && node_empty(synth_node),
	   "incremental zone update: node removal");
	knot_dname_free(&rem_node_name, NULL);

	/* Test iteration */
	zone_update_iter_t it;
	ret = zone_update_iter(&it, &update);
	ok(ret == KNOT_EOK, "incremental zone update: init iter");

	if (zs_set_input_string(sc, del_str, strlen(del_str)) != 0 ||
	    zs_parse_all(sc) != 0) {
		assert(0);
	}
	const zone_node_t *iter_node = zone_update_iter_val(&it);
	assert(iter_node);

	bool rrset_present = node_contains_rr(iter_node, &rrset);
	ok(!rrset_present, "incremental zone update: first iter value check");

	knot_rdataset_clear(&rrset.rrs, NULL);

	if (zs_set_input_string(sc, add_str, strlen(add_str)) != 0 ||
	    zs_parse_all(sc) != 0) {
		assert(0);
	}
	rrset_present = node_contains_rr(iter_node, &rrset);
	ok(rrset_present, "incremental zone update: second iter value check");
	knot_rdataset_clear(&rrset.rrs, NULL);

	ret = zone_update_iter_next(&it);
	ok(ret == KNOT_EOK, "incremental zone update: iter next");
	ret = zone_update_iter_next(&it);
	ok(ret == KNOT_EOK, "incremental zone update: iter next");

	iter_node = zone_update_iter_val(&it);
	ok(iter_node == NULL, "incremental zone update: iter val past end");

	zone_update_iter_finish(&it);

	/* Commit */
	ret = zone_update_commit(conf(), &update);
	iter_node = zone_contents_find_node_for_rr(zone->contents, &rrset);
	rrset_present = node_contains_rr(iter_node, &rrset);
	ok(ret == KNOT_EOK && rrset_present, "incremental zone update: commit");

	knot_rdataset_clear(&rrset.rrs, NULL);
}

int main(int argc, char *argv[])
{
	plan_lazy();

	char *temp_dir = test_mkdtemp();
	ok(temp_dir != NULL, "make temporary directory");

	char conf_str[256] = "zone:\n - domain: test.\n   storage: ";
	strlcat(conf_str, temp_dir, 256);
	strlcat(conf_str, "\n", 256);

	/* Load test configuration. */
	int ret = test_conf(conf_str, NULL);
	assert(ret == KNOT_EOK);

	/* Set up empty zone */
	knot_dname_t *apex = knot_dname_from_str_alloc("test");
	assert(apex);
	zone_t *zone = zone_new(apex);

	/* Setup zscanner */
	zs_scanner_t sc;
	if (zs_init(&sc, "test.", KNOT_CLASS_IN, 3600) != 0 ||
	    zs_set_processing(&sc, process_rr, NULL, NULL) != 0) {
		assert(0);
	}

	/* Test FULL update, commit it and use the result to test the INCREMENTAL update */
	test_full(zone, &sc);
	test_incremental(zone, &sc);

	zs_deinit(&sc);
	zone_free(&zone);
	knot_dname_free(&apex, NULL);
	conf_free(conf());
	test_rm_rf(temp_dir);
	free(temp_dir);

	return 0;
}
