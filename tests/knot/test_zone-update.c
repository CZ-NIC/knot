/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <assert.h>
#include <pthread.h>
#include <tap/basic.h>
#include <tap/files.h>
#include <unistd.h>

#include "test_conf.h"
#include "contrib/getline.h"
#include "knot/server/server.h"
#include "knot/updates/zone-update.h"
#include "knot/zone/adjust.h"
#include "knot/zone/node.h"
#include "libzscanner/scanner.h"

static const char *zone_str1 = "test. 600 IN SOA ns.test. m.test. 1 900 300 4800 900 \n";
static const char *zone_str2 = "test. 600 IN TXT \"test\"\n";
static const char *add_str   = "test. 600 IN TXT \"test2\"\n";
static const char *del_str   = "test. 600 IN TXT \"test\"\n";
static const char *node_str1 = "node.test. 601 IN TXT \"abc\"\n";
static const char *node_str2 = "node.test. 601 IN TXT \"def\"\n";

knot_rrset_t rrset;

/*!< \brief Returns true if node contains given RR in its RRSets. */
static bool node_contains_rr(const zone_node_t *node, const knot_rrset_t *data)
{
	const knot_rdataset_t *zone_rrs = node_rdataset(node, data->type);
	if (zone_rrs != NULL) {
		knot_rdata_t *rr = data->rrs.rdata;
		for (size_t i = 0; i < data->rrs.count; ++i) {
			if (!knot_rdataset_member(zone_rrs, rr)) {
				return false;
			}
			rr = knot_rdataset_next(rr);
		}

		return true;
	} else {
		return false;
	}
}

static void process_rr(zs_scanner_t *scanner)
{
	knot_rrset_init(&rrset, scanner->r_owner, scanner->r_type, scanner->r_class,
	                scanner->r_ttl);

	int ret = knot_rrset_add_rdata(&rrset, scanner->r_data,
	                               scanner->r_data_length, NULL);
	(void)ret;
	assert(ret == KNOT_EOK);
}

static int rr_data_cmp(struct rr_data *a, struct rr_data *b)
{
	if (a->type != b->type) {
		return 1;
	}
	if (a->ttl != b->ttl) {
		return 1;
	}
	if (a->rrs.count != b->rrs.count) {
		return 1;
	}
	if (a->rrs.rdata != b->rrs.rdata) {
		return 1;
	}
	if (a->additional != b->additional) {
		return 1;
	}
	return 0;
}

static int test_node_unified(zone_node_t *n1, _unused_ void *v)
{
	zone_node_t *n2 = binode_node(n1, false);
	if (n2 == n1) {
		n2 = binode_node(n1, true);
	}
	ok(n1->owner == n2->owner, "binode %s has equal %s owner", n1->owner, n2->owner);
	ok(n1->rrset_count == n2->rrset_count, "binode %s has equal rrset_count", n1->owner);
	for (uint16_t i = 0; i < n1->rrset_count; i++) {
		ok(rr_data_cmp(&n1->rrs[i], &n2->rrs[i]) == 0, "binode %s has equal rrs", n1->owner);
	}
	if (n1->flags & NODE_FLAGS_BINODE) {
		ok((n1->flags ^ n2->flags) == NODE_FLAGS_SECOND, "binode %s has correct flags", n1->owner);
	}
	ok(n1->children == n2->children, "binode %s has equal children count", n1->owner);
	return KNOT_EOK;
}

static void test_zone_unified(zone_t *z)
{
	knot_sem_wait(&z->cow_lock);
	zone_tree_apply(z->contents->nodes, test_node_unified, NULL);
	knot_sem_post(&z->cow_lock);
}

void test_full(zone_t *zone, zs_scanner_t *sc)
{
	zone_update_t update;
	/* Init update */
	int ret = zone_update_init(&update, zone, UPDATE_FULL);
	is_int(KNOT_EOK, ret, "zone update: init full");

	if (zs_set_input_string(sc, zone_str1, strlen(zone_str1)) != 0 ||
	    zs_parse_all(sc) != 0) {
		assert(0);
	}

	/* First addition */
	ret = zone_update_add(&update, &rrset);
	knot_rdataset_clear(&rrset.rrs, NULL);
	is_int(KNOT_EOK, ret, "full zone update: first addition");

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
	assert(node && node_rdataset(node, KNOT_RRTYPE_TXT)->count == 2);
	/* Node removal */
	ret = zone_update_remove_node(&update, rem_node_name);
	node = (zone_node_t *) zone_update_get_node(&update, rem_node_name);
	ok(ret == KNOT_EOK && !node, "full zone update: node removal");
	knot_dname_free(rem_node_name, NULL);

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
	ok(ret == KNOT_EOK && rrset_present, "full zone update: commit (max TTL: %u)", zone->contents->max_ttl);

	test_zone_unified(zone);

	knot_rdataset_clear(&rrset.rrs, NULL);
}

void test_incremental(zone_t *zone, zs_scanner_t *sc)
{
	int ret = KNOT_EOK;

	/* Init update */
	zone_update_t update;
	zone_update_init(&update, zone, UPDATE_INCREMENTAL);
	ok(update.zone == zone && changeset_empty(&update.change),
	   "incremental zone update: init");

	if (zs_set_input_string(sc, add_str, strlen(add_str)) != 0 ||
	    zs_parse_all(sc) != 0) {
		assert(0);
	}

	/* Addition */
	ret = zone_update_add(&update, &rrset);
	knot_rdataset_clear(&rrset.rrs, NULL);
	is_int(KNOT_EOK, ret, "incremental zone update: addition");

	const zone_node_t *synth_node = update.new_cont->apex;
	ok(synth_node && node_rdataset(synth_node, KNOT_RRTYPE_TXT)->count == 2,
	   "incremental zone update: add change");

	if (zs_set_input_string(sc, del_str, strlen(del_str)) != 0 ||
	    zs_parse_all(sc) != 0) {
		assert(0);
	}
	/* Removal */
	ret = zone_update_remove(&update, &rrset);
	is_int(KNOT_EOK, ret, "incremental zone update: removal");
	knot_rdataset_clear(&rrset.rrs, NULL);

	ok(node_rdataset(synth_node, KNOT_RRTYPE_TXT)->count == 1,
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
	assert(synth_node && node_rdataset(synth_node, KNOT_RRTYPE_TXT)->count == 2);
	/* Node Removal */
	ret = zone_update_remove_node(&update, rem_node_name);
	synth_node = zone_update_get_node(&update, rem_node_name);
	ok(ret == KNOT_EOK && !synth_node,
	   "incremental zone update: node removal");
	knot_dname_free(rem_node_name, NULL);

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
	const zone_node_t *iter_node = zone_contents_find_node_for_rr(zone->contents, &rrset);
	bool rrset_present = node_contains_rr(iter_node, &rrset);
	ok(ret == KNOT_EOK && rrset_present, "incremental zone update: commit");

	test_zone_unified(zone);

	knot_rdataset_clear(&rrset.rrs, NULL);

	size_t zone_size1 = zone->contents->size;
	uint32_t zone_max_ttl1 = zone->contents->max_ttl;
	ret = zone_adjust_full(zone->contents, 2);
	ok(ret == KNOT_EOK, "zone adjust full shall work");
	size_t zone_size2 = zone->contents->size;
	uint32_t zone_max_ttl2 = zone->contents->max_ttl;
	ok(zone_size1 == zone_size2, "zone size measured the same incremental vs full (%zu, %zu)", zone_size1, zone_size2);
	ok(zone_max_ttl1 == zone_max_ttl2, "zone max TTL measured the same incremental vs full (%u, %u)", zone_max_ttl1, zone_max_ttl2);
	// TODO test more things after re-adjust, search for non-unified bi-nodes
}

int main(int argc, char *argv[])
{
	plan_lazy();

	char *temp_dir = test_mkdtemp();
	ok(temp_dir != NULL, "make temporary directory");

	char conf_str[512];
	snprintf(conf_str, sizeof(conf_str),
	         "zone:\n"
	         " - domain: test.\n"
	         "database:\n"
	         "   journal-db-max-size: 100M\n"
	         "   storage: %s\n",
	         temp_dir);

	/* Load test configuration. */
	int ret = test_conf(conf_str, NULL);
	is_int(KNOT_EOK, ret, "load configuration");

	server_t server;
	ret = server_init(&server, 1);
	is_int(KNOT_EOK, ret, "server init");

	/* Set up empty zone */
	knot_dname_t *apex = knot_dname_from_str_alloc("test");
	assert(apex);
	zone_t *zone = zone_new(apex);
	zone->server = &server;

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
	server_deinit(&server);
	knot_dname_free(apex, NULL);
	conf_free(conf());
	test_rm_rf(temp_dir);
	free(temp_dir);

	return 0;
}
