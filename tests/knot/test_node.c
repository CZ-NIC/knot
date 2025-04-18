/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <assert.h>
#include <tap/basic.h>

#include "knot/zone/node.h"
#include "libknot/libknot.h"

static knot_rrset_t *create_dummy_rrset(const knot_dname_t *owner, uint16_t type)
{
	knot_rrset_t *r = knot_rrset_new(owner, type, KNOT_CLASS_IN, 3600, NULL);
	assert(r);
	uint8_t wire[16] = { 0 };
	memcpy(wire, "testtest", strlen("testtest"));
	int ret = knot_rrset_add_rdata(r, wire, strlen("testtest"), NULL);
	assert(ret == KNOT_EOK);
	(void)ret;
	return r;
}

static knot_rrset_t *create_dummy_rrsig(const knot_dname_t *owner, uint16_t type)
{
	knot_rrset_t *r = knot_rrset_new(owner, KNOT_RRTYPE_RRSIG, KNOT_CLASS_IN,
	                                 3600, NULL);
	assert(r);
	uint8_t wire[sizeof(uint16_t)];
	knot_wire_write_u16(wire, type);
	int ret = knot_rrset_add_rdata(r, wire, sizeof(uint16_t), NULL);
	assert(ret == KNOT_EOK);
	(void)ret;
	return r;
}

int main(int argc, char *argv[])
{
	plan_lazy();

	knot_dname_t *dummy_owner = knot_dname_from_str_alloc("test.");
	// Test new
	zone_node_t *node = node_new(dummy_owner, false, false, NULL);
	ok(node != NULL, "Node: new");
	assert(node);
	ok(knot_dname_is_equal(node->owner, dummy_owner), "Node: new - set fields");

	// Test RRSet addition
	knot_rrset_t *dummy_rrset = create_dummy_rrset(dummy_owner, KNOT_RRTYPE_TXT);
	int ret = node_add_rrset(node, dummy_rrset, NULL);
	ok(ret == KNOT_EOK && node->rrset_count == 1 &&
	   knot_rdataset_eq(&dummy_rrset->rrs, &node->rrs[0].rrs), "Node: add RRSet.");

	// Test RRSet getters
	knot_rrset_t *n_rrset = node_create_rrset(node, KNOT_RRTYPE_TXT);
	ok(n_rrset && knot_rrset_equal(n_rrset, dummy_rrset, true),
	   "Node: create existing RRSet.");

	knot_rrset_free(n_rrset, NULL);

	n_rrset = node_create_rrset(node, KNOT_RRTYPE_SOA);
	ok(n_rrset == NULL, "Node: create non-existing RRSet.");

	knot_rrset_t stack_rrset = node_rrset(node, KNOT_RRTYPE_TXT);
	ok(knot_rrset_equal(&stack_rrset, dummy_rrset, true), "Node: get existing RRSet.");
	stack_rrset = node_rrset(node, KNOT_RRTYPE_SOA);
	ok(knot_rrset_empty(&stack_rrset), "Node: get non-existent RRSet.");

	knot_rdataset_t *n_rdataset = node_rdataset(node, KNOT_RRTYPE_TXT);
	ok(n_rdataset && knot_rdataset_eq(n_rdataset, &dummy_rrset->rrs),
	   "Node: get existing rdataset.");
	n_rdataset = node_rdataset(node, KNOT_RRTYPE_SOA);
	ok(n_rdataset == NULL, "Node: get non-existing rdataset.");

	stack_rrset = node_rrset_at(node, 0);
	ok(knot_rrset_equal(&stack_rrset, dummy_rrset, true),
	   "Node: get existing position.");
	stack_rrset = node_rrset_at(node, 1);
	ok(knot_rrset_empty(&stack_rrset), "Node: get non-existent position.");

	// Test TTL mismatch
	dummy_rrset->ttl = 1800;
	ret = node_add_rrset(node, dummy_rrset, NULL);
	ok(ret == KNOT_ETTL && node->rrset_count == 1,
	   "Node: add RRSet, TTL mismatch.");

	knot_rrset_free(dummy_rrset, NULL);

	// Test bool functions
	ok(node_rrtype_exists(node, KNOT_RRTYPE_TXT), "Node: type exists.");
	ok(!node_rrtype_exists(node, KNOT_RRTYPE_AAAA), "Node: type does not exist.");
	ok(!node_rrtype_is_signed(node, KNOT_RRTYPE_TXT), "Node: type is not signed.");

	dummy_rrset = create_dummy_rrsig(dummy_owner, KNOT_RRTYPE_TXT);
	ret = node_add_rrset(node, dummy_rrset, NULL);
	assert(ret == KNOT_EOK);

	ok(node_rrtype_is_signed(node, KNOT_RRTYPE_TXT), "Node: type is signed.");

	knot_rrset_free(dummy_rrset, NULL);

	// Test remove RRset
	node_remove_rdataset(node, KNOT_RRTYPE_AAAA);
	ok(node->rrset_count == 2, "Node: remove non-existent rdataset.");
	node_remove_rdataset(node, KNOT_RRTYPE_TXT);
	ok(node->rrset_count == 1, "Node: remove existing rdataset.");

	// "Test" freeing
	node_free_rrsets(node, NULL);
	ok(node->rrset_count == 0, "Node: free RRSets.");

	node_free(node, NULL);

	knot_dname_free(dummy_owner, NULL);

	return 0;
}
