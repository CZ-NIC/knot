/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
	zone_node_t *node = node_new(dummy_owner, NULL);
	ok(node != NULL, "Node: new");
	assert(node);
	ok(knot_dname_is_equal(node->owner, dummy_owner), "Node: new - set fields");

	// Test parent setting
	zone_node_t *parent = node_new(dummy_owner, NULL);
	assert(parent);
	node_set_parent(node, parent);
	ok(node->parent == parent && parent->children == 1, "Node: set parent.");

	node_free(&parent, NULL);

	// Test RRSet addition
	knot_rrset_t *dummy_rrset = create_dummy_rrset(dummy_owner, KNOT_RRTYPE_TXT);
	int ret = node_add_rrset(node, dummy_rrset, NULL);
	ok(ret == KNOT_EOK && node->rrset_count == 1 &&
	   knot_rdataset_eq(&dummy_rrset->rrs, &node->rrs[0].rrs), "Node: add RRSet.");

	// Test shallow copy
	node->flags |= NODE_FLAGS_DELEG;
	zone_node_t *copy = node_shallow_copy(node, NULL);
	ok(copy != NULL, "Node: shallow copy.");
	assert(copy);
	const bool copy_ok = knot_dname_is_equal(copy->owner, node->owner) &&
	                     copy->rrset_count == node->rrset_count &&
	                     memcmp(copy->rrs, node->rrs,
	                            copy->rrset_count * sizeof(struct rr_data)) == 0 &&
	                     copy->flags == node->flags;
	ok(copy_ok, "Node: shallow copy - set fields.");

	node_free(&copy, NULL);

	// Test RRSet getters
	knot_rrset_t *n_rrset = node_create_rrset(node, KNOT_RRTYPE_TXT);
	ok(n_rrset && knot_rrset_equal(n_rrset, dummy_rrset, KNOT_RRSET_COMPARE_WHOLE),
	   "Node: create existing RRSet.");

	knot_rrset_free(n_rrset, NULL);

	n_rrset = node_create_rrset(node, KNOT_RRTYPE_SOA);
	ok(n_rrset == NULL, "Node: create non-existing RRSet.");

	knot_rrset_t stack_rrset = node_rrset(node, KNOT_RRTYPE_TXT);
	ok(knot_rrset_equal(&stack_rrset, dummy_rrset,
	                    KNOT_RRSET_COMPARE_WHOLE), "Node: get existing RRSet.");
	stack_rrset = node_rrset(node, KNOT_RRTYPE_SOA);
	ok(knot_rrset_empty(&stack_rrset), "Node: get non-existent RRSet.");

	knot_rdataset_t *n_rdataset = node_rdataset(node, KNOT_RRTYPE_TXT);
	ok(n_rdataset && knot_rdataset_eq(n_rdataset, &dummy_rrset->rrs),
	   "Node: get existing rdataset.");
	n_rdataset = node_rdataset(node, KNOT_RRTYPE_SOA);
	ok(n_rdataset == NULL, "Node: get non-existing rdataset.");

	stack_rrset = node_rrset_at(node, 0);
	ok(knot_rrset_equal(&stack_rrset, dummy_rrset, KNOT_RRSET_COMPARE_WHOLE),
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
	void *to_free = node_rdataset(node, KNOT_RRTYPE_TXT)->data;
	node_remove_rdataset(node, KNOT_RRTYPE_TXT);
	ok(node->rrset_count == 1, "Node: remove existing rdataset.");

	free(to_free);

	// "Test" freeing
	node_free_rrsets(node, NULL);
	ok(node->rrset_count == 0, "Node: free RRSets.");

	node_free(&node, NULL);
	ok(node == NULL, "Node: free.");

	knot_dname_free(dummy_owner, NULL);

	return 0;
}
