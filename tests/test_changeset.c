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

#include <config.h>
#include <assert.h>
#include <tap/basic.h>

#include "libknot/errcode.h"
#include "knot/updates/changesets.h"

int main(int argc, char *argv[])
{
	plan_lazy();

	// Test with NULL changeset
	ok(changeset_size(NULL) == 0, "changeset: NULL size");
	ok(changeset_empty(NULL), "changeset: NULL empty");

	// Test creation.
	knot_dname_t *d = knot_dname_from_str_alloc("test.");
	assert(d);
	changeset_t *ch = changeset_new(d);
	knot_dname_free(&d, NULL);
	ok(ch != NULL, "changeset: new");
	if (!ch) {
		return 1;
	}
	ok(changeset_empty(ch), "changeset: empty");
	ch->soa_to = (knot_rrset_t *)0xdeadbeef;
	ok(!changeset_empty(ch), "changseset: empty SOA");
	ch->soa_to = NULL;
	ok(changeset_size(ch) == 0, "changeset: empty size");

	// Test additions.
	d = knot_dname_from_str_alloc("non.terminals.test.");
	assert(d);
	knot_rrset_t *apex_txt_rr = knot_rrset_new(d, KNOT_RRTYPE_TXT, KNOT_CLASS_IN, NULL);
	assert(apex_txt_rr);
	uint8_t data[8] = "\7teststr";
	knot_rrset_add_rdata(apex_txt_rr, data, sizeof(data), 3600, NULL);

	int ret = changeset_add_addition(ch, apex_txt_rr, CHANGESET_CHECK);
	ok(ret == KNOT_EOK, "changeset: add RRSet");
	ok(changeset_size(ch) == 1, "changeset: size add");
	ret = changeset_add_removal(ch, apex_txt_rr, CHANGESET_CHECK);
	ok(ret == KNOT_EOK, "changeset: rem RRSet");
	ok(changeset_size(ch) == 1, "changeset: size remove");
	ok(!changeset_empty(ch), "changeset: empty");
	changeset_add_addition(ch, apex_txt_rr, CHANGESET_CHECK);

	// Add another RR to node.
	knot_rrset_t *apex_spf_rr = knot_rrset_new(d, KNOT_RRTYPE_SPF, KNOT_CLASS_IN, NULL);
	assert(apex_spf_rr);
	knot_rrset_add_rdata(apex_spf_rr, data, sizeof(data), 3600, NULL);
	ret = changeset_add_addition(ch, apex_spf_rr, CHANGESET_CHECK);
	ok(ret == KNOT_EOK, "changeset: add multiple");

	// Add another node.
	knot_dname_free(&d, NULL);
	d = knot_dname_from_str_alloc("here.come.more.non.terminals.test");
	assert(d);
	knot_rrset_t *other_rr = knot_rrset_new(d, KNOT_RRTYPE_TXT, KNOT_CLASS_IN, NULL);
	assert(other_rr);
	knot_rrset_add_rdata(other_rr, data, sizeof(data), 3600, NULL);
	ret = changeset_add_addition(ch, other_rr, CHANGESET_CHECK);
	ok(ret == KNOT_EOK, "changeset: remove multiple");

	// Test add traversal.
	changeset_iter_t it;
	ret = changeset_iter_add(&it, ch);
	ok(ret == KNOT_EOK, "changeset: create iter add");
	// Order: non.terminals.test. TXT, SPF, here.come.more.non.terminals.test. TXT.
	knot_rrset_t iter = changeset_iter_next(&it);
	bool trav_ok = knot_rrset_equal(&iter, apex_txt_rr, KNOT_RRSET_COMPARE_WHOLE);
	iter = changeset_iter_next(&it);
	trav_ok = trav_ok && knot_rrset_equal(&iter, apex_spf_rr, KNOT_RRSET_COMPARE_WHOLE);
	iter = changeset_iter_next(&it);
	trav_ok = trav_ok && knot_rrset_equal(&iter, other_rr, KNOT_RRSET_COMPARE_WHOLE);

	ok(trav_ok, "changeset: add traversal");

	iter = changeset_iter_next(&it);
	changeset_iter_clear(&it);
	ok(knot_rrset_empty(&iter), "changeset: traversal: skip non-terminals");

	changeset_add_removal(ch, apex_txt_rr, CHANGESET_CHECK);
	changeset_add_removal(ch, apex_txt_rr, CHANGESET_CHECK);

	// Test remove traversal.
	ret = changeset_iter_rem(&it, ch);
	ok(ret == KNOT_EOK, "changeset: create iter rem");
	iter = changeset_iter_next(&it);
	ok(knot_rrset_equal(&iter, apex_txt_rr, KNOT_RRSET_COMPARE_WHOLE),
	   "changeset: rem traversal");
	changeset_iter_clear(&it);

	// Test all traversal - just count.
	ret = changeset_iter_all(&it, ch);
	ok(ret == KNOT_EOK, "changest: create iter all");
	size_t size = 0;
	iter = changeset_iter_next(&it);
	while (!knot_rrset_empty(&iter)) {
		++size;
		iter = changeset_iter_next(&it);
	}
	changeset_iter_clear(&it);
	ok(size == 3, "changeset: iter all");

	// Create new changeset.
	knot_dname_free(&d, NULL);
	d = knot_dname_from_str_alloc("test.");
	assert(d);
	changeset_t *ch2 = changeset_new(d);
	knot_dname_free(&d, NULL);
	assert(ch2);
	// Add something to add section.
	knot_dname_free(&apex_txt_rr->owner, NULL);
	apex_txt_rr->owner = knot_dname_from_str_alloc("something.test.");
	assert(apex_txt_rr->owner);
	ret = changeset_add_addition(ch2, apex_txt_rr, CHANGESET_CHECK);
	assert(ret == KNOT_EOK);

	// Add something to remove section.
	knot_dname_free(&apex_txt_rr->owner, NULL);
	apex_txt_rr->owner =
		knot_dname_from_str_alloc("and.now.for.something.completely.different.test.");
	assert(apex_txt_rr->owner);
	ret = changeset_add_removal(ch2, apex_txt_rr, CHANGESET_CHECK);
	assert(ret == KNOT_EOK);

	// Test merge.
	ret = changeset_merge(ch, ch2);
	ok(ret == KNOT_EOK && changeset_size(ch) == 5, "changeset: merge");

	// Test cleanup.
	changeset_clear(ch);
	ok(changeset_empty(ch), "changeset: clear");
	free(ch);

	list_t chgs;
	init_list(&chgs);
	add_head(&chgs, &ch2->n);
	changesets_clear(&chgs);
	ok(changeset_empty(ch2), "changeset: clear list");
	free(ch2);

	knot_rrset_free(&apex_txt_rr, NULL);
	knot_rrset_free(&apex_spf_rr, NULL);
	knot_rrset_free(&other_rr, NULL);

	return 0;
}
