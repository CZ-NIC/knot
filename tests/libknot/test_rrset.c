/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <assert.h>
#include <inttypes.h>
#include <tap/basic.h>

#include "libknot/rrset.h"
#include "libknot/descriptor.h"

static bool check_rrset(const knot_rrset_t *rrset, const knot_dname_t *owner,
                        uint16_t type, uint16_t rclass, uint32_t ttl)
{
	if (!rrset) {
		return false;
	}

	const bool dname_cmp = owner == NULL ? rrset->owner == NULL :
	                                       knot_dname_is_equal(rrset->owner, owner);
	return rrset->type == type && rrset->rclass == rclass && dname_cmp &&
	       rrset->ttl == ttl && rrset->rrs.count == 0; // We do not test rdataset here
}

int main(int argc, char *argv[])
{
	plan_lazy();

	// Test new
	knot_dname_t *dummy_owner = knot_dname_from_str_alloc("test.");
	assert(dummy_owner);

	knot_rrset_t *rrset = knot_rrset_new(dummy_owner, KNOT_RRTYPE_TXT,
	                                     KNOT_CLASS_IN, 3600, NULL);
	ok(rrset != NULL, "rrset: create.");
	assert(rrset);

	ok(check_rrset(rrset, dummy_owner, KNOT_RRTYPE_TXT, KNOT_CLASS_IN, 3600),
	   "rrset: set fields during create.");

	// Test init
	knot_dname_free(dummy_owner, NULL);
	dummy_owner = knot_dname_from_str_alloc("test2.");
	assert(dummy_owner);

	knot_dname_free(rrset->owner, NULL);
	knot_rrset_init(rrset, dummy_owner, KNOT_RRTYPE_A, KNOT_CLASS_CH, 7200);
	ok(check_rrset(rrset, dummy_owner, KNOT_RRTYPE_A, KNOT_CLASS_CH, 7200),
	   "rrset: init.");

	// Test copy
	knot_rrset_t *copy = knot_rrset_copy(rrset, NULL);
	ok(copy != NULL, "rrset: copy.");
	ok(check_rrset(copy, rrset->owner, rrset->type, rrset->rclass, 7200),
	   "rrset: set fields during copy.");
	ok(knot_rrset_copy(NULL, NULL) == NULL, "rrset: copy NULL.");
	assert(copy);

	// Test equal - same TTL
	ok(knot_rrset_equal(rrset, copy, true), "rrset: cmp same TTL");

	// Test equal - different TTL
	copy->ttl++;
	ok(!knot_rrset_equal(rrset, copy, true), "rrset: cmp different TTL");

	// Test equal - ignore TTL
	ok(knot_rrset_equal(rrset, copy, false), "rrset: cmp ignore TTL");

	copy->ttl = rrset->ttl;

	// Test equal - different type
	copy->type++;
	ok(!knot_rrset_equal(rrset, copy, true), "rrset: cmp different type");

	copy->type = rrset->type;

	// Test equal - owners
	knot_dname_free(rrset->owner, NULL);
	rrset->owner = NULL;
	ok(!knot_rrset_equal(rrset, copy, true), "rrset: cmp NULL owner");

	knot_dname_free(copy->owner, NULL);
	copy->owner = NULL;
	ok(knot_rrset_equal(rrset, copy, true), "rrset: cmp NULL owners");

	// Test equal - different rdata
	knot_rrset_add_rdata(copy, (const uint8_t *)"abc", 3, NULL);
	ok(!knot_rrset_equal(rrset, copy, true), "rrset: cmp different rdata");

	// Test clear
	knot_rrset_clear(rrset, NULL);
	ok(rrset->owner == NULL, "rrset: clear.");

	// Test empty
	ok(knot_rrset_empty(rrset), "rrset: empty.");
	ok(knot_rrset_empty(NULL), "rrset: empty NULL.");
	copy->rrs.count = 1;
	ok(!knot_rrset_empty(copy), "rrset: not empty.");

	// Test init empty
	knot_rrset_init_empty(rrset);
	ok(check_rrset(rrset, NULL, 0, KNOT_CLASS_IN, 0), "rrset: init empty.");

	// "Test" freeing
	knot_rrset_free(rrset, NULL);
	knot_rrset_free(copy, NULL);

	return 0;
}
