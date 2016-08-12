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
#include <string.h>

#include "libknot/rdataset.h"
#include "libknot/libknot.h"

// Inits rdataset with given rdata.
#define RDATASET_INIT_WITH(set, rdata) \
	knot_rdataset_clear(&set, NULL); \
	ret = knot_rdataset_add(&set, rdata, NULL); \
	assert(ret == KNOT_EOK);

int main(int argc, char *argv[])
{
	plan(34);

	// Test init
	knot_rdataset_t rdataset;
	knot_rdataset_init(&rdataset);
	ok(rdataset.data == NULL && rdataset.rr_count == 0, "rdataset: init.");

	// Test rdata addition
	knot_rdata_t rdata_gt[knot_rdata_array_size(4)];
	knot_rdata_init(rdata_gt, 4, (uint8_t *)"wxyz", 3600);

	int ret = knot_rdataset_add(NULL, NULL, NULL);
	ok(ret == KNOT_EINVAL, "rdataset: add NULL.");
	ret = knot_rdataset_add(&rdataset, rdata_gt, NULL);
	bool add_ok = ret == KNOT_EOK && rdataset.rr_count == 1 &&
	              knot_rdata_cmp(rdata_gt, rdataset.data) == 0;
	ok(add_ok, "rdataset: add.");

	knot_rdata_t rdata_lo[knot_rdata_array_size(4)];
	knot_rdata_init(rdata_lo, 4, (uint8_t *)"abcd", 3600);
	ret = knot_rdataset_add(&rdataset, rdata_lo, NULL);
	add_ok = ret == KNOT_EOK && rdataset.rr_count == 2 &&
	         knot_rdata_cmp(rdata_lo, rdataset.data) == 0;
	ok(add_ok, "rdataset: add lower.");

	// Test getters
	ok(knot_rdata_cmp(knot_rdataset_at(&rdataset, 0), rdata_lo) == 0 &&
	   knot_rdata_cmp(knot_rdataset_at(&rdataset, 1), rdata_gt) == 0,
	   "rdataset: at.");

	ok(knot_rdataset_size(&rdataset) == knot_rdata_array_size(4) * 2,
	   "rdataset: size.");

	// Test copy
	ok(knot_rdataset_copy(NULL, NULL, NULL) == KNOT_EINVAL,
	   "rdataset: copy NULL.");
	knot_rdataset_t copy;
	ret = knot_rdataset_copy(&copy, &rdataset, NULL);
	const bool copy_ok = ret == KNOT_EOK && copy.rr_count == rdataset.rr_count &&
	                     knot_rdataset_size(&copy) == knot_rdataset_size(&rdataset) &&
	                     memcmp(rdataset.data, copy.data,
	                            knot_rdataset_size(&rdataset)) == 0;
	ok(copy_ok, "rdataset: copy");

	// Test eq
	ok(knot_rdataset_eq(&rdataset, &copy), "rdataset: equal");

	// Test clear
	knot_rdataset_clear(&copy, NULL);
	ok(copy.rr_count == 0 && copy.data == NULL, "rdataset: clear.");

	// Test not equal (different count)
	ok(!knot_rdataset_eq(&rdataset, &copy), "rdataset: not equal - count");

	// Test member
	knot_rdata_t not_a_member[knot_rdata_array_size(1)];
	knot_rdata_init(not_a_member, 1, (uint8_t *)"?", 3600);
	ok(knot_rdataset_member(&rdataset, rdata_gt, true), "rdataset: is member.");
	ok(!knot_rdataset_member(&rdataset, not_a_member, true), "rdataset: is not member.");

	knot_rdata_set_ttl(rdata_gt, 1234);
	ok(knot_rdataset_member(&rdataset, rdata_gt, false), "rdataset: is member TTL.");
	ok(!knot_rdataset_member(&rdataset, rdata_gt, true), "rdataset: is not member TTL.");

	// Test merge
	ok(knot_rdataset_merge(NULL, NULL, NULL) == KNOT_EINVAL,
	   "rdataset: merge NULL.");
	knot_rdataset_t empty;
	knot_rdataset_init(&empty);
	ret = knot_rdataset_merge(&empty, &rdataset, NULL);
	bool merge_ok = ret == KNOT_EOK && knot_rdataset_eq(&empty, &rdataset);
	ok(merge_ok, "rdataset: merge empty.");
	knot_rdata_t *data_before = rdataset.data;
	ret = knot_rdataset_merge(&rdataset, &rdataset, NULL);
	merge_ok = ret == KNOT_EOK && rdataset.rr_count == 2 &&
	           data_before == rdataset.data;
	ok(merge_ok, "rdataset: merge self.");

	knot_rdataset_clear(&empty, NULL);

	// Init structs for merge sort testing
	knot_rdataset_t rdataset_lo; // "Lower" rdataset
	knot_rdataset_init(&rdataset_lo);
	RDATASET_INIT_WITH(rdataset_lo, rdata_lo);
	knot_rdataset_t rdataset_gt; // "Greater" rdataset
	knot_rdataset_init(&rdataset_gt);
	RDATASET_INIT_WITH(rdataset_gt, rdata_gt);

	// Test not equal - different data
	ok(!knot_rdataset_eq(&rdataset_gt, &rdataset_lo), "rdataset: data not equal.");

	// Test that merge keeps the sorted order
	ret = knot_rdataset_merge(&rdataset_lo, &rdataset_gt, NULL);
	merge_ok = ret == KNOT_EOK && knot_rdataset_eq(&rdataset_lo, &rdataset);
	ok(merge_ok, "rdataset: merge into lower.");

	RDATASET_INIT_WITH(rdataset_lo, rdata_lo);
	RDATASET_INIT_WITH(rdataset_gt, rdata_gt);
	ret = knot_rdataset_merge(&rdataset_gt, &rdataset_lo, NULL);
	merge_ok = ret == KNOT_EOK && knot_rdataset_eq(&rdataset_gt, &rdataset);
	ok(merge_ok, "rdataset: merge into greater.");

	// Test intersect
	ok(knot_rdataset_intersect(NULL, NULL, NULL, NULL) == KNOT_EINVAL,
	   "rdataset: intersect NULL.");

	knot_rdataset_t intersection;
	ret = knot_rdataset_intersect(&rdataset, &rdataset, &intersection, NULL);
	bool intersect_ok = ret == KNOT_EOK && knot_rdataset_eq(&rdataset, &intersection);
	ok(intersect_ok, "rdataset: intersect self.");
	knot_rdataset_clear(&intersection, NULL);

	RDATASET_INIT_WITH(rdataset_lo, rdata_lo);
	RDATASET_INIT_WITH(rdataset_gt, rdata_gt);
	ret = knot_rdataset_intersect(&rdataset_lo, &rdataset_gt, &intersection, NULL);
	intersect_ok = ret == KNOT_EOK && intersection.rr_count == 0;
	ok(intersect_ok, "rdataset: intersect no common.");

	ret = knot_rdataset_intersect(&rdataset, &rdataset_lo, &intersection, NULL);
	intersect_ok = ret == KNOT_EOK && knot_rdataset_eq(&intersection, &rdataset_lo);
	ok(intersect_ok, "rdataset: intersect normal.");
	knot_rdataset_clear(&intersection, NULL);

	// Test subtract
	ok(knot_rdataset_subtract(NULL, NULL, NULL) == KNOT_EINVAL,
	   "rdataset: subtract NULL.");
	ret = knot_rdataset_copy(&copy, &rdataset, NULL);
	assert(ret == KNOT_EOK);
	ok(knot_rdataset_subtract(&copy, &copy, NULL) == KNOT_EOK &&
	   copy.rr_count == 0, "rdataset: subtract self.");

	ret = knot_rdataset_copy(&copy, &rdataset, NULL);
	assert(ret == KNOT_EOK);
	ret = knot_rdataset_subtract(&copy, &rdataset, NULL);
	bool subtract_ok = ret == KNOT_EOK && copy.rr_count == 0;
	ok(subtract_ok, "rdataset: subtract identical.");

	RDATASET_INIT_WITH(rdataset_lo, rdata_lo);
	RDATASET_INIT_WITH(rdataset_gt, rdata_gt);
	data_before = rdataset_lo.data;
	ret = knot_rdataset_subtract(&rdataset_lo, &rdataset_gt, NULL);
	subtract_ok = ret == KNOT_EOK && rdataset_lo.rr_count == 1 &&
	              rdataset_lo.data == data_before;
	ok(subtract_ok, "rdataset: subtract no common.");

	ret = knot_rdataset_subtract(&rdataset, &rdataset_gt, NULL);
	subtract_ok = ret == KNOT_EOK && knot_rdataset_eq(&rdataset, &rdataset_lo);
	ok(subtract_ok, "rdataset: subtract normal.");

	ret = knot_rdataset_subtract(&rdataset, &rdataset_lo, NULL);
	subtract_ok = ret == KNOT_EOK && rdataset.rr_count == 0 &&
	              rdataset.data == NULL;
	ok(subtract_ok, "rdataset: subtract last.");

	ret = knot_rdataset_reserve(&rdataset, 65536, NULL);
	ok(ret == KNOT_EINVAL, "rdataset: reserve too much");

	RDATASET_INIT_WITH(rdataset, rdata_gt);

	size_t old_rrs_size = knot_rdataset_size(&rdataset);
	size_t rr_size = knot_rdata_rdlen(rdata_lo);
	ret = knot_rdataset_reserve(&rdataset, rr_size, NULL);
	size_t new_rrs_size = knot_rdataset_size(&rdataset);
	bool reserve_ok = ret == KNOT_EOK && new_rrs_size == (old_rrs_size + knot_rdata_array_size(rr_size));
	ok(reserve_ok, "rdataset: reserve normal");

	RDATASET_INIT_WITH(copy, rdata_lo);
	knot_rdataset_add(&copy, rdata_gt, NULL);

	knot_rdata_init(knot_rdataset_at(&rdataset, 1), 4, (uint8_t *)"abcd", 3600);

	ret = knot_rdataset_sort_at(&rdataset, 1, NULL);
	bool sort_ok = ret == KNOT_EOK && knot_rdataset_eq(&rdataset, &copy);
	ok(sort_ok, "rdataset: sort reserved space");

	knot_rdataset_clear(&copy, NULL);
	knot_rdataset_clear(&rdataset, NULL);
	knot_rdataset_clear(&rdataset_lo, NULL);
	knot_rdataset_clear(&rdataset_gt, NULL);

	return EXIT_SUCCESS;
}
