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
#include <tap/basic.h>
#include <string.h>

#include "libknot/rdataset.c"
#include "libknot/libknot.h"

// Inits rdataset with given rdata.
#define RDATASET_INIT_WITH(set, rdata) \
	knot_rdataset_clear(&set, NULL); \
	ret = knot_rdataset_add(&set, rdata, NULL); \
	assert(ret == KNOT_EOK);

static size_t rdataset_size(const knot_rdataset_t *rrs)
{
	if (rrs == NULL || rrs->count == 0) {
		return 0;
	}

	const knot_rdata_t *last = rr_seek(rrs, rrs->count - 1);
	return (uint8_t *)last + knot_rdata_size(last->len) - (uint8_t *)rrs->rdata;
}

int main(int argc, char *argv[])
{
	plan_lazy();

	// Test init
	knot_rdataset_t rdataset;
	knot_rdataset_init(&rdataset);
	ok(rdataset.rdata == NULL && rdataset.count == 0 && rdataset.size == 0, "rdataset: init.");

	// Test rdata addition
	uint8_t buf_gt[knot_rdata_size(4)];
	knot_rdata_t *rdata_gt = (knot_rdata_t *)buf_gt;
	knot_rdata_init(rdata_gt, 4, (uint8_t *)"wxyz");

	int ret = knot_rdataset_add(NULL, NULL, NULL);
	is_int(KNOT_EINVAL, ret, "rdataset: add NULL.");
	ret = knot_rdataset_add(&rdataset, rdata_gt, NULL);
	bool add_ok = ret == KNOT_EOK && rdataset.count == 1 &&
	              knot_rdata_cmp(rdata_gt, rdataset.rdata) == 0;
	ok(add_ok, "rdataset: add.");

	uint8_t buf_lo[knot_rdata_size(4)];
	knot_rdata_t *rdata_lo = (knot_rdata_t *)buf_lo;
	knot_rdata_init(rdata_lo, 4, (uint8_t *)"abcd");
	ret = knot_rdataset_add(&rdataset, rdata_lo, NULL);
	add_ok = ret == KNOT_EOK && rdataset.count == 2 &&
	         knot_rdata_cmp(rdata_lo, rdataset.rdata) == 0;
	ok(add_ok, "rdataset: add lower.");

	// Test getters
	ok(knot_rdata_cmp(knot_rdataset_at(&rdataset, 0), rdata_lo) == 0 &&
	   knot_rdata_cmp(knot_rdataset_at(&rdataset, 1), rdata_gt) == 0,
	   "rdataset: at.");

	ok(rdataset_size(&rdataset) == knot_rdata_size(4) * 2,
	   "rdataset: size.");
	ok(rdataset.size == rdataset_size(&rdataset), "rdataset: size precomputed (%u %zu).",
	   rdataset.size, rdataset_size(&rdataset));

	// Test copy
	ok(knot_rdataset_copy(NULL, NULL, NULL) == KNOT_EINVAL,
	   "rdataset: copy NULL.");
	knot_rdataset_t copy;
	ret = knot_rdataset_copy(&copy, &rdataset, NULL);
	const bool copy_ok = ret == KNOT_EOK && copy.count == rdataset.count &&
	                     rdataset_size(&copy) == rdataset_size(&rdataset) &&
	                     memcmp(rdataset.rdata, copy.rdata,
	                            rdataset_size(&rdataset)) == 0;
	ok(copy_ok, "rdataset: copy");
	ok(copy.size == rdataset_size(&copy), "copy: size precomputed.");

	// Test eq
	ok(knot_rdataset_eq(&rdataset, &copy), "rdataset: equal");

	// Test clear
	knot_rdataset_clear(&copy, NULL);
	ok(copy.count == 0 && copy.rdata == NULL, "rdataset: clear.");

	// Test not equal (different count)
	ok(!knot_rdataset_eq(&rdataset, &copy), "rdataset: not equal - count");

	// Test member
	uint8_t buf_not[knot_rdata_size(1)];
	knot_rdata_t *not_a_member = (knot_rdata_t *)buf_not;
	knot_rdata_init(not_a_member, 1, (uint8_t *)"?");
	ok(knot_rdataset_member(&rdataset, rdata_gt), "rdataset: is member.");
	ok(!knot_rdataset_member(&rdataset, not_a_member), "rdataset: is not member.");

	// Test merge
	ok(knot_rdataset_merge(NULL, NULL, NULL) == KNOT_EINVAL,
	   "rdataset: merge NULL.");
	knot_rdataset_t empty;
	knot_rdataset_init(&empty);
	ret = knot_rdataset_merge(&empty, &rdataset, NULL);
	bool merge_ok = ret == KNOT_EOK && knot_rdataset_eq(&empty, &rdataset);
	ok(merge_ok, "rdataset: merge empty.");
	knot_rdata_t *data_before = rdataset.rdata;
	ret = knot_rdataset_merge(&rdataset, &rdataset, NULL);
	merge_ok = ret == KNOT_EOK && rdataset.count == 2 &&
	           data_before == rdataset.rdata;
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
	intersect_ok = ret == KNOT_EOK && intersection.count == 0;
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
	   copy.count == 0, "rdataset: subtract self.");

	ret = knot_rdataset_copy(&copy, &rdataset, NULL);
	assert(ret == KNOT_EOK);
	ret = knot_rdataset_subtract(&copy, &rdataset, NULL);
	bool subtract_ok = ret == KNOT_EOK && copy.count == 0;
	ok(subtract_ok, "rdataset: subtract identical.");

	RDATASET_INIT_WITH(rdataset_lo, rdata_lo);
	RDATASET_INIT_WITH(rdataset_gt, rdata_gt);
	data_before = rdataset_lo.rdata;
	ret = knot_rdataset_subtract(&rdataset_lo, &rdataset_gt, NULL);
	subtract_ok = ret == KNOT_EOK && rdataset_lo.count == 1 &&
	              rdataset_lo.rdata == data_before;
	ok(subtract_ok, "rdataset: subtract no common.");

	ret = knot_rdataset_subtract(&rdataset, &rdataset_gt, NULL);
	subtract_ok = ret == KNOT_EOK && rdataset.count == 1;
	ok(subtract_ok, "rdataset: subtract the second.");

	ret = knot_rdataset_subtract(&rdataset, &rdataset_lo, NULL);
	subtract_ok = ret == KNOT_EOK && rdataset.count == 0 &&
	              rdataset.rdata == NULL;
	ok(subtract_ok, "rdataset: subtract last.");

	knot_rdataset_clear(&copy, NULL);
	knot_rdataset_clear(&rdataset, NULL);
	knot_rdataset_clear(&rdataset_lo, NULL);
	knot_rdataset_clear(&rdataset_gt, NULL);

	return EXIT_SUCCESS;
}
