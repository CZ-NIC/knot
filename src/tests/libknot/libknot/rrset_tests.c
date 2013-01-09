/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <stdint.h>

#include "tests/libknot/libknot/rrset_tests.h"
#include "common/descriptor_new.h"
#include "common/errcode.h"
#include "libknot/rrset.h"

static int knot_rrset_tests_count(int argc, char *argv[]);
static int knot_rrset_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api rrset_tests_api = {
	"DNS library - rrset",    //! Unit name
	&knot_rrset_tests_count,  //! Count scheduled tests
	&knot_rrset_tests_run     //! Run scheduled tests
};

/*
 *  Unit implementation.
 */

enum rrset_test_const {
	TEST_RRSET_COUNT = 6,
	TEST_RDATA_COUNT = 6,
	TEST_DNAME_COUNT = 3,
	TEST_RDATA_A_BASE = 0,
	TEST_RDATA_A_LESS = 1,
	TEST_RDATA_NS_1 = 2,
	TEST_RDATA_NS_2 = 3,
	TEST_RDATA_NS_3 = 4,
	TEST_RDATA_MX_1 = 5,
	TEST_RDATA_MX_2 = 6,
	TEST_RDATA_MX_3 = 7,
	CHECK_LAST_INDEX = 100,
	OMMIT_LAST_INDEX = 101
};

static uint8_t *test_dname_strings[TEST_DNAME_COUNT] = {
	(uint8_t *)"test.dname.com.",
	(uint8_t *)"test2.dname.com.",
	(uint8_t *)"test3.dname.com."
};

static knot_dname_t *test_dnames[TEST_DNAME_COUNT];

struct test_rdata {
	uint8_t *rdata; // Rdata in knot internal format
	uint8_t *wire; // Rdata in wireformat
	uint16_t size;
	uint16_t wire_size;
};

typedef struct test_rdata test_rdata_t;

struct test_rrset {
	knot_rrset_t *rrset;
	uint8_t header_wire[1024];
	size_t header_wire_size;
	uint8_t rdata[65535];
	size_t rdata_size;
	test_rdata_t *test_rdata;
};

typedef struct test_rrset test_rrset_t;

test_rrset_t test_rrset_array[TEST_RRSET_COUNT];

/* Artificial RDATA definitions: */
test_rdata_t test_rdata_array[TEST_RDATA_COUNT] = {
/* A type: */
	{(uint8_t *)"\x1\x1\x1\1", (uint8_t *)"\x1\x1\x1\1", 4, 4},
/* A < previous */
	{(uint8_t *)"\x1\x1\x1\0", (uint8_t *)"\x1\x1\x1\0", 4, 4},
/* A = previous */
	{(uint8_t *)"\x1\x1\x1\0", (uint8_t *)"\x1\x1\x1\0", 4, 4},
/* NS Domain names: (Will be filled dynamically) */
	{(uint8_t *)&test_dnames[0], "", sizeof(knot_dname_t *), 0},
	{(uint8_t *)&test_dnames[1], "", sizeof(knot_dname_t *), 0},
	{(uint8_t *)&test_dnames[2], "", sizeof(knot_dname_t *), 0},
/* MX type: (raw data + DNAME) */
	{"\x0\x1", "", sizeof(knot_dname_t *) + 2, 0},
	{"\x0\x2", "", sizeof(knot_dname_t *) + 2, 0},
	{"\x2\x1", "", sizeof(knot_dname_t *) + 2, 0}
};

static int create_test_dnames()
{
	for (int i = 0; i < TEST_DNAME_COUNT; i++) {
		test_dnames[i] =
			knot_dname_new_from_str(test_dname_strings[i],
		                                strlen(test_dname_strings[i]),
		                                NULL);
		if (test_dnames[i] == NULL) {
			diag("Failed to create test dname.\n");
			return -1;
		}
	}
}
static int create_test_rdata()
{
	/* Only MX types need init. */
	memcpy(test_rdata_array[TEST_RDATA_MX_1].rdata + 2, &test_dnames[0],
	       sizeof(knot_dname_t *));
	memcpy(test_rdata_array[TEST_RDATA_MX_2].rdata + 2, &test_dnames[1],
	       sizeof(knot_dname_t *));
	memcpy(test_rdata_array[TEST_RDATA_MX_3].rdata + 2, &test_dnames[2],
	       sizeof(knot_dname_t *));
	return 0;
}

static int create_test_rrsets()
{
}

static int check_rrset_values(const knot_rrset_t *rrset,
                              knot_dname_t *dname, uint16_t type,
                              uint16_t rclass, uint16_t ttl, uint16_t rr_count)
{
	int errors = 0;
	
	if (rrset->dname != dname) {
		diag("Wrong DNAME in the created RRSet.\n");
		++errors;
	}
	
	if (rrset->type != type) {
		diag("Wrong type in the created RRSet.\n");
		++errors;
	}
	
	if (rrset->rclass != rclass) {
		diag("Wrong class in the created RRSet.\n");
		++errors;
	}
	
	if (rrset->ttl != ttl) {
		diag("Wrong TTL in the created RRSet.\n");
		++errors;
	}
	
	if (rrset->rdata_count!= rr_count) {
		diag("Wrong RR count in the created RRSet.\n");
		++errors;
	}
	
	return errors;
}

static int test_rrset_new()
{
	/* Actual values don't matter in this case. */
	knot_dname_t *dname = (knot_dname_t *)0x1;
	uint16_t type = 1;
	uint16_t rclass = 1;
	uint32_t ttl = 1;

	knot_rrset_t *rrset = knot_rrset_new(dname, type, rclass, ttl);
	if (rrset == NULL) {
		diag("Failed to create new RRSet.\n");
		return 0;
	}
	
	int check_errors = check_rrset_values(rrset, dname, type, rclass, ttl,
	                                      0);
	free(rrset);

	diag("Total errors: %d", check_errors);

	return (check_errors == 0);
}

static int test_rrset_create_rdata(knot_rrset_t **in_rrset)
{
	/* Two cases need to be tested - empty RRSet and non-empty RRSet. */
	
	
	knot_rrset_t *rrset = knot_rrset_new(NULL, 0, 0, 0);
	assert(rrset);
	*in_rrset = rrset;
	
	/*
	* Again, actual data are not crutial, we need to see if indices 
	* are changed accordingly and so on, but the data are not important.
	*/
	uint8_t *write_pointer =
		knot_rrset_create_rdata(rrset,
	                                test_rdata_array[0].size);
	if (write_pointer == NULL) {
		diag("Could not create data of size %d\n",
		     test_rdata_array[0].size);
		return 0;
	}
	
	/* Write dummy data. */
	memcpy(write_pointer, test_rdata_array[0].rdata,
	       test_rdata_array[0].size);
	
	/* Check that indices are set right. */
	if (rrset->rdata_indices[0] != test_rdata_array[0].size) {
		diag("Wrong RDATA index after inserting RDATA to RRSet.\n");
		return 0;
	}
	
	/* Rdata count must be equal to one. */
	if (rrset->rdata_count != 1) {
		diag("Wrong RDATA count after inserting RDATA to RRSet.\n");
		return 0;
	}
	
	/* Make sure that the data in the RRSet are the same. */
	int ret = memcmp(rrset->rdata, test_rdata_array[0].rdata,
	                 test_rdata_array[0].size);
	if (ret) {
		diag("Wrong data inserted into RRSet.\n");
		return 0;
	}
	
	/* Insert second item - all other inserts will do the same thing. */
	write_pointer = knot_rrset_create_rdata(rrset,
	                                        test_rdata_array[1].size);
	if (write_pointer == NULL) {
		diag("Could not create data of size %d\n",
		     test_rdata_array[1].size);
		return 0;
	}
	
	/* Write dummy data. */
	memcpy(write_pointer, test_rdata_array[1].rdata,
	       test_rdata_array[1].size);
	
	/* Check that indices are set right. */
	if (rrset->rdata_indices[0] != test_rdata_array[1].size) {
		diag("Wrong RDATA first index after "
		     "inserting RDATA to RRSet.\n");
		return 0;
	}
	
	if (rrset->rdata_indices[1] !=
	    test_rdata_array[0].size + test_rdata_array[1].size) {
		diag("Wrong RDATA last index after "
		     "inserting RDATA to RRSet.\n");
		return 0;
	}
	
	/* Rdata count must be equal to two. */
	if (rrset->rdata_count != 2) {
		diag("Wrong RDATA count after inserting second "
		     "RDATA to RRSet.\n");
		return 0;
	}
	
	/* Make sure that the data in the RRSet are the same. */
	ret = memcmp(rrset->rdata + test_rdata_array[0].size, data2,
	             test_rdata_array[1].rdata);
	if (ret) {
		diag("Wrong data inserted into RRSet.\n");
		return 0;
	}
	
	/* Test that data of length 0 are not inserted. */
	void *ret = knot_rrset_create_rdata(rrset, 0);
	if (ret != NULL) {
		diag("Empty RDATA inserted.\n");
		return 0;
	}
	
	return 1;
}

static int test_rrset_rdata_item_size(const knot_rrset_t *rrset)
{
	if (rrset_rdata_item_size(rrset, 0) != DATA1_LENGTH) {
		diag("Wrong item length read from RRSet (first item).\n");
		return 0;
	}
	
	if (rrset_rdata_item_size(rrset, 1) != DATA2_LENGTH) {
		diag("Wrong item length read from RRSet (last item).\n");
		return 0;
	}
	
	return 1;
}

static int test_rrset_get_rdata(const knot_rrset_t *rrset)
{
	uint8_t *pointer = knot_rrset_get_rdata(rrset, 0);
	if (pointer == NULL) {
		diag("Could not ger RDATA from RRSet.\n");
		return 0;
	}
	
	int ret = memcmp(pointer, RDATA_INIT_1, DATA1_LENGTH);
	if (ret) {
		diag("Got bad RDATA from RRSet.\n");
		return 0;
	}
	
	pointer = knot_rrset_get_rdata(rrset, 1);
	if (pointer == NULL) {
		diag("Could not ger RDATA from RRSet.\n");
		return 0;
	}
	
	ret = memcmp(pointer, RDATA_INIT_2, DATA2_LENGTH);
	if (ret) {
		diag("Got bad RDATA from RRSet.\n");
		return 0;
	}
	
	return 1;
}

static int test_rrset_shallow_copy(const knot_rrset_t *rrset)
{
	knot_rrset_t *rrset_copy = NULL;
	
	int ret = knot_rrset_shallow_copy(rrset, &rrset_copy);
	if (ret != KNOT_EOK) {
		diag("Could not copy RRSet.\n");
		return 0;
	}
	
	/* Check that created RRSet has the same as the old one. */
	int errors = check_rrset_values(rrset_copy, rrset->owner, rrset->type,
	                                rrset->rclass, rrset->ttl,
	                                rrset->rdata_count);
	if (errors) {
		return 0;
	}
	
	/* Check that created RRSet has the same RDATA. */
	if (rrset->rdata != rrset_copy->rdata) {
		diag("RDATA in the new RRSet do not match.\n");
		return 0;
	}
	
	/* Check that RDATA indices are the same. */
	if (rrset->rdata_indices != rrset_copy->rdata_indices) {
		diag("RDATA indices in the new RRSet do not match.\n");
		return 0;
	}
	
	knot_rrset_free(&rrset_copy);
	return (errors == 0);
}

static int test_rrset_deep_copy(const knot_rrset_t *rrset)
{
	
	knot_rrset_t *rrset_copy = NULL;
	
	int ret = knot_rrset_deep_copy(rrset, &rrset_copy);
	if (ret != KNOT_EOK) {
		diag("Could not copy RRSet.\n");
		return 0;
	}
	
	/* Check that created RRSet has the same as the old one. */
	int errors = check_rrset_values(rrset_copy, rrset->owner, rrset->type,
	                                rrset->rclass, rrset->ttl,
	                                rrset->rdata_count);
	if (errors) {
		return 0;
	}
	
	/* Check that RDATA indices contain the same data. */
	ret = memcmp(rrset->rdata_indices, rrset_copy->rdata_indices,
	             rrset->rdata_count);
	if (ret) {
		diag("Copied RRSet has different RDATA indices.\n");
		return 0;
	}
	
	/*
	 * Go through RDATA and compare blocks. Cannot compare the whole thing
	 * since DNAMEs are copied as well and will have different address.
	 */
	ret = knot_rrset_compare_rdata(rrset, rrset_copy);
	if (ret) {
		diag("Copied RRSet has different RDATA.\n");
		return 0;
	}
	
	return 1;
}

static int test_rrset_to_wire()
{
	size_t wire_size = 65535;
	uint8_t wire[wire_size];
	uint16_t rr_count = 0;
	for (int i = 0; i < TEST_RRSET_COUNT; i++) {
		wire_size = 65535;
		/* Convert to wire. */
		int ret = knot_rrset_to_wire(test_rrset_array[i].rrset, wire,
		                             &wire_size, &rr_count);
		if (ret) {
			diag("Could not convert RRSet to wire.\n");
			return 0;
		}
		
		/* Check that the header is OK. */
		ret = memcmp(wire, test_rrset_array[i].header_wire,
		             test_rrset_array[i].header_wire_size);
		if (cmp) {
			diag("Header of RRSet %d is wrongly converted.\n",
			     i);
			return 0;
		}
		
		/* Check that the RDATA are OK. */
		ret = memcmp(wire + test_rrset_array[i].header_wire_size,
		             test_rrset_array[i].rdata,
		             test_rrset_array[i].rdata_size);
		if (cmp) {
			diag("RDATA of RRSet %d are wrongly converted.\n",
			     i);
			return 0;
		}
	}
	
	/* Check that function does not crash if given small wire. */
	wire_size = 5; // even header does not fit
	ret = knot_rrset_to_wire(test_rrset_array[i].rrset, wire,
	                         &wire_size, &rr_count);
	if (ret != KNOT_ESPACE) {
		diag("RRSet was converted to wire even though twe wire was"
		     " not big enough.\n");
		return 0;
	}
	wire_size = 25; // even RDATA do not fit TODO check those values
	ret = knot_rrset_to_wire(test_rrset_array[i].rrset, wire,
	                         &wire_size, &rr_count);
	if (ret != KNOT_ESPACE) {
		diag("RRSet was converted to wire even though twe wire was"
		     " not big enough.\n");
		return 0;
	}
	
	return 1;
}

static int test_rrset_merge()
{
	knot_rrset_t *merge_to =
		knot_rrset_deep_copy(test_rrset_array[0].rrset);
	knot_rrset_t *merge_from = test_rrset_array[1].rrset;
	
	int ret = knot_rrset_merge(&merge_to, &merge_from);
	if (ret) {
		diag("Could not merge RRSets.\n");
		return 0;
	}
	
	if (merge_to->rdata_count != test_rrset_array[0].rrset->rdata_count +
	    merge_from->rdata_count) {
		diag("Not all RDATA were merged.\n");
		return 0;
	}
	
	/* Check that the first RRSet now contains RDATA from the second. */
	/* Indices first. */
	ret = memcmp(merge_to->rdata_indices, test_rrset_array[TODOmergnuty],
	             merge_to->rdata_count);
	if (ret) {
		diag("Merge operation corrupted the first RRSet's indices.\n");
		return 0;
	}
	
	/* Check actual RDATA. */
	ret = knot_rrset_compare_rdata(merge_to->rdata,
	                               test_rrset_array[TODOmergnuty]);
	if (ret) {
		diag("Merged RDATA are wrong.\n");
		return 0;
	}
	
	return 1;
}

static int test_rrset_merge_no_dupl()
{
	
}

static int test_rrset_get_rdata(knot_rrset_t **rrsets)
{
}

static const int KNOT_RRSET_TEST_COUNT = 13;

/*! This helper routine should report number of
 *  scheduled tests for given parameters.
 */
static int knot_rrset_tests_count(int argc, char *argv[])
{
	return KNOT_RRSET_TEST_COUNT;
}

/*! Run all scheduled tests for given parameters.
 */
static int knot_rrset_tests_run(int argc, char *argv[])
{
	int res = 0,
	    res_final = 1;

	int ret = create_test_dnames();
	assert(ret == 0);
	ret = create_test_rdata();
	assert(ret == 0);
	
	create_test_rrsets

	res = test_rrset_create();
	ok(res, "rrset: create");
	res_final *= res;

	return res_final;
}
