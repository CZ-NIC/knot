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

#include "tests/libknot/libknot/rrset_tests.h"
#include "common/descriptor_new.h"
#include "libknot/rrset.h"

static int knot_rrset_tests_count(int argc, char *argv[]);
static int knot_rrset_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api rrset_tests_api = {
	"DNS library - rrset",        //! Unit name
	&knot_rrset_tests_count,  //! Count scheduled tests
	&knot_rrset_tests_run     //! Run scheduled tests
};

/*----------------------------------------------------------------------------*/
/*
 *  Unit implementation.
 */

static knot_node_t *NODE_ADDRESS = (knot_node_t *)0xDEADBEEF;

enum { TEST_RRSETS = 6 , TEST_RRSIGS = 6};

//void *RRSIG_ADDRESS = (void *)0xDEADBEEF;
//void *RRSIG_FIRST = RRSIG_ADDRESS + 10;

struct test_domain {
	char *str;
	char *wire;
	uint size;
	char *labels;
	short label_count;
};

struct test_rrset {
	char *owner;
	uint16_t type;
	uint16_t rclass;
	uint32_t  ttl;
	knot_rdata_t *rdata;
	const knot_rrset_t *rrsigs;
};

/* this has to changed */
static const char *signature_strings[TEST_RRSIGS] =
{"signature 1", "signature 2", "signature 3",
 "signature 4", "signature 5", "signature 6"};

enum {
	RR_DNAMES_COUNT = 3,
	RR_ITEMS_COUNT = 3,
	RR_RDATA_COUNT = 4,
};

enum { TEST_DOMAINS_OK = 8 };

static knot_dname_t RR_DNAMES[RR_DNAMES_COUNT] =
	{ {{}, (uint8_t *)"\7example\3com", NULL, NULL, 0, 13, 0}, //0's at the end are added
	  {{}, (uint8_t *)"\3ns1\7example\3com", NULL, NULL, 0, 17, 0},
	  {{}, (uint8_t *)"\3ns2\7example\3com", NULL, NULL, 0, 17, 0} };

/*                         192.168.1.1 */
static uint8_t address[4] = {0xc0, 0xa8, 0x01, 0x01};

/*! \warning Do not change the order in those, if you want to test some other
 *           feature with new dname, add it at the end of these arrays.
 */
static const struct test_domain
		test_domains_ok[TEST_DOMAINS_OK] = {
	{ "abc.test.domain.com.", "\3abc\4test\6domain\3com", 21,
	  "\x0\x4\x9\x10", 4 },
	{ "some.test.domain.com.", "\4some\4test\6domain\3com", 22,
	  "\x0\x5\xA\x11", 4 },
	{ "xyz.test.domain.com.", "\3xyz\4test\6domain\3com", 21,
	  "\x0\x4\x9\x10", 4 },
	{ "some.test.domain.com.", "\4some\4test\6domain\3com", 22,
	  "\x0\x5\xA\x11", 4 },
	{ "test.domain.com.", "\4test\6domain\3com", 17,
	  "\x0\x5\xC", 3 },
	{ ".", "\0", 1,
	  "", 0 },
	{ "foo.bar.net.", "\3foo\3bar\3net", 13,
	  "\x0\x4\x8", 3},
	{ "bar.net.", "\3bar\3net", 9,
	  "\x0\x4", 2}
};



static int check_rrset_values(const knot_rrset_t *rrset,
                              knot_dname_t *dname, uint16_t type,
                              uint16_t rclass, uint16_t ttl)
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
	
	int check_errors = check_rrset_values(rrset, dname, type, rclass, ttl);
	free(rrset);

	diag("Total errors: %d", check_errors);

	return (check_errors == 0);
}

static int test_rrset_create_rdata()
{
	/* Two cases need to be tested - empty RRSet and non-empty RRSet. */
	
	knot_rrset_t *rrset = knot_rrset_new(NULL, 0, 0, 0);
	assert(rrset);
	
	/*
	* Again, actual data are not crutial, we need to see if indices 
	* are changed accordingly and so on, but the data are not important. 
	*/
	uint16_t data1_length = 16;
	uint8_t data1[data1_length];
	memset(data1, 1, data1_length);
	
	uint8_t *write_pointer = knot_rrset_create_rdata(rrset, data1_length);
	if (write_pointer == NULL) {
		diag("Could not create data of size %d\n", data1_length);
		return 0;
	}
	
	/* Write dummy data. */
	memcpy(write_pointer, data1, data1_length);
	
	/* Check that indices are set right. */
	if (rrset->rdata_indices[0] != data1_length) {
		diag("Wrong RDATA index after inserting RDATA to RRSet.\n");
		return 0;
	}
	
	/* Rdata count must be equal to one. */
	if (rrset->rdata_count != 1) {
		diag("Wrong RDATA count after inserting RDATA to RRSet.\n");
		return 0;
	}
	
	/* Make sure that the data in the RRSet are the same. */
	int ret = memcmp(rrset->rdata, data1, data1_length);
	if (ret) {
		diag("Wrong data inserted into RRSet.\n");
		return 0;
	}
	
	/* Insert second item - all other inserts will do the same thing. */
	uint16_t data2_length = 33;
	uint8_t data2[data2_length];
	memset(data2, 1, data1_length);
	
	write_pointer = knot_rrset_create_rdata(rrset, data2_length);
	if (write_pointer == NULL) {
		diag("Could not create data of size %d\n", data2_length);
		return 0;
	}
	
	/* Write dummy data. */
	memcpy(write_pointer, data1, data1_length);
	
	/* Check that indices are set right. */
	if (rrset->rdata_indices[0] != data1_length) {
		diag("Wrong RDATA first index after "
		     "inserting RDATA to RRSet.\n");
		return 0;
	}
	
	if (rrset->rdata_indices[1] != data1_length + data2_length) {
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
	int ret = memcmp(rrset->rdata + data1_length, data2, data2_length);
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

static int test_rrset_add_rdata()
{
	/*
	 * This function is basically a wrapper around knot_rrset_create_rdata()
	 */
}

static int test_rrset_merge()
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

/*	for (int i = 0; i < 4; i++) {
		knot_rdata_dump(&RR_RDATA[i], 2, 1);
		printf("%p %p\n", &RR_RDATA[i], (&RR_RDATA)[i]->next);
	} */

	create_rdata();

	res = test_rrset_create();
	ok(res, "rrset: create");
	res_final *= res;

	skip(!res, 11);

	todo();

	ok(res = test_rrset_delete(), "rrset: delete");
	//res_final *= res;

	endtodo;

	ok(res = test_rrset_getters(0), "rrset: owner");
	res_final *= res;

	ok(res = test_rrset_getters(1), "rrset: type");
	res_final *= res;

	ok(res = test_rrset_getters(2), "rrset: class");
	res_final *= res;

	ok(res = test_rrset_getters(3), "rrset: ttl");
	res_final *= res;

	ok(res = test_rrset_getters(4), "rrset: rdata");
	res_final *= res;

	ok(res = test_rrset_getters(5), "rrset: get rdata");
	res_final *= res;

	ok(res = test_rrset_getters(6), "rrset: rrsigs");
	res_final *= res;

	ok(res = test_rrset_add_rdata(), "rrset: add_rdata");
	res_final *= res;

	ok(res = test_rrset_rrsigs(), "rrset: rrsigs manipulation");
	res_final *= res;

	ok(res = test_rrset_merge(), "rrset: rdata merging");
	res_final *= res;

	ok(res = test_rrset_deep_free(), "rrset: deep free");
	res_final *= res;

	endskip;	/* !res_create */

	return res_final;
}
