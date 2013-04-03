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

#include "tests/libknot/rrset_tests.h"
#include "common/descriptor.h"
#include "common/errcode.h"
#include "common/print.h"
#include "libknot/rrset.h"
#include "libknot/util/wire.h"
#include "common/mempattern.h"

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
	TEST_RRSET_COUNT = 13,
	TEST_RDATA_COUNT = 10,
	TEST_DNAME_COUNT = 11,
	TEST_RDATA_A_LESS = 0,
	TEST_RDATA_A_GT = 1,
	TEST_RDATA_NS_LESS = 2,
	TEST_RDATA_NS_GT = 3,
	TEST_RDATA_MX_DNAME_LESS = 4,
	TEST_RDATA_MX_DNAME_GT = 5,
	TEST_RDATA_MX_BIN_LESS = 6,
	TEST_RDATA_MX_BIN_GT = 7,
	TEST_RDATA_MINFO1 = 8,
	TEST_RDATA_MINFO2 = 9,
	TEST_RRSET_A_LESS = 0,
	TEST_RRSET_A_GT = 1,
	TEST_RRSET_MERGE_UNIQUE1 = 0,
	TEST_RRSET_MERGE_UNIQUE2 = 1,
	TEST_RRSET_MERGE_RESULT1 = 10,
	TEST_RRSET_NS_LESS = 2,
	TEST_RRSET_NS_GT = 3,
	TEST_RRSET_MX_BIN_LESS = 4,
	TEST_RRSET_MX_BIN_GT = 5,
	TEST_RRSET_MX_DNAME_LESS = 6,
	TEST_RRSET_MX_DNAME_GT = 7,
	TEST_RRSET_MINFO = 8,
	TEST_RRSET_MINFO_MULTIPLE = 9,
	TEST_RRSET_OWNER_LESS = 11,
	TEST_RRSET_OWNER_GT = 12,
	CHECK_LAST_INDEX = 0,
	OMMIT_LAST_INDEX = 1,
	TEST_DNAME_GENERIC = 0,
	TEST_DNAME_LESS = 1,
	TEST_DNAME_GREATER = 2
};

static char *test_dname_strings[TEST_DNAME_COUNT] = {
	"a.dname.com.",
	"b.dname.com.",
	"c.dname.com.",
	"d.dname.com.",
	"e.dname.com.",
	"f.dname.com.",
	"ns1.nic.cz.",
	"ns2.nic.cz.",
	"ns3.nic.cz.",
	"ns4.nic.cz.",
	"ns5.nic.cz."
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
	int owner_id;
	knot_rrset_t rrset;
	uint8_t *header_wire;
	size_t header_wire_size;
	uint8_t *rdata_wire;
	size_t rdata_wire_size;
	size_t rr_count;
	int test_rdata_ids[16];
	test_rdata_t **test_rdata;
};

typedef struct test_rrset test_rrset_t;

/* Artificial RDATA definitions: */
static test_rdata_t test_rdata_array[TEST_RDATA_COUNT] = {
	[TEST_RDATA_A_LESS] = {(uint8_t *)"\x1\x1\x1\0", (uint8_t *)"\x1\x1\x1\0", 4, 4},
	[TEST_RDATA_A_GT] = {(uint8_t *)"\x1\x1\x1\1", (uint8_t *)"\x1\x1\x1\1", 4, 4},
	[TEST_RDATA_NS_LESS] = {NULL, NULL, sizeof(knot_dname_t *), 0},
	[TEST_RDATA_NS_GT] = {NULL, NULL, sizeof(knot_dname_t *), 0},
	[TEST_RDATA_MX_DNAME_LESS] = {NULL, NULL, sizeof(knot_dname_t *) + 2, 0},
	[TEST_RDATA_MX_DNAME_GT] = {NULL, NULL, sizeof(knot_dname_t *) + 2, 0},
	[TEST_RDATA_MX_BIN_LESS] = {NULL, NULL, sizeof(knot_dname_t *) + 2, 0},
	[	TEST_RDATA_MX_BIN_GT] = {NULL, NULL, sizeof(knot_dname_t *) + 2, 0},
	[TEST_RDATA_MINFO1] = {NULL, NULL, sizeof(knot_dname_t *) * 2, 0},
	[TEST_RDATA_MINFO2] = {NULL, NULL, sizeof(knot_dname_t *) * 2, 0}
};


test_rrset_t test_rrset_array[TEST_RRSET_COUNT] = {
	 [TEST_RRSET_A_LESS] = {TEST_DNAME_GENERIC, {NULL, KNOT_RRTYPE_A, KNOT_CLASS_IN, 3600, NULL, NULL, 0, NULL},
          NULL, 0, NULL, 0, 1, {TEST_RDATA_A_LESS}, NULL},
	 [TEST_RRSET_A_GT] = {TEST_DNAME_GENERIC, {NULL, KNOT_RRTYPE_A, KNOT_CLASS_IN, 3600, NULL, NULL, 0, NULL},
          NULL, 0, NULL, 0, 1, {TEST_RDATA_A_GT}, NULL},
	 [TEST_RRSET_NS_LESS] = {TEST_DNAME_GENERIC, {NULL, KNOT_RRTYPE_NS, KNOT_CLASS_IN, 3600, NULL, NULL, 0, NULL},
          NULL, 0, NULL, 0, 1, {TEST_RDATA_NS_LESS}, NULL},
	 [TEST_RRSET_NS_GT] = {TEST_DNAME_GENERIC, {NULL, KNOT_RRTYPE_NS, KNOT_CLASS_IN, 3600, NULL, NULL, 0, NULL},
          NULL, 0, NULL, 0, 1, {TEST_RDATA_NS_GT}, NULL},
	 [TEST_RRSET_MX_DNAME_LESS] = {TEST_DNAME_GENERIC, {NULL, KNOT_RRTYPE_MX, KNOT_CLASS_IN, 3600, NULL, NULL, 0, NULL},
          NULL, 0, NULL, 0, 1, {TEST_RDATA_MX_DNAME_LESS}, NULL},
	 [TEST_RRSET_MX_DNAME_GT] = {TEST_DNAME_GENERIC, {NULL, KNOT_RRTYPE_MX, KNOT_CLASS_IN, 3600, NULL, NULL, 0, NULL},
          NULL, 0, NULL, 0, 1, {TEST_RDATA_MX_DNAME_GT}, NULL},
	 [TEST_RRSET_MX_BIN_LESS] = {TEST_DNAME_GENERIC, {NULL, KNOT_RRTYPE_MX, KNOT_CLASS_IN, 3600, NULL, NULL, 0, NULL},
          NULL, 0, NULL, 0, 1, {TEST_RDATA_MX_BIN_LESS}, NULL},
	 [TEST_RRSET_MX_BIN_GT] = {TEST_DNAME_GENERIC, {NULL, KNOT_RRTYPE_MX, KNOT_CLASS_IN, 3600, NULL, NULL, 0, NULL},
          NULL, 0, NULL, 0, 1, {TEST_RDATA_MX_BIN_GT}, NULL},
	 [TEST_RRSET_MINFO] = {TEST_DNAME_GENERIC, {NULL, KNOT_RRTYPE_MINFO, KNOT_CLASS_IN, 3600, NULL, NULL, 0, NULL},
          NULL, 0, NULL, 0, 1, {TEST_RDATA_MINFO1}, NULL},
	 [TEST_RRSET_MINFO_MULTIPLE] = {TEST_DNAME_GENERIC, {NULL, KNOT_RRTYPE_MINFO, KNOT_CLASS_IN, 3600, NULL, NULL, 0, NULL},
          NULL, 0, NULL, 0, 2, {TEST_RDATA_MINFO1, TEST_RDATA_MINFO2}, NULL},
	 [TEST_RRSET_MERGE_RESULT1] = {TEST_DNAME_GENERIC, {NULL, KNOT_RRTYPE_A, KNOT_CLASS_IN, 3600, NULL, NULL, 0, NULL},
          NULL, 0, NULL, 0, 2, {TEST_RDATA_A_LESS, TEST_RDATA_A_GT}, NULL},
	 [TEST_RRSET_OWNER_LESS] = {TEST_DNAME_LESS, {NULL, KNOT_RRTYPE_A, KNOT_CLASS_IN, 3600, NULL, NULL, 0, NULL},
          NULL, 0, NULL, 0, 1, {TEST_RDATA_A_LESS}, NULL},
	 [TEST_RRSET_OWNER_GT] = {TEST_DNAME_GREATER, {NULL, KNOT_RRTYPE_A, KNOT_CLASS_IN, 3600, NULL, NULL, 0, NULL},
          NULL, 0, NULL, 0, 1, {TEST_RDATA_A_LESS}, NULL}
};

static void create_test_dnames()
{
	for (int i = 0; i < TEST_DNAME_COUNT; i++) {
		test_dnames[i] =
			knot_dname_new_from_str(test_dname_strings[i],
		                                strlen(test_dname_strings[i]),
		                                NULL);
	}
}

static void create_test_rdata()
{
	/* NS, MX and MINFO types need init. */
	/* TODO use tmp variables, this is too big. This needs a rewrite, but i'm too tired now. */
	test_rdata_array[TEST_RDATA_NS_LESS].rdata =
		xmalloc(sizeof(knot_dname_t *));
	memcpy(test_rdata_array[TEST_RDATA_NS_LESS].rdata, &test_dnames[0],
	       sizeof(knot_dname_t *));
	test_rdata_array[TEST_RDATA_NS_LESS].wire =
		xmalloc(test_dnames[0]->size);
	memcpy(test_rdata_array[TEST_RDATA_NS_LESS].wire, test_dnames[0]->name,
	       test_dnames[0]->size);
	test_rdata_array[TEST_RDATA_NS_LESS].wire_size = test_dnames[0]->size;
	test_rdata_array[TEST_RDATA_NS_LESS].size = sizeof(knot_dname_t *);
	
	
	test_rdata_array[TEST_RDATA_NS_GT].rdata =
		xmalloc(sizeof(knot_dname_t *));
	memcpy(test_rdata_array[TEST_RDATA_NS_GT].rdata, &test_dnames[0],
	       sizeof(knot_dname_t *));
	test_rdata_array[TEST_RDATA_NS_GT].wire =
		xmalloc(test_dnames[0]->size);
	memcpy(test_rdata_array[TEST_RDATA_NS_GT].wire, test_dnames[0]->name,
	       test_dnames[0]->size);
	test_rdata_array[TEST_RDATA_NS_GT].wire_size = test_dnames[0]->size;
	test_rdata_array[TEST_RDATA_NS_GT].size = sizeof(knot_dname_t *);
	
	
	test_rdata_array[TEST_RDATA_MX_DNAME_LESS].rdata =
		xmalloc(2 + sizeof(knot_dname_t *));
	uint16_t id = 10;
	knot_wire_write_u16(test_rdata_array[TEST_RDATA_MX_DNAME_LESS].rdata, id);
	memcpy(test_rdata_array[TEST_RDATA_MX_DNAME_LESS].rdata + 2, &test_dnames[0],
	       sizeof(knot_dname_t *));
	test_rdata_array[TEST_RDATA_MX_DNAME_LESS].wire =
		xmalloc(test_dnames[0]->size + 2);
	knot_wire_write_u16(test_rdata_array[TEST_RDATA_MX_DNAME_LESS].wire, id);
	memcpy(test_rdata_array[TEST_RDATA_MX_DNAME_LESS].wire + 2,
	       test_dnames[0]->name, test_dnames[0]->size);
	test_rdata_array[TEST_RDATA_MX_DNAME_LESS].wire_size = test_dnames[0]->size + 2;
	test_rdata_array[TEST_RDATA_MX_DNAME_LESS].size = sizeof(knot_dname_t *) + 2;
	
	
	test_rdata_array[TEST_RDATA_MX_DNAME_GT].rdata =
		xmalloc(2 + sizeof(knot_dname_t *));
	id = 10;
	knot_wire_write_u16(test_rdata_array[TEST_RDATA_MX_DNAME_GT].rdata, id);
	memcpy(test_rdata_array[TEST_RDATA_MX_DNAME_GT].rdata + 2, &test_dnames[1],
	       sizeof(knot_dname_t *));
	test_rdata_array[TEST_RDATA_MX_DNAME_GT].wire =
		xmalloc(test_dnames[1]->size + 2);
	knot_wire_write_u16(test_rdata_array[TEST_RDATA_MX_DNAME_GT].wire, id);
	memcpy(test_rdata_array[TEST_RDATA_MX_DNAME_GT].wire + 2,
	       test_dnames[0]->name, test_dnames[1]->size);
	test_rdata_array[TEST_RDATA_MX_DNAME_GT].wire_size = test_dnames[1]->size + 2;
	test_rdata_array[TEST_RDATA_MX_DNAME_GT].size = sizeof(knot_dname_t *) + 2;
	
	
	test_rdata_array[TEST_RDATA_MX_BIN_LESS].rdata =
		xmalloc(2 + sizeof(knot_dname_t *));
	id = 10;
	knot_wire_write_u16(test_rdata_array[TEST_RDATA_MX_BIN_LESS].rdata, id);
	memcpy(test_rdata_array[TEST_RDATA_MX_BIN_LESS].rdata + 2, &test_dnames[2],
	       sizeof(knot_dname_t *));
	test_rdata_array[TEST_RDATA_MX_BIN_LESS].wire =
		xmalloc(test_dnames[0]->size + 2);
	knot_wire_write_u16(test_rdata_array[TEST_RDATA_MX_BIN_LESS].wire, id);
	memcpy(test_rdata_array[TEST_RDATA_MX_BIN_LESS].wire + 2,
	       test_dnames[0]->name, test_dnames[0]->size);
	test_rdata_array[TEST_RDATA_MX_BIN_LESS].wire_size = test_dnames[0]->size + 2;
	test_rdata_array[TEST_RDATA_MX_BIN_LESS].size = sizeof(knot_dname_t *) + 2;
	
	
	test_rdata_array[TEST_RDATA_MX_BIN_GT].rdata =
		xmalloc(2 + sizeof(knot_dname_t *));
	id = 20;
	knot_wire_write_u16(test_rdata_array[TEST_RDATA_MX_BIN_GT].rdata, id);
	memcpy(test_rdata_array[TEST_RDATA_MX_BIN_GT].rdata + 2, &test_dnames[2],
	       sizeof(knot_dname_t *));
	test_rdata_array[TEST_RDATA_MX_BIN_GT].wire =
		xmalloc(test_dnames[0]->size + 2);
	knot_wire_write_u16(test_rdata_array[TEST_RDATA_MX_BIN_GT].wire, id);
	memcpy(test_rdata_array[TEST_RDATA_MX_BIN_GT].wire + 2,
	       test_dnames[0]->name, test_dnames[0]->size);
	test_rdata_array[TEST_RDATA_MX_BIN_GT].wire_size = test_dnames[0]->size + 2;
	test_rdata_array[TEST_RDATA_MX_BIN_GT].size = sizeof(knot_dname_t *) + 2;
	
	test_rdata_array[TEST_RDATA_MINFO1].rdata =
		xmalloc(sizeof(knot_dname_t *) * 2);
	memcpy(test_rdata_array[TEST_RDATA_MINFO1].rdata, &test_dnames[0],
	       sizeof(knot_dname_t *));
	memcpy(test_rdata_array[TEST_RDATA_MINFO1].rdata + sizeof(knot_dname_t *),
	       &test_dnames[1], sizeof(knot_dname_t *));
	test_rdata_array[TEST_RDATA_MINFO1].wire =
		xmalloc(test_dnames[0]->size + test_dnames[1]->size);
	memcpy(test_rdata_array[TEST_RDATA_MINFO1].wire, test_dnames[0]->name,
	       test_dnames[0]->size);
	memcpy(test_rdata_array[TEST_RDATA_MINFO1].wire + test_dnames[0]->size,
	       test_dnames[1]->name, test_dnames[1]->size);
	test_rdata_array[TEST_RDATA_MINFO1].wire_size =
		test_dnames[0]->size + test_dnames[1]->size;
	test_rdata_array[TEST_RDATA_MINFO1].size = sizeof(knot_dname_t *) * 2;
	
	test_rdata_array[TEST_RDATA_MINFO2].rdata =
		xmalloc(sizeof(knot_dname_t *) * 2);
	memcpy(test_rdata_array[TEST_RDATA_MINFO2].rdata, &test_dnames[2],
	       sizeof(knot_dname_t *));
	memcpy(test_rdata_array[TEST_RDATA_MINFO2].rdata + sizeof(knot_dname_t *),
	       &test_dnames[3], sizeof(knot_dname_t *));
	test_rdata_array[TEST_RDATA_MINFO2].wire =
		xmalloc(test_dnames[2]->size + test_dnames[3]->size);
	memcpy(test_rdata_array[TEST_RDATA_MINFO2].wire, test_dnames[0]->name,
	       test_dnames[0]->size);
	memcpy(test_rdata_array[TEST_RDATA_MINFO2].wire + test_dnames[2]->size,
	       test_dnames[3]->name, test_dnames[3]->size);
	test_rdata_array[TEST_RDATA_MINFO2].wire_size =
		test_dnames[2]->size + test_dnames[3]->size;
	test_rdata_array[TEST_RDATA_MINFO2].size = sizeof(knot_dname_t *) * 2;
	
	/* TODO Quick fix, remove */
	knot_dname_retain(test_dnames[0]);
	knot_dname_retain(test_dnames[0]);
	knot_dname_retain(test_dnames[0]);
	knot_dname_retain(test_dnames[0]);
	knot_dname_retain(test_dnames[0]);
	knot_dname_retain(test_dnames[0]);
	knot_dname_retain(test_dnames[1]);
	knot_dname_retain(test_dnames[1]);
	knot_dname_retain(test_dnames[1]);
	knot_dname_retain(test_dnames[1]);
	knot_dname_retain(test_dnames[1]);
	knot_dname_retain(test_dnames[2]);
	knot_dname_retain(test_dnames[2]);
	knot_dname_retain(test_dnames[2]);
	knot_dname_retain(test_dnames[2]);
	knot_dname_retain(test_dnames[3]);
	knot_dname_retain(test_dnames[3]);
	knot_dname_retain(test_dnames[3]);
	knot_dname_retain(test_dnames[3]);
	knot_dname_retain(test_dnames[3]);
	knot_dname_retain(test_dnames[3]);
	knot_dname_retain(test_dnames[3]);
}

static void create_test_rrsets()
{
	for (int i = 0; i < TEST_RRSET_COUNT; i++) {
		test_rrset_t *test_rrset = &test_rrset_array[i];
		/* Assign owner. */
		test_rrset->rrset.owner = test_dnames[test_rrset->owner_id];
		/* Create header wire. */
		test_rrset->header_wire_size = test_rrset->rrset.owner->size + 8 + 2;
		test_rrset->header_wire =
			xmalloc(test_rrset->header_wire_size);
		/* Copy owner wire to header wire. */
		memcpy(test_rrset->header_wire, test_rrset->rrset.owner->name,
		       test_rrset->rrset.owner->size);
		/* Copy type to wire. */
		size_t offset = test_rrset->rrset.owner->size;
		knot_wire_write_u16(test_rrset->header_wire + offset,
		                    test_rrset->rrset.type);
		offset += sizeof(uint16_t);
		/* Copy class to wire. */
		knot_wire_write_u16(test_rrset->header_wire + offset,
		                    test_rrset->rrset.rclass);
		offset += sizeof(uint16_t);
		/* Copy TTL to wire. */
		knot_wire_write_u32(test_rrset->header_wire + offset,
		                    test_rrset->rrset.ttl);
		offset += sizeof(uint32_t);
		uint16_t rdlength = 0;
		test_rrset->test_rdata =
			xmalloc(sizeof(void *) * test_rrset->rr_count);
		size_t actual_length = 0;
		test_rrset->rrset.rdata_count = test_rrset->rr_count;
		/* TODO all thing below into a cycle. */
		for (int j = 0; j < test_rrset->rr_count; j++) {
			test_rrset->test_rdata[j] = &test_rdata_array[test_rrset->test_rdata_ids[j]];
			rdlength += test_rrset->test_rdata[j]->wire_size;
			actual_length += test_rrset->test_rdata[j]->size;
		}
		/* Copy RDLENGTH to wire. */
		knot_wire_write_u16(test_rrset->header_wire + offset,
		                    rdlength);
		/* Assign RDATA (including indices). */
		offset = 0;
		test_rrset->rrset.rdata = xmalloc(actual_length);
		test_rrset->rdata_wire = xmalloc(rdlength + (test_rrset->rr_count * test_rrset->header_wire_size));
		test_rrset->rdata_wire_size = rdlength;
		test_rrset->rrset.rdata_indices =
			xmalloc(sizeof(uint32_t) * test_rrset->rr_count);
		for (int j = 0; j < test_rrset->rr_count; j++) {
			if (j > 0) {
				test_rrset->rrset.rdata_indices[j - 1] =
					test_rrset->test_rdata[j]->size;
			}
			
			memcpy(test_rrset->rrset.rdata + offset,
			       test_rrset->test_rdata[j]->rdata,
			       test_rrset->test_rdata[j]->size);
			offset += test_rrset->test_rdata[j]->size;
		}
		/* Store sum of indices to the last index. */
		test_rrset->rrset.rdata_indices[test_rrset->rr_count - 1] =
			offset;
		/* Store RDATA wire. */
		offset = 0;
		for (int j = 0; j < test_rrset->rr_count; j++) {
			memcpy(test_rrset->rdata_wire + offset,
			       test_rrset->test_rdata[j]->wire,
			       test_rrset->test_rdata[j]->wire_size);
			offset += test_rrset->test_rdata[j]->wire_size;
		}
		assert(offset == rdlength);
	}
}

static int check_rrset_values(const knot_rrset_t *rrset,
                              knot_dname_t *dname, uint16_t type,
                              uint16_t rclass, uint16_t ttl, uint16_t rr_count)
{
	int errors = 0;
	
	if (knot_dname_compare_non_canon(rrset->owner, dname)) {
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
	knot_dname_t *dname = test_dnames[0];
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

static int test_rrset_create_rdata()
{
	/* Two cases need to be tested - empty RRSet and non-empty RRSet. */
	
	
	knot_rrset_t *rrset = knot_rrset_new(NULL, 0, 0, 0);
	assert(rrset);
	
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
	ret = memcmp(rrset->rdata + test_rdata_array[0].size,
	             test_rdata_array[1].rdata, test_rdata_array[1].size);
	if (ret) {
		diag("Wrong data inserted into RRSet.\n");
		return 0;
	}
	
	/* Test that data of length 0 are not inserted. */
	void *ret_ptr = knot_rrset_create_rdata(rrset, 0);
	if (ret_ptr != NULL) {
		diag("Empty RDATA inserted.\n");
		return 0;
	}
	
	return 1;
}

static int test_rrset_rdata_item_size()
{
	/* Test that types containing DNAMEs only return OK values. */
	knot_rrset_t *rrset =
		&test_rrset_array[TEST_RRSET_MINFO_MULTIPLE].rrset;
	if (rrset_rdata_item_size(rrset, 0) != sizeof(knot_dname_t *) * 2) {
		diag("Wrong item length read from RRSet (first item).\n");
		return 0;
	}
	
	if (rrset_rdata_item_size(rrset, 1) != sizeof(knot_dname_t *) * 2) {
		diag("Wrong item length read from RRSet (last item).\n");
		return 0;
	}
	
	if (rrset_rdata_size_total(rrset) != sizeof(knot_dname_t *) * 4) {
		diag("Wrong total size returned (MINFO RRSet)\n");
		return 0;
	}
	
	rrset = &test_rrset_array[TEST_RRSET_A_GT].rrset;
	if (rrset_rdata_item_size(rrset, 0) != 4) {
		diag("Wrong item length read from A RRSet.\n");
		return 0;
	}
	
        rrset = &test_rrset_array[TEST_RRSET_MX_BIN_GT].rrset;
        if (rrset_rdata_item_size(rrset, 0) != 2 + sizeof(knot_dname_t *)) {
            diag("Wrong item length read from A RRSet.\n");
            return 0;
        }
	
	knot_rrset_t *rrset1 = knot_rrset_new(rrset->owner,
	                                      KNOT_RRTYPE_TXT, KNOT_CLASS_IN,
	                                      3600);
	
	knot_rrset_create_rdata(rrset1, 16);
	knot_rrset_add_rdata(rrset1,
	                     (uint8_t *)"thesearesomedatathatdonotmatter", 25);
	knot_rrset_create_rdata(rrset1, 38);
	
	if (rrset_rdata_item_size(rrset1, 0) != 16) {
		diag("Wrong item lenght in read (first).\n");
		return 0;
	}
	
	if (rrset_rdata_item_size(rrset1, 1) != 25) {
		diag("Wrong item lenght in read (middle).\n");
		return 0;
	}
	
	if (rrset_rdata_item_size(rrset1, 2) != 38) {
		diag("Wrong item lenght in read (last).\n");
		return 0;
	}
	
	return 1;
}

static int test_rrset_get_rdata()
{
//	uint8_t *pointer = knot_rrset_get_rdata(rrset, 0);
//	if (pointer == NULL) {
//		diag("Could not ger RDATA from RRSet.\n");
//		return 0;
//	}
	
//	int ret = memcmp(pointer, RDATA_INIT_1, DATA1_LENGTH);
//	if (ret) {
//		diag("Got bad RDATA from RRSet.\n");
//		return 0;
//	}
	
//	pointer = knot_rrset_get_rdata(rrset, 1);
//	if (pointer == NULL) {
//		diag("Could not ger RDATA from RRSet.\n");
//		return 0;
//	}
	
//	ret = memcmp(pointer, RDATA_INIT_2, DATA2_LENGTH);
//	if (ret) {
//		diag("Got bad RDATA from RRSet.\n");
//		return 0;
//	}
	
	return 1;
}

static int test_rrset_shallow_copy()
{
	for (int i = 0; i < TEST_RRSET_COUNT; i++) {
		knot_rrset_t *rrset_copy = NULL;
		knot_rrset_t *rrset = &test_rrset_array[i].rrset;
		int ret = knot_rrset_shallow_copy(rrset,
		                                  &rrset_copy);
		if (ret != KNOT_EOK) {
			knot_rrset_free(&rrset_copy);
			diag("Could not copy RRSet.\n");
			return 0;
		}
	
		/* Check that created RRSet has the same as the old one. */
		int errors = check_rrset_values(rrset_copy, rrset->owner, rrset->type,
		                                rrset->rclass, rrset->ttl,
		                                rrset->rdata_count);
		if (errors) {
			knot_rrset_free(&rrset_copy);
			return 0;
		}
	
		/* Check that created RRSet has the same RDATA. */
		if (rrset->rdata != rrset_copy->rdata) {
			diag("RDATA in the new RRSet do not match.\n");
			knot_rrset_free(&rrset_copy);
			return 0;
		}
	
		/* Check that RDATA indices are the same. */
		if (rrset->rdata_indices != rrset_copy->rdata_indices) {
			diag("RDATA indices in the new RRSet do not match.\n");
			knot_rrset_free(&rrset_copy);
			return 0;
		}
	}
	
	return 1;
}

static int test_rrset_deep_copy()
{
	for (int i = 0; i < TEST_RRSET_COUNT; i++) {
		knot_rrset_t *rrset_copy = NULL;
		knot_rrset_t *rrset = &test_rrset_array[i].rrset;
		int ret = knot_rrset_deep_copy(rrset, &rrset_copy, 1);
		if (ret != KNOT_EOK) {
			diag("Could not copy RRSet.\n");
			return 0;
		}
	
		/* Check that created RRSet has the same as the old one. */
		int errors = check_rrset_values(rrset_copy, rrset->owner, rrset->type,
		                                rrset->rclass, rrset->ttl,
		                                rrset->rdata_count);
		if (errors) {
			knot_rrset_deep_free(&rrset_copy, 1, 1);
			return 0;
		}
	
		/* Check that RDATA indices contain the same data. */
		ret = memcmp(rrset->rdata_indices, rrset_copy->rdata_indices,
		             rrset->rdata_count);
		if (ret) {
			diag("Copied RRSet has different RDATA indices.\n");
			knot_rrset_deep_free(&rrset_copy, 1, 1);
			return 0;
		}
	
		/*
		 * Go through RDATA and compare blocks. Cannot compare the whole thing
		 * since DNAMEs are copied as well and will have different address.
		 */
		ret = knot_rrset_rdata_equal(rrset, rrset_copy);
		if (!ret) {
			diag("Copied RRSet has different RDATA.\n");
			knot_rrset_deep_free(&rrset_copy, 1, 1);
			return 0;
		}
		knot_rrset_deep_free(&rrset_copy, 1, 1);
	}
	
	return 1;
}

static int test_rrset_to_wire()
{
	size_t wire_size = 65535;
	uint8_t wire[wire_size];
	uint16_t rr_count = 0;
	int failed = 0;
	for (int i = 0; i < TEST_RRSET_COUNT; i++) {
		memset(wire, 0, wire_size);
		wire_size = 65535;
		/* Convert to wire. */
		int ret = knot_rrset_to_wire(&test_rrset_array[i].rrset, wire,
		                             &wire_size, 65535, &rr_count, NULL);
		if (ret) {
			diag("Could not convert RRSet to wire.\n");
			return 0;
		}
		
		/* Check that the header is OK. */
		ret = memcmp(wire, test_rrset_array[i].header_wire,
		             test_rrset_array[i].header_wire_size);
		if (ret) {
			diag("Header of RRSet %d is wrongly converted.\n",
			     i);
			return 0;
		}
		
		if (wire_size != test_rrset_array[i].rdata_wire_size +
		    test_rrset_array[i].header_wire_size) {
			diag("Wrong wire size, in RRSet=%d "
			     "(should be=%d, is=%d).\n", i,
			     test_rrset_array[i].rdata_wire_size +
			     test_rrset_array[i].header_wire_size, wire_size);
			failed = 1;
			continue;
		}
		
		/* Check that the RDATA are OK. */
		ret = memcmp(wire + test_rrset_array[i].header_wire_size,
		             test_rrset_array[i].rdata_wire,
		             test_rrset_array[i].rdata_wire_size);
		if (ret) {
			diag("RDATA of RRSet %d are wrongly converted.\n",
			     i);
			failed = 1;
			hex_print((char *)(wire + test_rrset_array[i].header_wire_size),
			          test_rrset_array[i].rdata_wire_size);
			hex_print((char *)(test_rrset_array[i].rdata_wire),
			          test_rrset_array[i].rdata_wire_size);
		}
	}
	
	/* Check that function does not crash if given small wire. */
	wire_size = 5; // even header does not fit
	int ret = knot_rrset_to_wire(&test_rrset_array[0].rrset, wire,
	                         &wire_size, 65535, &rr_count, NULL);
	if (ret != KNOT_ESPACE) {
		diag("RRSet was converted to wire even though twe wire was"
		     " not big enough.\n");
		return 0;
	}
	wire_size = 25; // even RDATA do not fit TODO check those values
	ret = knot_rrset_to_wire(&test_rrset_array[0].rrset, wire,
	                         &wire_size, 65335, &rr_count, NULL);
	if (ret != KNOT_ESPACE) {
		diag("RRSet was converted to wire even though twe wire was"
		     " not big enough.\n");
		return 0;
	}
	
	return !failed;
}

static int test_rrset_merge()
{
	knot_rrset_t *merge_to;
	knot_rrset_deep_copy(&test_rrset_array[TEST_RRSET_MERGE_UNIQUE1].rrset,
	                     &merge_to, 1);
	knot_rrset_t *merge_from;
	knot_rrset_deep_copy(&test_rrset_array[TEST_RRSET_MERGE_UNIQUE2].rrset,
	                     &merge_from, 1);
	assert(merge_to);
	assert(merge_from);
	int ret = knot_rrset_merge(merge_to, merge_from);
	if (ret != KNOT_EOK) {
		diag("Could not merge RRSets.\n");
		knot_rrset_deep_free(&merge_to, 1, 1);
		knot_rrset_deep_free(&merge_from, 1, 1);
		return 0;
	}
	
	//TODO check that merge operation does not cahgne second rr
	//TODO check that two RRSet that are not mergable will not merge
	if (!knot_rrset_equal(&test_rrset_array[TEST_RRSET_MERGE_UNIQUE2].rrset,
	                      merge_from,
	                      KNOT_RRSET_COMPARE_WHOLE)) {
		diag("Merge corrupted second RRSet.\n");
		return 0;
	}
	
	if (merge_to->rdata_count !=
	    test_rrset_array[TEST_RRSET_MERGE_UNIQUE1].rrset.rdata_count +
	    merge_from->rdata_count) {
		diag("Not all RDATA were merged.\n");
		knot_rrset_deep_free(&merge_to, 1, 1);
		knot_rrset_deep_free(&merge_from, 1, 1);
		return 0;
	}
	
	/* Check that the first RRSet now contains RDATA from the second. */
	/* Indices first. */
	ret = memcmp(merge_to->rdata_indices,
	             test_rrset_array[TEST_RRSET_MERGE_RESULT1].rrset.rdata_indices,
	             merge_to->rdata_count);
	if (ret) {
		diag("Merge operation corrupted the first RRSet's indices.\n");
		knot_rrset_deep_free(&merge_to, 1, 1);
		knot_rrset_deep_free(&merge_from, 1, 1);
		return 0;
	}
	
	/* Check actual RDATA. */
	ret = knot_rrset_rdata_equal(merge_to,
	                             &test_rrset_array[TEST_RRSET_MERGE_RESULT1].rrset);
	if (!ret) {
		diag("Merged RDATA are wrong.\n");
		knot_rrset_deep_free(&merge_to, 1, 1);
		knot_rrset_deep_free(&merge_from, 1, 1);
		return 0;
	}
	
	knot_rrset_deep_free(&merge_to, 1, 1);
	knot_rrset_deep_free(&merge_from, 1, 1);
	
	return 1;
}

static int test_rrset_merge_no_dupl()
{
	/* Test that merge of two identical RRSets results in no-op. */
	knot_rrset_t *merge_to = NULL;
	knot_rrset_deep_copy(&test_rrset_array[TEST_RRSET_MERGE_UNIQUE1].rrset,
	                     &merge_to, 1);
	knot_rrset_t *merge_from = NULL;
	knot_rrset_deep_copy(&test_rrset_array[TEST_RRSET_MERGE_UNIQUE1].rrset,
	                     &merge_from, 1);
	int merged, removed_rrs;
	int ret = knot_rrset_merge_no_dupl(merge_to, merge_from, &merged, &removed_rrs);
	if (ret != KNOT_EOK) {
		diag("Merge of identical RRSets failed.\n");
		return 0;
	}
	
	if (!knot_rrset_equal(&test_rrset_array[TEST_RRSET_MERGE_UNIQUE1].rrset,
	                      merge_to, KNOT_RRSET_COMPARE_WHOLE)) {
		diag("Merge corrupted first RRSet.\n");
		return 0;
	}
	
	if (!knot_rrset_equal(&test_rrset_array[TEST_RRSET_MERGE_UNIQUE1].rrset,
	                       merge_from, KNOT_RRSET_COMPARE_WHOLE)) {
		diag("Merge corrupted second RRSet.\n");
		return 0;
	}
	
	knot_rrset_deep_free(&merge_to, 1, 1);
	knot_rrset_deep_free(&merge_from, 1, 1);
	
	/* Merge normal, non-duplicated RRSets. */
	knot_rrset_deep_copy(&test_rrset_array[TEST_RRSET_MERGE_UNIQUE1].rrset,
	                     &merge_to, 1);
	knot_rrset_deep_copy(&test_rrset_array[TEST_RRSET_MERGE_UNIQUE2].rrset,
	                     &merge_from, 1);
	assert(merge_to);
	assert(merge_from);
	
	ret = knot_rrset_merge_no_dupl(merge_to, merge_from, &merged,
	                               &removed_rrs);
	if (ret != KNOT_EOK) {
		diag("Merge of identical RRSets failed.\n");
		return 0;
	}
	
	if (!knot_rrset_equal(&test_rrset_array[TEST_RRSET_MERGE_UNIQUE2].rrset,
	                      merge_from,
	                      KNOT_RRSET_COMPARE_WHOLE)) {
		diag("Merge corrupted second RRSet.\n");
		return 0;
	}
	
	if (!knot_rrset_equal(&test_rrset_array[TEST_RRSET_MERGE_RESULT1].rrset,
	                      merge_to,
	                      KNOT_RRSET_COMPARE_WHOLE)) {
		diag("Merge did not create correct RDATA.\n");
		return 0;
	}
	
	knot_rrset_deep_free(&merge_to, 1, 1);
	knot_rrset_deep_free(&merge_from, 1, 1);
	
	/* Merge RRSets with both duplicated and unique RDATAs. */
	knot_rrset_deep_copy(&test_rrset_array[TEST_RRSET_MERGE_UNIQUE1].rrset,
	                     &merge_to, 1);
	knot_rrset_deep_copy(&test_rrset_array[TEST_RRSET_MERGE_RESULT1].rrset,
	                     &merge_from, 1);
	assert(merge_to);
	assert(merge_from);
	
	ret = knot_rrset_merge_no_dupl(merge_to, merge_from, &merged,
	                               &removed_rrs);
	if (ret != KNOT_EOK) {
		diag("Merge of identical RRSets failed.\n");
		return 0;
	}
	
	if (!knot_rrset_equal(&test_rrset_array[TEST_RRSET_MERGE_RESULT1].rrset,
	                      merge_from,
	                      KNOT_RRSET_COMPARE_WHOLE)) {
		diag("Merge corrupted second RRSet.\n");
		return 0;
	}
	
	if (!knot_rrset_equal(&test_rrset_array[TEST_RRSET_MERGE_RESULT1].rrset,
	                      merge_to,
	                      KNOT_RRSET_COMPARE_WHOLE)) {
		diag("Merge did not create correct RDATA.\n");
		return 0;
	}
	
	knot_rrset_deep_free(&merge_to, 1, 1);
	knot_rrset_deep_free(&merge_from, 1, 1);
	
	return 1;
}

static int test_rrset_compare_rdata()
{
	/* TODO the test is written, but the function is not. */
//	/* Comparing different RDATA types should result in EINVAL. */
//	knot_rrset_t *rrset1 = &test_rrset_array[TEST_RRSET_A_LESS].rrset;
//	knot_rrset_t *rrset2 = &test_rrset_array[TEST_RRSET_NS_GT].rrset;
	
//	if (knot_rrset_compare_rdata(rrset1, rrset2) != KNOT_EINVAL) {
//		diag("rrset_compare_rdata() did comparison when it "
//		     "shouldn't have.\n");
//		return 0;
//	}
	
//	/* Equal - raw data only. */
//	rrset1 = &test_rrset_array[TEST_RRSET_A_LESS].rrset;
//	knot_rrset_deep_copy(&test_rrset_array[TEST_RRSET_A_LESS].rrset,
//	                     &rrset2, 1);
	
//	assert(rrset1->type == rrset2->type);
	
//	if (knot_rrset_compare_rdata(rrset1, rrset2) != 0) {
//		diag("rrset_compare_rdata() returned wrong "
//		     "value, should be 0. (raw data) %d %d\n",
//		     rrset1->type, rrset2->type);
//		return 0;
//	}
	
//	knot_rrset_deep_free(&rrset2, 1, 1);
	
//	/* Equal - DNAME only. */
//	rrset1 = &test_rrset_array[TEST_RRSET_NS_LESS].rrset;
//	knot_rrset_deep_copy(&test_rrset_array[TEST_RRSET_NS_LESS].rrset,
//	                     &rrset2, 1);
	
//	if (knot_rrset_compare_rdata(rrset1, rrset2) != 0) {
//		diag("rrset_compare_rdata() returned wrong "
//		     "value, should be 0. (DNAME only)\n");
//		knot_rrset_deep_free(&rrset2, 1, 1);
//		return 0;
//	}
	
//	knot_rrset_deep_free(&rrset2, 1, 1);
	
//	/* Equal - combination. */
//	rrset1 = &test_rrset_array[TEST_RRSET_MX_BIN_LESS].rrset;
//	knot_rrset_deep_copy(&test_rrset_array[TEST_RRSET_MX_BIN_LESS].rrset,
//	                     &rrset2, 1);
	
//	if (knot_rrset_compare_rdata(rrset1, rrset2) != 0) {
//		diag("rrset_compare_rdata() returned wrong "
//		     "value, should be 0. (combination)\n");
//		knot_rrset_deep_free(&rrset2, 1, 1);
//		return 0;
//	}
	
//	knot_rrset_deep_free(&rrset2, 1, 1);
	
//	/* Smaller - raw data only. */
//	rrset1 = &test_rrset_array[TEST_RRSET_A_LESS].rrset;
//	rrset2 = &test_rrset_array[TEST_RRSET_A_GT].rrset;
	
//	if (knot_rrset_compare_rdata(rrset1, rrset2) >= 0) {
//		diag("rrset_compare_rdata() returned wrong "
//		     "value, should be -1. (raw data only)\n");
//		return 0;
//	}
	
//	/* Greater - raw data only. */
//	if (knot_rrset_compare_rdata(rrset2, rrset1) <= 0) {
//		diag("rrset_compare_rdata() returned wrong "
//		     "value, should be 1. (raw data only)\n");
//		return 0;
//	}
	
//	/* Smaller - DNAME only. */
//	rrset1 = &test_rrset_array[TEST_RRSET_NS_LESS].rrset;
//	rrset2 = &test_rrset_array[TEST_RRSET_NS_GT].rrset;
	
//	if (knot_rrset_compare_rdata(rrset1, rrset2) >= 0) {
//		diag("rrset_compare_rdata() returned wrong "
//		     "value, should be -1. (DNAME only)\n");
//		return 0;
//	}
	
//	/* Greater - DNAME only. */
//	if (knot_rrset_compare_rdata(rrset2, rrset1) <= 0) {
//		diag("rrset_compare_rdata() returned wrong "
//		     "value, should be 1. (DNAME only)\n");
//		return 0;
//	}
	
//	/* Smaller - combination, difference in binary part. */
//	rrset1 = &test_rrset_array[TEST_RRSET_MX_BIN_LESS].rrset;
//	rrset2 = &test_rrset_array[TEST_RRSET_MX_BIN_GT].rrset;
	
//	if (knot_rrset_compare_rdata(rrset1, rrset2) >= 0) {
//		diag("rrset_compare_rdata() returned wrong "
//		     "value, should be -1. (combination)\n");
//		return 0;
//	}
	
//	/* Greater - combination, difference in binary part. */
//	if (knot_rrset_compare_rdata(rrset2, rrset1) <= 0) {
//		diag("rrset_compare_rdata() returned wrong "
//		     "value, should be 1. (combination)\n");
//		return 0;
//	}
	
//	/* Smaller - combination, difference in DNAME part. */
//	rrset1 = &test_rrset_array[TEST_RRSET_MX_DNAME_LESS].rrset;
//	rrset2 = &test_rrset_array[TEST_RRSET_MX_DNAME_GT].rrset;
	
//	if (knot_rrset_compare_rdata(rrset1, rrset2) >= 0) {
//		diag("rrset_compare_rdata() returned wrong "
//		     "value, should be -1. (combination)\n");
//		return 0;
//	}
	
//	/* Greater - combination, difference in DNAME part. */
//	if (knot_rrset_compare_rdata(rrset2, rrset1) <= 0) {
//		diag("rrset_compare_rdata() returned wrong "
//		     "value, should be 1. (combination)\n");
//		return 0;
//	}
	
	return 1;
}

static int test_rrset_compare()
{
	/* 
	 * In this test, we only care about non-RDATA comparisons, since RDATA 
	 * comparisons have been already tested in test_rrset_rdata_compare().
	 */
	
	/* Equal. */
	knot_rrset_t *rrset1 = &test_rrset_array[TEST_RRSET_A_LESS].rrset;
	knot_rrset_t *rrset2;
	knot_rrset_deep_copy(&test_rrset_array[TEST_RRSET_A_LESS].rrset,
	                     &rrset2, 1);
	
	if (knot_rrset_compare(rrset1, rrset2,
	                       KNOT_RRSET_COMPARE_HEADER) != 0) {
		diag("Wrong RRSet comparison, should be 0.\n");
		knot_rrset_deep_free(&rrset2, 1, 1);
		return 0;
	}
	
	knot_rrset_deep_free(&rrset2, 1, 1);
	
	/* Less. */
	rrset1 = &test_rrset_array[TEST_RRSET_A_LESS].rrset;
	rrset2 = &test_rrset_array[TEST_RRSET_NS_LESS].rrset;
	
	if (knot_rrset_compare(rrset1, rrset2,
	                       KNOT_RRSET_COMPARE_HEADER) >= 0) {
		diag("Wrong RRSet comparison, should be 0.\n");
		return 0;
	}
	
	/* Greater. */
	rrset1 = &test_rrset_array[TEST_RRSET_NS_LESS].rrset;
	rrset2 = &test_rrset_array[TEST_RRSET_A_LESS].rrset;
	
	if (knot_rrset_compare(rrset1, rrset2,
	                       KNOT_RRSET_COMPARE_HEADER) <= 0) {
		diag("Wrong RRSet comparison, should be 0.\n");
		knot_rrset_deep_free(&rrset2, 1, 1);
		return 0;
	}
	
	return 1;
}

static int test_rrset_equal()
{
	/* Test pointer comparison. */
	int ret = knot_rrset_equal((knot_rrset_t *)0xdeadbeef,
	                           (knot_rrset_t *)0xdeadbeef, 
	                           KNOT_RRSET_COMPARE_PTR);
	if (!ret) {
		diag("Pointer comparison failed (1).\n");
		return 0;
	}
	
	ret = knot_rrset_equal((knot_rrset_t *)0xdeadbeef, 
	                       (knot_rrset_t *)0xcafebabe,
	                        KNOT_RRSET_COMPARE_PTR);
	if (ret) {
		diag("Pointer comparison failed (0).\n");
		return 0;
	}
	
	/* Create equal RRSets. */
	knot_rrset_t *rrs1 = NULL;
	knot_rrset_deep_copy(&test_rrset_array[TEST_RRSET_A_GT].rrset, &rrs1, 1);
	knot_rrset_t *rrs2 = NULL;
	knot_rrset_deep_copy(&test_rrset_array[TEST_RRSET_A_GT].rrset, &rrs2, 1);
	/* Test header comparison. */
	ret = knot_rrset_equal(rrs1, rrs2, KNOT_RRSET_COMPARE_HEADER);
	if (!ret) {
		diag("Header comparison failed (Header equal).\n");
		return 0;
	}
	/* Change DNAME. */
	rrs1->owner = test_dnames[4];
	ret = knot_rrset_equal(rrs1, rrs2, KNOT_RRSET_COMPARE_HEADER);
	if (ret) {
		diag("Header comparison failed (DNAMEs different).\n");
		return 0;
	}
	rrs1->owner = test_dnames[0];
	/* Change CLASS. */
	rrs2->rclass = KNOT_CLASS_CH;
	ret = knot_rrset_equal(rrs1, rrs2, KNOT_RRSET_COMPARE_HEADER);
	if (ret) {
		diag("Header comparison failed (CLASSEs different).\n");
		return 0;
	}
	rrs2->rclass = KNOT_CLASS_IN;
	
	/* Test whole comparison. */
        ret = knot_rrset_equal(rrs1, rrs2, KNOT_RRSET_COMPARE_WHOLE);
        if (!ret) {
            diag("Whole comparison failed (Same RRSets).\n");
            return 0;
        }
	
	knot_rrset_deep_free(&rrs2, 1, 1);
	knot_rrset_deep_copy(&test_rrset_array[TEST_RRSET_A_LESS].rrset, &rrs2, 1);
        ret = knot_rrset_equal(rrs1, rrs2, KNOT_RRSET_COMPARE_WHOLE);
        if (ret) {
            diag("Whole comparison failed (Different RRSets).\n");
            return 0;
        }
	knot_rrset_deep_free(&rrs1, 1, 1);
	knot_rrset_deep_free(&rrs2, 1, 1);
	
	return 1;
}

static int test_rrset_rdata_equal()
{
	// TODO different order of RDATA
	return 0;
}

static int test_rrset_next_dname()
{
	/* Same test as in above, but we'll use multiple RRs within one SET. */
	knot_rrset_t *rrset = &test_rrset_array[TEST_RRSET_MINFO_MULTIPLE].rrset;
	knot_dname_t *extracted_dnames[4];
	extracted_dnames[0] = test_dnames[0];
	extracted_dnames[1] = test_dnames[1];
	extracted_dnames[2] = test_dnames[2];
	extracted_dnames[3] = test_dnames[3];
	knot_dname_t **dname = NULL;
	int i = 0;
	while ((dname = knot_rrset_get_next_dname(rrset, dname))) {
		if (knot_dname_compare_non_canon(extracted_dnames[i], *dname)) {
			diag("Got wrong DNAME from RDATA. on index %d\n", i);
			diag("DNAME should be %s, but was %s (%p - %p)\n",
			     knot_dname_to_str(extracted_dnames[i]), knot_dname_to_str(*dname),
			     extracted_dnames[i], *dname);
			return 0;
		}
		i++;
	}
	
	if (i != 4) {
		diag("Not all DNAMEs were extracted (%d out of 4).\n",
		     i);
		return 0;
	}
	
	/* Now try NS. */
	rrset = &test_rrset_array[TEST_RRSET_NS_GT].rrset;
	dname = NULL;
	dname = knot_rrset_get_next_dname(rrset, dname);
	if (knot_dname_compare_non_canon(*dname, test_dnames[TEST_DNAME_GENERIC])) {
		diag("Got wrong DNAME from NS RDATA. on index %d\n", i);
		return 0;
	}
	dname = knot_rrset_get_next_dname(rrset, dname);
	if (dname != NULL) {
		diag("Got DNAME from RRSet even though all had been extracted previously. (NS)\n");
		return 0;
	}
	/* Now try MX. */
	rrset = &test_rrset_array[TEST_RRSET_MX_BIN_GT].rrset;
	dname = NULL;
	dname = knot_rrset_get_next_dname(rrset, dname);
	if (knot_dname_compare_non_canon(*dname, test_dnames[2])) {
		diag("Got wrong DNAME from NS RDATA. on index %d\n", i);
		return 0;
	}
	dname = knot_rrset_get_next_dname(rrset, dname);
	if (dname != NULL) {
		diag("Got DNAME from RRSet even though all had been extracted previously. (MX)\n");
		return 0;
	}
	
	/* Try writes into DNAMEs you've gotten. */
	knot_rrset_deep_copy(&test_rrset_array[TEST_RRSET_MINFO_MULTIPLE].rrset,
	                     &rrset, 1);
	dname = NULL;
	i = 4;
	while ((dname = knot_rrset_get_next_dname(rrset, dname))) {
		knot_dname_free(dname);
		memcpy(dname, &test_dnames[i], sizeof(knot_dname_t *));
		i++;
	}
	
	if (i != 8) {
		diag("Not all DNAMEs were traversed (%d).\n", i);
		return 0;
	}
	
	knot_dname_t **dname_read = NULL;
	i = 4;
	while ((dname_read = knot_rrset_get_next_dname(rrset,
	                                               dname_read))) {
		if (*dname_read != test_dnames[i]) {
			diag("Rewriting of DNAMEs in RDATA was "
			     "not successful.\n");
			knot_rrset_deep_free(&rrset, 1, 1);
			return 0;
		}
		i++;
	}
	
	if (i != 8) {
		diag("Not all DNAMEs were traversed (%d).\n", i);
		return 0;
	}
	
	return 1;
}

static int test_rrset_find_pos()
{
	/* Create some mockup TXT RRSets. */
	knot_rrset_t *rrset_source = knot_rrset_new(test_dnames[0], KNOT_RRTYPE_TXT,
	                                            KNOT_CLASS_IN, 3600);
	uint8_t *mock_data = (uint8_t *)"cafebabebadcafecafecafecafe";
	/* Test removal of two exactly same items. */
	uint8_t *rdata = knot_rrset_create_rdata(rrset_source,
	                                          strlen((char *)mock_data));
	memcpy(rdata, mock_data, strlen((char *)mock_data));
	knot_rrset_t *rrset_find_in = NULL;
	knot_rrset_deep_copy(rrset_source, &rrset_find_in, 1);
	rdata = knot_rrset_create_rdata(rrset_source, 10);
	memcpy(rdata, mock_data ,10);
	size_t rr_pos = 0;
	int ret = knot_rrset_find_rr_pos(rrset_source, rrset_find_in, 0, &rr_pos);
	if (ret != KNOT_EOK) {
		knot_rrset_deep_free(&rrset_source, 1, 1);
		knot_rrset_deep_free(&rrset_find_in, 1, 1);
		diag("RR was not found, even though it should have been.");
		return 0;
	}
	if (rr_pos != 0) {
		knot_rrset_deep_free(&rrset_source, 1, 1);
		knot_rrset_deep_free(&rrset_find_in, 1, 1);
		diag("Wrong index returned. Should be 0, was %zu", rr_pos);
		return 0;
	}
	
	/* Add second RR. */
	knot_rrset_deep_free(&rrset_find_in, 1, 1);
	knot_rrset_shallow_copy(rrset_source, &rrset_find_in);
	knot_rrset_rdata_reset(rrset_find_in);
	rdata = knot_rrset_create_rdata(rrset_find_in, 10);
	memcpy(rdata, mock_data ,10);
	knot_rrset_dump(rrset_find_in);
	ret = knot_rrset_find_rr_pos(rrset_source, rrset_find_in, 1, &rr_pos);
	if (ret != KNOT_EOK) {
		diag("RR was not found, even though it should have been.");
		return 0;
	}
	if (rr_pos != 1) {
		diag("Wrong index returned. Should be 1, was %zu", rr_pos);
		return 0;
	}
	
	knot_rrset_deep_free(&rrset_source, 1, 1);
	knot_rrset_deep_free(&rrset_find_in, 1, 1);
	
	return 1;
}

static int test_rrset_remove_rr()
{
	/* Remove RR and test that the returned data were OK. */
	
	/* Create some mockup TXT RRSets. */
	knot_rrset_t *rrset_source = knot_rrset_new(test_dnames[0], KNOT_RRTYPE_TXT,
	                                            KNOT_CLASS_IN, 3600);
	uint8_t *mock_data = (uint8_t *)"cafebabebadcafecafecafecafe";
	/* Test removal of two exactly same items. */
	uint8_t *rdata = knot_rrset_create_rdata(rrset_source,
	                                         strlen((char *)mock_data));
	memcpy(rdata, mock_data, strlen((char *)mock_data));
	rdata = knot_rrset_create_rdata(rrset_source, 10);
	memcpy(rdata, mock_data ,10);
	knot_rrset_t *rrset_dest = NULL;
	/* Create copy. */
	knot_rrset_deep_copy(rrset_source, &rrset_dest, 1);
	rdata = knot_rrset_create_rdata(rrset_dest, 16);
	memcpy(rdata, "foobarfoobarfoo", 16);
	knot_rrset_t *returned_rr = NULL;
	int ret = knot_rrset_remove_rr_using_rrset(rrset_dest, rrset_source, &returned_rr, 0);
	if (ret != KNOT_EOK) {
		diag("Could not remove");
		knot_rrset_deep_free(&rrset_source, 1, 1);
		knot_rrset_deep_free(&returned_rr, 1, 1);
		return 0;
	}
	
	diag("Returned\n");
	knot_rrset_dump(returned_rr);
	diag("Source\n");
	knot_rrset_dump(rrset_source);
	diag("Destinantion\n");
	knot_rrset_dump(rrset_dest);

	/* Only one RR within RRSet, needs to be the same. */
	if (knot_rrset_equal(rrset_source, returned_rr,
	                     KNOT_RRSET_COMPARE_WHOLE)) {
		diag("Got wrong data in return rrset.");
		knot_rrset_deep_free(&rrset_source, 1, 1);
		knot_rrset_deep_free(&returned_rr, 1, 1);
		return 0;
	}
	
	knot_rrset_deep_free(&rrset_source, 1, 1);
	knot_rrset_deep_free(&rrset_dest, 1, 1);
	knot_rrset_deep_free(&returned_rr, 1, 1);
	
	return 1;
}

static const int KNOT_RRSET_TEST_COUNT = 16;

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

	create_test_dnames();
	create_test_rdata();
	create_test_rrsets();
	
	res = test_rrset_new();
	ok(res, "rrset: create");
	res_final *= res;
	
	res = test_rrset_create_rdata();
	ok(res, "rrset: create_rdata");
	res_final *= res;
	
	res = test_rrset_get_rdata();
	ok(res, "rrset: get rdata");
	res_final *= res;
	
	res = test_rrset_equal();
	ok(res, "rrset: rrset_equal");
	
	res = test_rrset_rdata_equal();
	ok(res, "rrset: rrset_rdata_equal");

	res = test_rrset_compare();
	ok(res, "rrset: rrset compare");
	res_final *= res;
	
	todo("WRITE THE FUNCTIONS");
	res = test_rrset_compare_rdata();
	ok(res, "rrset: rrset compare rdata");
	res_final *= res;
	endtodo;
	
	res = test_rrset_shallow_copy();
	ok(res, "rrset: shallow copy");
	res_final *= res;
	
	res = test_rrset_deep_copy();
	ok(res, "rrset: deep copy");
	res_final *= res;
	
	res = test_rrset_to_wire();
	ok(res, "rrset: to wire");
	res_final *= res;
	
	res = test_rrset_rdata_item_size();
	ok(res, "rrset: rdata_item_size");
	res_final *= res;
	
	res = test_rrset_merge();
	ok(res, "rrset: merge");
	res_final *= res;
	
	res = test_rrset_merge_no_dupl();
	ok(res, "rrset: merge no dupl");
	res_final *= res;
	
	res = test_rrset_next_dname();
	ok(res, "rrset: next dname");
	res_final *= res;
	
	res = test_rrset_remove_rr();
	ok(res, "rrset: remove rr");
	
	res = test_rrset_find_pos();
	ok(res, "rrset: find pos");
	res_final *= res;
	
	return res_final;
}
