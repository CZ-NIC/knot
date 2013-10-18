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
#include <config.h>
#include <assert.h>
#include <stdint.h>
#include <inttypes.h>
#include <tap/basic.h>

#include "common/descriptor.h"
#include "common/errcode.h"
#include "common/print.h"
#include "libknot/rrset.h"
#include "libknot/util/wire.h"
#include "common/mempattern.h"

#if 0
/*
 *  Unit implementation.
 */

enum rrset_test_const {
	TEST_RRSET_COUNT = 14,
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
	TEST_RRSET_MINFO_MULTIPLE1 = 9,
	TEST_RRSET_MINFO_MULTIPLE2 = 13,
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
	uint8_t *rdata; // RDATA in knot internal format
	uint8_t *wire; // RDATA in wireformat
	uint16_t size; // RDATA internal size
	uint16_t wire_size; // Wireformat size
};

typedef struct test_rdata test_rdata_t;

struct test_rrset {
	int owner_id; // Owners have to be dynamically allocated, IDs used to connect.
	knot_rrset_t rrset; // Dynamically created knot_rrset_t structure.
	uint8_t *header_wire; // Owner, class, TTL.
	size_t header_wire_size; // Header size.
	size_t rr_count; // RR count.
	int test_rdata_ids[16]; // RDATA IDs - will be used to assign RDATA.
	test_rdata_t **test_rdata; // Dynamically created test RDATA.
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
	[TEST_RDATA_MX_BIN_GT] = {NULL, NULL, sizeof(knot_dname_t *) + 2, 0},
	[TEST_RDATA_MINFO1] = {NULL, NULL, sizeof(knot_dname_t *) * 2, 0},
	[TEST_RDATA_MINFO2] = {NULL, NULL, sizeof(knot_dname_t *) * 2, 0},
};


test_rrset_t test_rrset_array[TEST_RRSET_COUNT] = {
	 [TEST_RRSET_A_LESS] = {TEST_DNAME_GENERIC, {NULL, KNOT_RRTYPE_A, KNOT_CLASS_IN, 3600, NULL, NULL, 0, NULL},
          NULL, 0, 1, {TEST_RDATA_A_LESS}, NULL},
	 [TEST_RRSET_A_GT] = {TEST_DNAME_GENERIC, {NULL, KNOT_RRTYPE_A, KNOT_CLASS_IN, 3600, NULL, NULL, 0, NULL},
          NULL, 0, 1, {TEST_RDATA_A_GT}, NULL},
	 [TEST_RRSET_NS_LESS] = {TEST_DNAME_GENERIC, {NULL, KNOT_RRTYPE_NS, KNOT_CLASS_IN, 3600, NULL, NULL, 0, NULL},
          NULL, 0, 1, {TEST_RDATA_NS_LESS}, NULL},
	 [TEST_RRSET_NS_GT] = {TEST_DNAME_GENERIC, {NULL, KNOT_RRTYPE_NS, KNOT_CLASS_IN, 3600, NULL, NULL, 0, NULL},
          NULL, 0, 1, {TEST_RDATA_NS_GT}, NULL},
	 [TEST_RRSET_MX_DNAME_LESS] = {TEST_DNAME_GENERIC, {NULL, KNOT_RRTYPE_MX, KNOT_CLASS_IN, 3600, NULL, NULL, 0, NULL},
          NULL, 0, 1, {TEST_RDATA_MX_DNAME_LESS}, NULL},
	 [TEST_RRSET_MX_DNAME_GT] = {TEST_DNAME_GENERIC, {NULL, KNOT_RRTYPE_MX, KNOT_CLASS_IN, 3600, NULL, NULL, 0, NULL},
          NULL, 0, 1, {TEST_RDATA_MX_DNAME_GT}, NULL},
	 [TEST_RRSET_MX_BIN_LESS] = {TEST_DNAME_GENERIC, {NULL, KNOT_RRTYPE_MX, KNOT_CLASS_IN, 3600, NULL, NULL, 0, NULL},
          NULL, 0, 1, {TEST_RDATA_MX_BIN_LESS}, NULL},
	 [TEST_RRSET_MX_BIN_GT] = {TEST_DNAME_GENERIC, {NULL, KNOT_RRTYPE_MX, KNOT_CLASS_IN, 3600, NULL, NULL, 0, NULL},
          NULL, 0, 1, {TEST_RDATA_MX_BIN_GT}, NULL},
	 [TEST_RRSET_MINFO] = {TEST_DNAME_GENERIC, {NULL, KNOT_RRTYPE_MINFO, KNOT_CLASS_IN, 3600, NULL, NULL, 0, NULL},
          NULL, 0, 1, {TEST_RDATA_MINFO1}, NULL},
	 [TEST_RRSET_MINFO_MULTIPLE1] = {TEST_DNAME_GENERIC, {NULL, KNOT_RRTYPE_MINFO, KNOT_CLASS_IN, 3600, NULL, NULL, 0, NULL},
          NULL, 0, 2, {TEST_RDATA_MINFO1, TEST_RDATA_MINFO2}, NULL},
	 [TEST_RRSET_MINFO_MULTIPLE2] = {TEST_DNAME_GENERIC, {NULL, KNOT_RRTYPE_MINFO, KNOT_CLASS_IN, 3600, NULL, NULL, 0, NULL},
          NULL, 0, 2, {TEST_RDATA_MINFO2, TEST_RDATA_MINFO1}, NULL},
	 [TEST_RRSET_MERGE_RESULT1] = {TEST_DNAME_GENERIC, {NULL, KNOT_RRTYPE_A, KNOT_CLASS_IN, 3600, NULL, NULL, 0, NULL},
          NULL, 0, 2, {TEST_RDATA_A_LESS, TEST_RDATA_A_GT}, NULL},
	 [TEST_RRSET_OWNER_LESS] = {TEST_DNAME_LESS, {NULL, KNOT_RRTYPE_A, KNOT_CLASS_IN, 3600, NULL, NULL, 0, NULL},
          NULL, 0, 1, {TEST_RDATA_A_LESS}, NULL},
	 [TEST_RRSET_OWNER_GT] = {TEST_DNAME_GREATER, {NULL, KNOT_RRTYPE_A, KNOT_CLASS_IN, 3600, NULL, NULL, 0, NULL},
          NULL, 0, 1, {TEST_RDATA_A_LESS}, NULL}
};

static void create_test_dnames()
{
	for (int i = 0; i < TEST_DNAME_COUNT; i++) {
		test_dnames[i] =
			knot_dname_from_str(test_dname_strings[i],
		                                strlen(test_dname_strings[i]));
	}
}

static void init_test_rdata_with_dname(uint8_t **rdata, uint16_t *rdata_size,
                                       uint8_t **wire, uint16_t *wire_size,
                                       size_t pos, size_t wire_pos,
                                       size_t alloc_size,
                                       size_t wire_alloc_size,
                                       knot_dname_t *dname)
{
	if (pos == 0) {
		*rdata = xmalloc(alloc_size);
		*rdata_size = 0;
		*wire = xmalloc(wire_alloc_size);
		*wire_size = 0;
	}
	memcpy(*rdata + pos, &dname, sizeof(knot_dname_t *));
	*rdata_size += sizeof(knot_dname_t *);
	memcpy(*wire + wire_pos, dname, knot_dname_size(dname));
	*wire_size += knot_dname_size(dname);
}

static void init_test_rdata_with_binary(uint8_t **rdata, uint16_t *rdata_size,
                                        uint8_t **wire, uint16_t *wire_size,
                                        size_t pos, size_t wire_pos,
                                        size_t alloc_size,
                                        size_t wire_alloc_size,
                                        const void *data, size_t data_size)
{
	if (pos == 0) {
		// New structure, allocate.
		*rdata = xmalloc(alloc_size);
		*rdata_size = 0;
		*wire = xmalloc(wire_alloc_size);
		*wire_size = 0;
	}
	memcpy(*rdata + pos, data, data_size);
	*rdata_size += data_size;
	memcpy(*wire + wire_pos, data, data_size);
	*wire_size += data_size;
}

static void create_test_rdata()
{
	/* NS, MX and MINFO types need an init. */

	/* NS RDATA DNAME = a.dname.com. */
	init_test_rdata_with_dname(&test_rdata_array[TEST_RDATA_NS_LESS].rdata,
	                           &test_rdata_array[TEST_RDATA_NS_LESS].size,
	                           &test_rdata_array[TEST_RDATA_NS_LESS].wire,
	                           &test_rdata_array[TEST_RDATA_NS_LESS].wire_size,
	                           0, 0, sizeof(knot_dname_t *),
	                           knot_dname_size(test_dnames[0]), test_dnames[0]);

	/* NS RDATA DNAME = b.dname.com. */
	init_test_rdata_with_dname(&test_rdata_array[TEST_RDATA_NS_GT].rdata,
	                           &test_rdata_array[TEST_RDATA_NS_GT].size,
	                           &test_rdata_array[TEST_RDATA_NS_GT].wire,
	                           &test_rdata_array[TEST_RDATA_NS_GT].wire_size,
	                           0, 0, sizeof(knot_dname_t *),
	                           knot_dname_size(test_dnames[1]), test_dnames[1]);

	/* MX RDATA - short = 10 DNAME = a.dname.com. */
	uint16_t id = htobe16(10);
	init_test_rdata_with_binary(&test_rdata_array[TEST_RDATA_MX_DNAME_LESS].rdata,
	                            &test_rdata_array[TEST_RDATA_MX_DNAME_LESS].size,
	                            &test_rdata_array[TEST_RDATA_MX_DNAME_LESS].wire,
	                            &test_rdata_array[TEST_RDATA_MX_DNAME_LESS].wire_size,
	                            0, 0, sizeof(knot_dname_t *) + 2,
	                            knot_dname_size(test_dnames[1]) + 2, &id, 2);

	init_test_rdata_with_dname(&test_rdata_array[TEST_RDATA_MX_DNAME_LESS].rdata,
	                           &test_rdata_array[TEST_RDATA_MX_DNAME_LESS].size,
	                           &test_rdata_array[TEST_RDATA_MX_DNAME_LESS].wire,
	                           &test_rdata_array[TEST_RDATA_MX_DNAME_LESS].wire_size,
	                           2, 2, sizeof(knot_dname_t *),
	                           knot_dname_size(test_dnames[1]), test_dnames[0]);

	/* MX RDATA - short = 10 DNAME = b.dname.com. */
	init_test_rdata_with_binary(&test_rdata_array[TEST_RDATA_MX_DNAME_GT].rdata,
	                            &test_rdata_array[TEST_RDATA_MX_DNAME_GT].size,
	                            &test_rdata_array[TEST_RDATA_MX_DNAME_GT].wire,
	                            &test_rdata_array[TEST_RDATA_MX_DNAME_GT].wire_size,
	                            0, 0, sizeof(knot_dname_t *) + 2,
	                            knot_dname_size(test_dnames[1]) + 2, &id, 2);

	init_test_rdata_with_dname(&test_rdata_array[TEST_RDATA_MX_DNAME_GT].rdata,
	                           &test_rdata_array[TEST_RDATA_MX_DNAME_GT].size,
	                           &test_rdata_array[TEST_RDATA_MX_DNAME_GT].wire,
	                           &test_rdata_array[TEST_RDATA_MX_DNAME_GT].wire_size,
	                           2, 2, sizeof(knot_dname_t *),
	                           knot_dname_size(test_dnames[1]), test_dnames[1]);

	test_rdata_array[TEST_RDATA_MX_BIN_LESS] = test_rdata_array[TEST_RDATA_MX_DNAME_LESS];

	/* MX RDATA - short = 20 DNAME = b.dname.com. */
	id = htobe16(20);
	init_test_rdata_with_binary(&test_rdata_array[TEST_RDATA_MX_BIN_GT].rdata,
	                            &test_rdata_array[TEST_RDATA_MX_BIN_GT].size,
	                            &test_rdata_array[TEST_RDATA_MX_BIN_GT].wire,
	                            &test_rdata_array[TEST_RDATA_MX_BIN_GT].wire_size,
	                            0, 0, sizeof(knot_dname_t *) + 2,
	                            knot_dname_size(test_dnames[1]) + 2, &id, 2);

	init_test_rdata_with_dname(&test_rdata_array[TEST_RDATA_MX_BIN_GT].rdata,
	                           &test_rdata_array[TEST_RDATA_MX_BIN_GT].size,
	                           &test_rdata_array[TEST_RDATA_MX_BIN_GT].wire,
	                           &test_rdata_array[TEST_RDATA_MX_BIN_GT].wire_size,
	                           2, 2, sizeof(knot_dname_t *),
	                           knot_dname_size(test_dnames[1]), test_dnames[1]);

	/* MINFO RRs. */
	init_test_rdata_with_dname(&test_rdata_array[TEST_RDATA_MINFO1].rdata,
	                           &test_rdata_array[TEST_RDATA_MINFO1].size,
	                           &test_rdata_array[TEST_RDATA_MINFO1].wire,
	                           &test_rdata_array[TEST_RDATA_MINFO1].wire_size,
	                           0, 0, sizeof(knot_dname_t *) * 2,
	                           knot_dname_size(test_dnames[0]) + knot_dname_size(test_dnames[1]),
	                           test_dnames[0]);

	init_test_rdata_with_dname(&test_rdata_array[TEST_RDATA_MINFO1].rdata,
	                           &test_rdata_array[TEST_RDATA_MINFO1].size,
	                           &test_rdata_array[TEST_RDATA_MINFO1].wire,
	                           &test_rdata_array[TEST_RDATA_MINFO1].wire_size,
	                           sizeof(knot_dname_t *), knot_dname_size(test_dnames[0]),
	                           sizeof(knot_dname_t *),
	                           knot_dname_size(test_dnames[1]), test_dnames[1]);

	init_test_rdata_with_dname(&test_rdata_array[TEST_RDATA_MINFO2].rdata,
	                           &test_rdata_array[TEST_RDATA_MINFO2].size,
	                           &test_rdata_array[TEST_RDATA_MINFO2].wire,
	                           &test_rdata_array[TEST_RDATA_MINFO2].wire_size,
	                           0, 0, sizeof(knot_dname_t *) * 2,
	                           knot_dname_size(test_dnames[2]) + knot_dname_size(test_dnames[3]),
	                           test_dnames[2]);

	init_test_rdata_with_dname(&test_rdata_array[TEST_RDATA_MINFO2].rdata,
	                           &test_rdata_array[TEST_RDATA_MINFO2].size,
	                           &test_rdata_array[TEST_RDATA_MINFO2].wire,
	                           &test_rdata_array[TEST_RDATA_MINFO2].wire_size,
	                           sizeof(knot_dname_t *), knot_dname_size(test_dnames[2]),
	                           sizeof(knot_dname_t *),
	                           knot_dname_size(test_dnames[3]), test_dnames[3]);
}

static void create_test_rrsets()
{
	for (int i = 0; i < TEST_RRSET_COUNT; i++) {
		/* Create memory representation. */
		test_rrset_t *test_rrset = &test_rrset_array[i];
		/* Assign owner. */
		test_rrset->rrset.owner = test_dnames[test_rrset->owner_id];

		/* Create wire representation. */

		/* Create header wire. */
		test_rrset->header_wire_size = knot_dname_size(test_rrset->rrset.owner) + 8;
		test_rrset->header_wire =
			xmalloc(test_rrset->header_wire_size);
		/* Copy owner wire to header wire. */
		memcpy(test_rrset->header_wire, test_rrset->rrset.owner,
		       knot_dname_size(test_rrset->rrset.owner));
		/* Copy type to wire. */
		size_t offset = knot_dname_size(test_rrset->rrset.owner);
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

		/* Create RDATA. */
		test_rrset->test_rdata =
			xmalloc(sizeof(void *) * test_rrset->rr_count);
		size_t actual_length = 0;
		size_t rdlength = 0;
		test_rrset->rrset.rdata_count = test_rrset->rr_count;
		for (int j = 0; j < test_rrset->rr_count; j++) {
			test_rrset->test_rdata[j] =
				&test_rdata_array[test_rrset->test_rdata_ids[j]];
			rdlength += test_rrset->test_rdata[j]->wire_size;
			actual_length += test_rrset->test_rdata[j]->size;
		}
		/* Assign RDATA (including indices). */
		offset = 0;
		test_rrset->rrset.rdata = xmalloc(actual_length);
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
	}
}

static int check_rrset_values(const knot_rrset_t *rrset,
                              knot_dname_t *dname, uint16_t type,
                              uint16_t rclass, uint16_t ttl, uint16_t rr_count)
{
	int errors = 0;

	if (!knot_dname_is_equal(rrset->owner, dname)) {
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

	return (check_errors == 0);
}

static int test_rrset_create_rdata()
{
	/* Two cases need to be tested - empty RRSet and non-empty RRSet. */


	knot_rrset_t *rrset = knot_rrset_new(test_dnames[0], 0, 0, 0);
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
		knot_rrset_deep_free(&rrset, 1, 1);
		return 0;
	}

	/* Write dummy data. */
	memcpy(write_pointer, test_rdata_array[0].rdata,
	       test_rdata_array[0].size);

	/* Check that indices are set right. */
	if (rrset->rdata_indices[0] != test_rdata_array[0].size) {
		diag("Wrong RDATA index after inserting RDATA to RRSet.\n");
		knot_rrset_deep_free(&rrset, 1, 1);
		return 0;
	}

	/* Rdata count must be equal to one. */
	if (rrset->rdata_count != 1) {
		diag("Wrong RDATA count after inserting RDATA to RRSet.\n");
		knot_rrset_deep_free(&rrset, 1, 1);
		return 0;
	}

	/* Make sure that the data in the RRSet are the same. */
	int ret = memcmp(rrset->rdata, test_rdata_array[0].rdata,
	                 test_rdata_array[0].size);
	if (ret) {
		diag("Wrong data inserted into RRSet.\n");
		knot_rrset_deep_free(&rrset, 1, 1);
		return 0;
	}

	/* Insert second item - all other inserts will do the same thing. */
	write_pointer = knot_rrset_create_rdata(rrset,
	                                        test_rdata_array[1].size);
	if (write_pointer == NULL) {
		diag("Could not create data of size %d\n",
		     test_rdata_array[1].size);
		knot_rrset_deep_free(&rrset, 1, 1);
		return 0;
	}

	/* Write dummy data. */
	memcpy(write_pointer, test_rdata_array[1].rdata,
	       test_rdata_array[1].size);

	/* Check that indices are set right. */
	if (rrset->rdata_indices[0] != test_rdata_array[1].size) {
		diag("Wrong RDATA first index after "
		     "inserting RDATA to RRSet.\n");
		knot_rrset_deep_free(&rrset, 1, 1);
		return 0;
	}

	if (rrset->rdata_indices[1] !=
	    test_rdata_array[0].size + test_rdata_array[1].size) {
		diag("Wrong RDATA last index after "
		     "inserting RDATA to RRSet.\n");
		knot_rrset_deep_free(&rrset, 1, 1);
		return 0;
	}

	/* Rdata count must be equal to two. */
	if (rrset->rdata_count != 2) {
		diag("Wrong RDATA count after inserting second "
		     "RDATA to RRSet.\n");
		knot_rrset_deep_free(&rrset, 1, 1);
		return 0;
	}

	/* Make sure that the data in the RRSet are the same. */
	ret = memcmp(rrset->rdata + test_rdata_array[0].size,
	             test_rdata_array[1].rdata, test_rdata_array[1].size);
	if (ret) {
		diag("Wrong data inserted into RRSet.\n");
		knot_rrset_deep_free(&rrset, 1, 1);
		return 0;
	}

	/* Test that data of length 0 are not inserted. */
	void *ret_ptr = knot_rrset_create_rdata(rrset, 0);
	if (ret_ptr != NULL) {
		diag("Empty RDATA inserted.\n");
		knot_rrset_deep_free(&rrset, 1, 1);
		return 0;
	}

	knot_rrset_deep_free(&rrset, 1, 1);
	return 1;
}

static int test_rrset_rdata_item_size()
{
	/* Test that types containing DNAMEs only return OK values. */
	knot_rrset_t *rrset =
		&test_rrset_array[TEST_RRSET_MINFO_MULTIPLE1].rrset;
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
		knot_rrset_deep_free(&rrset1, 1, 1);
		return 0;
	}

	if (rrset_rdata_item_size(rrset1, 1) != 25) {
		diag("Wrong item lenght in read (middle).\n");
		knot_rrset_deep_free(&rrset1, 1, 1);
		return 0;
	}

	if (rrset_rdata_item_size(rrset1, 2) != 38) {
		diag("Wrong item lenght in read (last).\n");
		knot_rrset_deep_free(&rrset1, 1, 1);
		return 0;
	}

	knot_rrset_deep_free(&rrset1, 1, 1);
	return 1;
}

static int test_rrset_get_rdata()
{
	knot_rrset_t *rrset = knot_rrset_new(test_dnames[0],
	                                     KNOT_RRTYPE_TXT, KNOT_CLASS_IN, 3600);
	assert(rrset);
	uint8_t *ref_pointer = knot_rrset_create_rdata(rrset, 16);
	memcpy(ref_pointer, "badcafecafebabee", 16);
	uint8_t *pointer = knot_rrset_get_rdata(rrset, 0);
	if (pointer != ref_pointer) {
		diag("Could not get RDATA from RRSet (%p vs %p).\n",
		     pointer, ref_pointer);
		knot_rrset_deep_free(&rrset, 1, 1);
		return 0;
	}

	int ret = memcmp(pointer, ref_pointer, 16);
	if (ret) {
		diag("Got bad RDATA from RRSet (comparison failed).\n");
		knot_rrset_deep_free(&rrset, 1, 1);
		return 0;
	}

	uint8_t *ref_pointer2 = knot_rrset_create_rdata(rrset, 16);
	memcpy(ref_pointer2, "foobarfoobarfoob", 16);
	pointer = knot_rrset_get_rdata(rrset, 1);
	if (pointer != ref_pointer2) {
		diag("Could not ger RDATA from RRSet (%p vs %p).\n",
		     pointer, ref_pointer2);
		knot_rrset_deep_free(&rrset, 1, 1);
		return 0;
	}

	ret = memcmp(pointer, ref_pointer2, 16);
	if (ret) {
		diag("Got bad RDATA from RRSet (comparison failed).\n");
		knot_rrset_deep_free(&rrset, 1, 1);
		return 0;
	}

	knot_rrset_deep_free(&rrset, 1, 1);
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

		knot_rrset_free(&rrset_copy);
	}

	return 1;
}

static int test_rrset_deep_copy()
{
	for (int i = 0; i < TEST_RRSET_COUNT; i++) {
		knot_rrset_t *rrset_copy = NULL;
		knot_rrset_t *rrset = &test_rrset_array[i].rrset;
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

	/* Test correct conversions. */
	for (int i = 0; i < TEST_RRSET_COUNT; i++) {
		memset(wire, 0, wire_size);
		wire_size = 65535;
		/* Convert to wire. */
		int ret = knot_rrset_to_wire(&test_rrset_array[i].rrset, wire,
		                             &wire_size, 65535, &rr_count, NULL);
		if (ret != KNOT_EOK) {
			diag("Could not convert RRSet to wire (%s).\n",
			     knot_strerror(ret));
			return 0;
		}

		if (rr_count != test_rrset_array[i].rrset.rdata_count) {
			diag("Wrong number of RRs converted.\n");
			return 0;
		}

		size_t offset = 0;
		for (int j = 0; j < rr_count; ++j) {
			/* Check that header is OK. */
			ret = memcmp(wire + offset,
			             test_rrset_array[i].header_wire,
			             test_rrset_array[i].header_wire_size);
			if (ret) {
				diag("Header of RRSet %d, RR %d is wrongly converted.\n",
				     i, j);
				return 0;
			}

			offset += test_rrset_array[i].header_wire_size;
			/* Check RDLENGTH. */
			uint16_t rdlength = knot_wire_read_u16(wire + offset);
			if (rdlength != test_rrset_array[i].test_rdata[j]->wire_size) {
				diag("Wrong RDLENGTH\n");
				return 0;
			}
			offset += sizeof(uint16_t);

			/* Check that the RDATA are OK. */
			ret = memcmp(wire + offset,
			             test_rrset_array[i].test_rdata[j]->wire,
			             rdlength);
			if (ret) {
				diag("RDATA of RRSet %d, RR %d, "
				     "are wrongly converted. Type=%"PRIu16"\n",
				     i, j, test_rrset_array[i].rrset.type);
				return 0;
			}
			offset += rdlength;
		}

		if (offset != wire_size) {
			diag("Wrong wire size, in RRSet=%d "
			     "(should be=%d, is=%d).\n", i,
			     offset, wire_size);
			return 0;
		}
	}

	/* Check that function does not crash if given small wire. */
	int ret = knot_rrset_to_wire(&test_rrset_array[0].rrset, wire,
	                         &wire_size, 5, &rr_count, NULL);
	if (ret != KNOT_ESPACE) {
		diag("RRSet was converted to wire even though twe wire was"
		     " not big enough.\n");
		return 0;
	}
	/* RDATA do not fit. */
	ret = knot_rrset_to_wire(&test_rrset_array[0].rrset, wire,
	                         &wire_size, 25, &rr_count, NULL);
	if (ret != KNOT_ESPACE) {
		diag("RRSet was converted to wire even though twe wire was"
		     " not big enough.\n");
		return 0;
	}

	return 1;
}

static int test_rrset_merge()
{
	knot_rrset_t *merge_to;
	knot_rrset_deep_copy(&test_rrset_array[TEST_RRSET_MERGE_UNIQUE1].rrset,
	                     &merge_to);
	knot_rrset_t *merge_from;
	knot_rrset_deep_copy(&test_rrset_array[TEST_RRSET_MERGE_UNIQUE2].rrset,
	                     &merge_from);
	assert(merge_to);
	assert(merge_from);
	int ret = knot_rrset_merge(merge_to, merge_from);
	if (ret != KNOT_EOK) {
		diag("Could not merge RRSets.\n");
		knot_rrset_deep_free(&merge_to, 1, 1);
		knot_rrset_deep_free(&merge_from, 1, 1);
		return 0;
	}

	//TODO check that merge operation does not change second rr
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

static int test_rrset_merge_sort()
{
	/* Test that merge of two identical RRSets results in no-op. */
	knot_rrset_t *merge_to = NULL;
	knot_rrset_deep_copy(&test_rrset_array[TEST_RRSET_MERGE_UNIQUE1].rrset,
	                     &merge_to);
	knot_rrset_t *merge_from = NULL;
	knot_rrset_deep_copy(&test_rrset_array[TEST_RRSET_MERGE_UNIQUE1].rrset,
	                     &merge_from);
	int merged, removed_rrs;
	int ret = knot_rrset_merge_sort(merge_to, merge_from, &merged, &removed_rrs);
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
	                     &merge_to);
	knot_rrset_deep_copy(&test_rrset_array[TEST_RRSET_MERGE_UNIQUE2].rrset,
	                     &merge_from);
	assert(merge_to);
	assert(merge_from);

	ret = knot_rrset_merge_sort(merge_to, merge_from, &merged,
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
	                     &merge_to);
	knot_rrset_deep_copy(&test_rrset_array[TEST_RRSET_MERGE_RESULT1].rrset,
	                     &merge_from);
	assert(merge_to);
	assert(merge_from);

	ret = knot_rrset_merge_sort(merge_to, merge_from, &merged,
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
	knot_rrset_deep_copy(&test_rrset_array[TEST_RRSET_A_GT].rrset,
	                     &rrs1);
	knot_rrset_t *rrs2 = &test_rrset_array[TEST_RRSET_A_GT].rrset;
	/* Test header comparison. */
	ret = knot_rrset_equal(rrs1, rrs2, KNOT_RRSET_COMPARE_HEADER);
	if (!ret) {
		diag("Header comparison failed (Header equal).\n");
		knot_rrset_deep_free(&rrs1, 1, 1);
		return 0;
	}
	/* Change DNAME. */
	knot_rrset_set_owner(rrs1, test_dnames[4]);
	ret = knot_rrset_equal(rrs1, rrs2, KNOT_RRSET_COMPARE_HEADER);
	if (ret) {
		char *owner1 = knot_dname_to_str(rrs1->owner);
		char *owner2 = knot_dname_to_str(rrs2->owner);
		diag("Header comparison failed "
		     "(DNAMEs different (%s %s), but ret=%d).\n", owner1,
		     owner2, ret);
		rrs1->owner = test_dnames[0];
		knot_rrset_deep_free(&rrs1, 1, 1);
		free(owner1);
		free(owner2);
		return 0;
	}
	rrs1->owner = test_dnames[0];
	/* Change CLASS. */
	rrs1->rclass = KNOT_CLASS_CH;
	ret = knot_rrset_equal(rrs1, rrs2, KNOT_RRSET_COMPARE_HEADER);
	if (ret) {
		diag("Header comparison failed (CLASSEs different).\n");
		knot_rrset_deep_free(&rrs1, 1, 1);
		return 0;
	}
	rrs1->rclass = KNOT_CLASS_IN;

	/* Test whole comparison. */
	ret = knot_rrset_equal(rrs1, rrs2, KNOT_RRSET_COMPARE_WHOLE);
	if (!ret) {
		diag("Whole comparison failed (Same RRSets).\n");
		knot_rrset_deep_free(&rrs1, 1, 1);
		return 0;
	}

	rrs2 = &test_rrset_array[TEST_RRSET_A_LESS].rrset;
	ret = knot_rrset_equal(rrs1, rrs2, KNOT_RRSET_COMPARE_WHOLE);
	if (ret) {
		diag("Whole comparison failed (Different RRSets).\n");
		knot_rrset_deep_free(&rrs1, 1, 1);
		return 0;
	}

	knot_rrset_deep_free(&rrs1, 1, 1);

	return 1;
}

static int test_rrset_rdata_equal()
{
	/* Equal - raw data only. */
	knot_rrset_t *rrset1 = &test_rrset_array[TEST_RRSET_A_LESS].rrset;
	knot_rrset_t *rrset2 = &test_rrset_array[TEST_RRSET_A_LESS].rrset;
	if (!knot_rrset_rdata_equal(rrset1, rrset2)) {
		diag("rrset_rdata_equal() returned wrong "
		     "value, should be 1. (raw data) %d %d\n",
		     rrset1->type, rrset2->type);
		return 0;
	}

	/* Equal - DNAME only. */
	rrset1 = &test_rrset_array[TEST_RRSET_NS_LESS].rrset;
	rrset2 = &test_rrset_array[TEST_RRSET_NS_LESS].rrset;
	if (!knot_rrset_rdata_equal(rrset1, rrset2)) {
		diag("rrset_rdata_equal() returned wrong "
		     "value, should be 1. (DNAME only)\n");
		return 0;
	}

	/* Equal - combination. */
	rrset1 = &test_rrset_array[TEST_RRSET_MX_BIN_LESS].rrset;
	rrset2 = &test_rrset_array[TEST_RRSET_MX_BIN_LESS].rrset;
	if (!knot_rrset_rdata_equal(rrset1, rrset2)) {
		diag("rrset_rdata_equal() returned wrong "
		     "value, should be 1. (MX combination)\n");
		return 0;
	}

	/* Equal - combination, different order. */
	rrset1 = &test_rrset_array[TEST_RRSET_MINFO_MULTIPLE1].rrset;
	rrset2 = &test_rrset_array[TEST_RRSET_MINFO_MULTIPLE2].rrset;
	if (!knot_rrset_rdata_equal(rrset1, rrset2)) {
		diag("rrset_rdata_equal() returned wrong "
		     "value, should be 1. (MINFO - order, combination)\n");
		return 0;
	}

	/* Not equal - second item missing. */
	rrset1 = &test_rrset_array[TEST_RRSET_MINFO_MULTIPLE1].rrset;
	rrset2 = &test_rrset_array[TEST_RRSET_MINFO].rrset;
	if (knot_rrset_rdata_equal(rrset1, rrset2)) {
		diag("rrset_rdata_equal() returned wrong "
		     "value, should be 0. (MINFO - combination)\n");
		return 0;
	}

	/* Other way around. */
	if (knot_rrset_rdata_equal(rrset2, rrset1)) {
		diag("rrset_rdata_equal() returned wrong "
		     "value, should be 0. (combination)\n");
		return 0;
	}

	/* Not equal - second item different. */

	/* Other way around. */

	/* Not equal - raw data only. */
	rrset1 = &test_rrset_array[TEST_RRSET_A_LESS].rrset;
	rrset2 = &test_rrset_array[TEST_RRSET_A_GT].rrset;
	if (knot_rrset_rdata_equal(rrset1, rrset2) == 1) {
		diag("rrset_rdata_equal() returned wrong "
		     "value, should be 0. (raw data only)\n");
		return 0;
	}

	/* Not equal - raw data only. */
	if (knot_rrset_rdata_equal(rrset2, rrset1) == 1) {
		diag("rrset_rdata_equal() returned wrong "
		     "value, should be 0. (raw data only)\n");
		return 0;
	}

	/* Not equal - DNAME only. */
	rrset1 = &test_rrset_array[TEST_RRSET_NS_LESS].rrset;
	rrset2 = &test_rrset_array[TEST_RRSET_NS_GT].rrset;
	if (knot_rrset_rdata_equal(rrset1, rrset2) == 1) {
		diag("rrset_rdata_equal() returned wrong "
		     "value, should be 0. (DNAME only)\n");
		return 0;
	}

	/* Not equal - DNAME only. */
	if (knot_rrset_rdata_equal(rrset2, rrset1) == 1) {
		diag("rrset_rdata_equal() returned wrong "
		     "value, should be 0. (DNAME only)\n");
		return 0;
	}

	/* Not equal - combination, difference in binary part. */
	rrset1 = &test_rrset_array[TEST_RRSET_MX_BIN_LESS].rrset;
	rrset2 = &test_rrset_array[TEST_RRSET_MX_BIN_GT].rrset;
	if (knot_rrset_rdata_equal(rrset1, rrset2) == 1) {
		diag("rrset_rdata_equal() returned wrong "
		     "value, should be 0. (combination)\n");
		return 0;
	}

	/* Not equal - combination, difference in binary part. */
	if (knot_rrset_rdata_equal(rrset2, rrset1) == 1) {
		diag("rrset_rdata_equal() returned wrong "
		     "value, should be 0. (combination)\n");
		return 0;
	}

	/* Not equal - combination, difference in DNAME part. */
	rrset1 = &test_rrset_array[TEST_RRSET_MX_DNAME_LESS].rrset;
	rrset2 = &test_rrset_array[TEST_RRSET_MX_DNAME_GT].rrset;
	if (knot_rrset_rdata_equal(rrset1, rrset2) == 1) {
		diag("rrset_rdata_equal() returned wrong "
		     "value, should be 0. (combination)\n");
		return 0;
	}

	/* Not equal - combination, difference in DNAME part. */
	if (knot_rrset_rdata_equal(rrset2, rrset1) == 1) {
		diag("rrset_rdata_equal() returned wrong "
		     "value, should be 0 (combination)\n");
		return 0;
	}

	return 1;
}

static int test_rrset_next_dname()
{
	/* Same test as in above, but we'll use multiple RRs within one SET. */
	knot_rrset_t *rrset = &test_rrset_array[TEST_RRSET_MINFO_MULTIPLE1].rrset;
	knot_dname_t *extracted_dnames[4];
	extracted_dnames[0] = test_dnames[0];
	extracted_dnames[1] = test_dnames[1];
	extracted_dnames[2] = test_dnames[2];
	extracted_dnames[3] = test_dnames[3];
	knot_dname_t **dname = NULL;
	int i = 0;
	while ((dname = knot_rrset_get_next_dname(rrset, dname))) {
		if (!knot_dname_is_equal(extracted_dnames[i], *dname)) {
			diag("Got wrong DNAME from RDATA. on index %d\n", i);
			char *ext_name = knot_dname_to_str(extracted_dnames[i]);
			char *act_name = knot_dname_to_str(*dname);
			diag("DNAME should be %s, but was %s (%p - %p)\n",
			     ext_name, act_name, extracted_dnames[i], *dname);
			free(ext_name);
			free(act_name);
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
	rrset = &test_rrset_array[TEST_RRSET_NS_LESS].rrset;
	dname = NULL;
	dname = knot_rrset_get_next_dname(rrset, dname);
	if (dname == NULL || !knot_dname_is_equal(*dname, test_dnames[TEST_DNAME_GENERIC])) {
		diag("Got wrong DNAME from NS RDATA. Was %p, should be %p \n",
		     dname ? *dname: NULL, test_dnames[TEST_DNAME_GENERIC]);
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
	if (dname == NULL || !knot_dname_is_equal(*dname, test_dnames[1])) {
		diag("Got wrong DNAME from MX RDATA.\n");
		return 0;
	}
	dname = knot_rrset_get_next_dname(rrset, dname);
	if (dname != NULL) {
		diag("Got DNAME from RRSet even though all had been extracted previously. (MX)\n");
		return 0;
	}

	/* Try writes into DNAMEs you've gotten. */
	rrset = NULL;
	knot_rrset_deep_copy(&test_rrset_array[TEST_RRSET_MINFO_MULTIPLE1].rrset,
	                     &rrset);
	dname = NULL;
	i = 4;
	while ((dname = knot_rrset_get_next_dname(rrset, dname))) {
		knot_dname_free(dname);
		memcpy(dname, &test_dnames[i], sizeof(knot_dname_t *));
		i++;
	}

	if (i != 8) {
		diag("Not all DNAMEs were traversed (%d).\n", i);
		knot_rrset_deep_free(&rrset, 1, 1);
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
		knot_rrset_deep_free(&rrset, 1, 1);
		return 0;
	}

	knot_rrset_deep_free(&rrset, 1, 1);

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
	knot_rrset_deep_copy(rrset_source, &rrset_find_in);
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
	/* Reset RRSet. */
	rrset_find_in->rdata = NULL;
	rrset_find_in->rdata_indices = NULL;
	rrset_find_in->rdata_count = 0;

	rdata = knot_rrset_create_rdata(rrset_find_in, 10);
	memcpy(rdata, mock_data ,10);
	ret = knot_rrset_find_rr_pos(rrset_source, rrset_find_in, 0, &rr_pos);
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
	knot_rrset_deep_copy(rrset_source, &rrset_dest);
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

//	diag("Returned\n");
//	knot_rrset_dump(returned_rr);
//	diag("Source\n");
//	knot_rrset_dump(rrset_source);
//	diag("Destinantion\n");
//	knot_rrset_dump(rrset_dest);

	/* Only one RR within RRSet, needs to be the same. */
	if (!knot_rrset_equal(rrset_source, returned_rr,
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

static int knot_rrset_tests_run(int argc, char *argv[])
{
	plan(14);
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
	res_final *= res;

	res = test_rrset_rdata_equal();
	ok(res, "rrset: rrset_rdata_equal");

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

	res = test_rrset_merge_sort();
	ok(res, "rrset: merge + sort");
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
#else
int main(void) {
	plan(14);
	skip_block(14, "the implementation is not done yet");
}
#endif
