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

#include <stdlib.h>
#include <assert.h>

#include "tests/libknot/libknot/rdata_tests.h"
#include "libknot/common.h"
#include "libknot/rdata.h"
#include "libknot/dname.h"
#include "libknot/util/descriptor.h"
#include "libknot/util/utils.h"
#include "libknot/util/error.h"

enum { TEST_DOMAINS_OK = 8 };

struct test_domain {
	char *str;
	char *wire;
	uint size;
	char *labels;
	short label_count;
};

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


static int knot_rdata_tests_count(int argc, char *argv[]);
static int knot_rdata_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api rdata_tests_api = {
	"DNS library - rdata",        //! Unit name
	&knot_rdata_tests_count,  //! Count scheduled tests
	&knot_rdata_tests_run     //! Run scheduled tests
};

/*----------------------------------------------------------------------------*/
/*
 *  Unit implementation.
 */

static uint16_t *RDATA_ITEM_PTR = (uint16_t *)0xDEADBEEF;

enum { RDATA_ITEMS_COUNT = 7, TEST_RDATA_COUNT = 4 , RDATA_DNAMES_COUNT = 2 };

static knot_dname_t RDATA_DNAMES[RDATA_DNAMES_COUNT] = {
	{{}, (uint8_t *)"\6abcdef\7example\3com", 20,
         (uint8_t *)"\x0\x7\xF", 3},
	{{}, (uint8_t *)"\6abcdef\3foo\3com", 16,
        (uint8_t *)"\x0\x7\xB", 3}
};

static knot_rdata_item_t TEST_RDATA_ITEMS[RDATA_ITEMS_COUNT] = {
	{.dname = (knot_dname_t *)0xF00},
	{.raw_data = (uint16_t *)"some data"},
	{.raw_data = (uint16_t *)"other data"},
	{.raw_data = (uint16_t *)"123456"},
	{.raw_data = (uint16_t *)"654321"},
	{.dname = &RDATA_DNAMES[0]},
	{.dname = &RDATA_DNAMES[1]}
};

/* \note indices 0 to 3 should not be changed - used in (and only in)
 * test_rdata_compare() - better than creating new struct just for this
 */
static knot_rdata_t test_rdata[TEST_RDATA_COUNT] = {
	{&TEST_RDATA_ITEMS[3], 1, &test_rdata[1]},
	{&TEST_RDATA_ITEMS[4], 1, &test_rdata[2]},
	{&TEST_RDATA_ITEMS[5], 1, &test_rdata[3]},
	{&TEST_RDATA_ITEMS[6], 1, &test_rdata[4]},
};

static knot_rdata_t TEST_RDATA = {
	&TEST_RDATA_ITEMS[0],
	3,
	&TEST_RDATA
};

/*----------------------------------------------------------------------------*/
/*!
 * \brief Tests knot_rdata_new().
 *
 * Creates new RDATA structure with no items and tests if there really are no
 * items in it.
 *
 * \retval > 0 on success.
 * \retval 0 otherwise.
 */
static int test_rdata_create()
{
	knot_rdata_t *rdata = knot_rdata_new();
	if (rdata == NULL) {
		diag("RDATA structure not created!");
		return 0;
	}

	if (knot_rdata_item(rdata, 0) != NULL) {
		diag("Get item returned something else than NULL!");
		knot_rdata_free(&rdata);
		return 0;
	}

	knot_rdata_free(&rdata);
	return 1;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Tests knot_rdata_free().
 *
 * \retval > 0 on success.
 * \retval 0 otherwise.
 */
static int test_rdata_delete()
{
	// how to test this??
	return 0;
}

/*----------------------------------------------------------------------------*/

static void generate_rdata(uint8_t *data, int size)
{
	for (int i = 0; i < size; ++i) {
		data[i] = rand() % 256;
	}
}

/*----------------------------------------------------------------------------*/

static int fill_rdata(uint8_t *data, int max_size, uint16_t rrtype,
                      knot_rdata_t *rdata)
{
	assert(rdata != NULL);
	assert(data != NULL);
	assert(max_size > 0);

	uint8_t *pos = data;
	int used = 0;
	int wire_size = 0;

	//note("Filling RRType %u", rrtype);

	knot_rrtype_descriptor_t *desc =
	knot_rrtype_descriptor_by_type(rrtype);

	uint item_count = desc->length;
	knot_rdata_item_t *items =
	(knot_rdata_item_t *)malloc(item_count
				      * sizeof(knot_rdata_item_t));

	for (int i = 0; i < item_count; ++i) {
		uint size = 0;
		int domain = 0;
		knot_dname_t *dname = NULL;
		int binary = 0;
		int stored_size = 0;

		switch (desc->wireformat[i]) {
		case KNOT_RDATA_WF_COMPRESSED_DNAME:
		case KNOT_RDATA_WF_UNCOMPRESSED_DNAME:
		case KNOT_RDATA_WF_LITERAL_DNAME:
			dname = knot_dname_new_from_wire(
			                (uint8_t *)test_domains_ok[0].wire,
			                test_domains_ok[0].size, NULL);
			assert(dname != NULL);
			/* note("Created domain name: %s",
			         knot_dname_name(dname)); */
			//note("Domain name ptr: %p", dname);
			domain = 1;
			size = knot_dname_size(dname);
			//note("Size of created domain name: %u", size);
			assert(size < KNOT_MAX_RDATA_ITEM_SIZE);
			// store size of the domain name
			*(pos++) = size;
			// copy the domain name
			memcpy(pos, knot_dname_name(dname), size);
			pos += size;
			break;
		default:
			binary = 1;
			size = rand() % KNOT_MAX_RDATA_ITEM_SIZE;
		}

		if (binary) {
			// Rewrite the actual 2 bytes in the data array
			// with length.
			// (this is a bit ugly, but does the work ;-)
			knot_wire_write_u16(pos, size);
			//*pos = size;
		}

		//note("Filling %u bytes", size);
		used += size;
		assert(used < max_size);

		if (domain) {
			items[i].dname = dname;
			wire_size += knot_dname_size(dname);
/*			note("Saved domain name ptr on index %d: %p",
			      i, items[i].dname); */
		} else {
			free(dname);
//			note("Saved raw data ptr on index %d: %p",i, pos);
			items[i].raw_data = (uint16_t *)pos;
			pos += size;
			wire_size += size;
			if (binary && !stored_size) {
				wire_size -= 2;
			}
		}
	}

	int res = knot_rdata_set_items(rdata, items, item_count);
	if (res != 0) {
		diag("knot_rdata_set_items() returned %d.", res);
		free(items);
		return -1;
	} else {
		free(items);
		return wire_size;
	}
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Checks if all RDATA items in the given RDATA structure are correct.
 *
 * \return Number of errors encountered. Error is either if some RDATA item
 *         is not set (i.e. NULL) or if it has other than the expected value.
 */
static int check_rdata(const uint8_t *data, int max_size, uint16_t rrtype,
                       const knot_rdata_t *rdata)
{
	assert(rdata != NULL);
	assert(data != NULL);
	assert(max_size > 0);

	int errors = 0;

	const uint8_t *pos = data;
	int used = 0;

	knot_rrtype_descriptor_t *desc =
	knot_rrtype_descriptor_by_type(rrtype);
	uint item_count = desc->length;
	//note("check_rdata(), RRType: %u", rrtype);
	//note("  item count: %u", item_count);

	for (int i = 0; i < item_count; ++i) {
		uint size = 0;
		int domain = 0;
		int binary = 0;

		//note("  item: %d", i);

		switch (desc->wireformat[i]) {
		case KNOT_RDATA_WF_COMPRESSED_DNAME:
		case KNOT_RDATA_WF_UNCOMPRESSED_DNAME:
		case KNOT_RDATA_WF_LITERAL_DNAME:
			//note("    domain name");
			domain = 1;
			size = knot_dname_size(knot_rdata_item(
						 rdata, i)->dname);
			break;
		default:
			size =
			knot_wire_read_u16((uint8_t *)
					     (knot_rdata_item(
					      rdata, i)->raw_data));
		}

		assert(size > 0);
		//note("Size: %u", size);
		used += size;
		assert(used < max_size);

		//note("    item size: %u", size);

		if (domain) {
			/*note("Domain name ptr: %p",
				knot_rdata_get_item(rdata, i)->dname);*/
			// check dname size
			if (*pos != size) {
				diag("Domain name stored in %d-th"
				     "RDATA has wrong size: %d"
				     " (should be %d)", size, *pos);
				++errors;
			} else if (strncmp((char *)knot_dname_name(
			           knot_rdata_item(rdata, i)->dname),
			           (char *)(pos + 1), *pos) != 0) {
				diag("Domain name stored in %d-th"
				     "RDATA item is wrong: %s ("
				     "should be %.*s)", i,
				     knot_dname_name(knot_rdata_item(
				     rdata, i)->dname),
				     *pos, (char *)(pos + 1));
				++errors;
			}

			pos += *pos + 1;

			continue;
		}

		if (binary &&
		    size !=
		    knot_wire_read_u16(
			(uint8_t *)(knot_rdata_item(rdata, i)->raw_data))) {
		    diag("Size of stored binary data is wrong:"
		         " %u (should be %u)",
			 knot_rdata_item(rdata, i)->raw_data[0] + 1,
			                       size);
			++errors;
		}

		if (strncmp((char *)
		   (&knot_rdata_item(rdata, i)->raw_data[0]),
		   (char *)pos, size) != 0) {
/*			knot_rrtype_descriptor_t *desc =
			knot_rrtype_descriptor_by_type(rrtype); */

			diag("Data stored in %d-th RDATA item are wrong.", i);
			++errors;
		}

		pos += size;
	}

	return errors;
}

/*----------------------------------------------------------------------------*/

//static int convert_to_wire(const uint8_t *data, int max_size, uint16_t rrtype,
//                           uint8_t *data_wire)
//{
//	//note("Converting type %u", rrtype);

//	int wire_size = 0;
//	const uint8_t *pos = data;
//	uint8_t *pos_wire = data_wire;

//	knot_rrtype_descriptor_t *desc =
//	knot_rrtype_descriptor_by_type(rrtype);
//	uint item_count = desc->length;

//	for (int i = 0; i < item_count; ++i) {
//		const uint8_t *from = NULL;
//		uint to_copy = 0;

//		switch (desc->wireformat[i]) {
//		case KNOT_RDATA_WF_COMPRESSED_DNAME:
//		case KNOT_RDATA_WF_UNCOMPRESSED_DNAME:
//		case KNOT_RDATA_WF_LITERAL_DNAME:
//			// copy the domain name without its length
//			from = pos + 1;
//			to_copy = *pos;
//			pos += *pos + 1;
///*			note("Domain name in wire format (size %u): %s",
//			     to_copy, (char *)from); */
//			break;
//		case KNOT_RDATA_WF_BYTE:
//			//note("    1byte int");
//			from = pos;
//			to_copy = 1;
//			pos += 1;
//			break;
//		case KNOT_RDATA_WF_SHORT:
//			//note("    2byte int");
//			from = pos;
//			to_copy = 2;
//			pos += 2;
//			break;
//		case KNOT_RDATA_WF_LONG:
//			//note("    4byte int");
//			from = pos;
//			to_copy = 4;
//			pos += 4;
//			break;
//		case KNOT_RDATA_WF_A:
//			//note("    A");
//			from = pos;
//			to_copy = 4;
//			pos += 4;
//			break;
//		case KNOT_RDATA_WF_AAAA:
//			//note("    AAAA");
//			from = pos;
//			to_copy = 16;
//			pos += 16;
//			break;
//		case KNOT_RDATA_WF_BINARY:
//		case KNOT_RDATA_WF_APL:            // saved as binary
//		case KNOT_RDATA_WF_IPSECGATEWAY:   // saved as binary
//			//note("    binary");
//			from = pos + 1;
//			to_copy = *pos;
//			pos += *pos + 1;
//			break;
//		case KNOT_RDATA_WF_TEXT:
//		case KNOT_RDATA_WF_BINARYWITHLENGTH:
//			//note("    text or binary with length (%u)", *pos);
//			to_copy = *pos + 1;
//			from = pos;
//			pos += *pos + 1;
//			break;
//		default:
//			assert(0);
//		}

//		//note("Copying %u bytes from %p", to_copy, from);

//		assert(from != NULL);
//		assert(to_copy != 0);

//		memcpy(pos_wire, from, to_copy);
//		pos_wire += to_copy;
//		wire_size += to_copy;

//		assert(wire_size < max_size);
//	}

//	return wire_size;
//}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Tests knot_rdata_set_item().
 *
 * \retval > 0 on success.
 * \retval 0 otherwise.
 */
static int test_rdata_set_item()
{
	knot_rdata_t *rdata = knot_rdata_new();
	knot_rdata_item_t item;
	item.raw_data = RDATA_ITEM_PTR;

	int ret = knot_rdata_set_item(rdata, 0, item);
	if (ret == 0) {
		diag("knot_rdata_set_item() called on empty RDATA"
		     "returned %d instead of error (-1).", ret);
		knot_rdata_free(&rdata);
		return 0;
	}

//	uint8_t *data = malloc(sizeof(uint8_t) * KNOT_MAX_RDATA_WIRE_SIZE);
//	assert(data);
	uint8_t data[KNOT_MAX_RDATA_WIRE_SIZE];
	generate_rdata(data, KNOT_MAX_RDATA_WIRE_SIZE);

	// set items through set_items() and then call set_item()
	uint16_t rrtype = rand() % KNOT_RRTYPE_LAST + 1;
	if (fill_rdata(data, KNOT_MAX_RDATA_WIRE_SIZE, rrtype, rdata) < 0) {
		knot_rdata_free(&rdata);
		diag("Error filling RDATA");
		return 0;
	}

	uint8_t pos = rand() % knot_rrtype_descriptor_by_type(rrtype)->length;

	knot_rrtype_descriptor_t *desc =
	  knot_rrtype_descriptor_by_type(rrtype);

	// if the rdata on this position is domain name, free it to avoid leaks
	if (desc->wireformat[pos] == KNOT_RDATA_WF_UNCOMPRESSED_DNAME
	    || desc->wireformat[pos] == KNOT_RDATA_WF_COMPRESSED_DNAME
	    || desc->wireformat[pos] == KNOT_RDATA_WF_LITERAL_DNAME) {
		knot_dname_free(&(rdata->items[pos].dname));
	}

	ret = knot_rdata_set_item(rdata, pos, item);
	if (ret != 0) {
		diag("knot_rdata_set_item() called on filled"
		     " RDATA returned %d instead of 0.", ret);
		knot_rdata_free(&rdata);
		return 0;
	}

	if (knot_rdata_item(rdata, pos)->raw_data != RDATA_ITEM_PTR) {
		diag("RDATA item on position %d is wrong: %p (should be %p).",
		     pos, knot_rdata_item(rdata, pos)->raw_data,
		     RDATA_ITEM_PTR);
		knot_rdata_free(&rdata);
		return 0;
	}

	for (int x = 0; x < desc->length; x++) {
	       if (x != pos && (
		   desc->wireformat[x] ==
	               KNOT_RDATA_WF_UNCOMPRESSED_DNAME ||
	           desc->wireformat[x] ==
	               KNOT_RDATA_WF_COMPRESSED_DNAME ||
	           desc->wireformat[x] ==
	               KNOT_RDATA_WF_LITERAL_DNAME)) {
		knot_dname_free(&(rdata->items[x].dname));
	       }
	}

//	knot_rdata_free(&rdata);
	return 1;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Tests knot_rdata_set_items().
 *
 * Iterates over the test_rdatas array and for each testing RDATA it creates
 * the RDATA structure, sets its items (\see set_rdata_all()) and checks if the
 * items are set properly (\see check_rdata()).
 *
 * \retval > 0 on success.
 * \retval 0 otherwise.
 */
static int test_rdata_set_items()
{
	knot_rdata_t *rdata = NULL;
	knot_rdata_item_t *item = (knot_rdata_item_t *)0xDEADBEEF;
	int errors = 0;

	// check error return values
	if (knot_rdata_set_items(rdata, NULL, 0) != KNOT_EBADARG) {
		diag("Return value of knot_rdata_set_items() "
		     "when rdata == NULL is wrong");
		return 0;
	} else {
		rdata = knot_rdata_new();
		assert(rdata != NULL);

		if (knot_rdata_set_items(rdata, NULL, 0) != KNOT_EBADARG) {
			diag("Return value of knot_rdata_set_items()"
			     " when items == NULL is wrong");
//			knot_rdata_free(&rdata);
			return 0;
		} else if (knot_rdata_set_items(rdata, item, 0) !=
			   KNOT_EBADARG) {
			diag("Return value of knot_rdata_set_items()"
			     " when count == 0"
			     "is wrong");
//			knot_rdata_free(&rdata);
			return 0;
		}
//		knot_rdata_free(&rdata);
	}

	// generate some random data
//	uint8_t *data = malloc(sizeof(uint8_t) * KNOT_MAX_RDATA_WIRE_SIZE);
	uint8_t data [KNOT_MAX_RDATA_WIRE_SIZE];
	generate_rdata(data, KNOT_MAX_RDATA_WIRE_SIZE);

	for (int i = 0; i <= KNOT_RRTYPE_LAST; ++i) {
		rdata = knot_rdata_new();

		if (fill_rdata(data, KNOT_MAX_RDATA_WIRE_SIZE, i, rdata)
		    < 0) {
			++errors;
		}
		errors += check_rdata(data, KNOT_MAX_RDATA_WIRE_SIZE, i,
		                      rdata);

		knot_rrtype_descriptor_t *desc =
		knot_rrtype_descriptor_by_type(i);

		for (int x = 0; x < desc->length; x++) {
			if (desc->wireformat[x] ==
			    KNOT_RDATA_WF_UNCOMPRESSED_DNAME ||
			    desc->wireformat[x] ==
			    KNOT_RDATA_WF_COMPRESSED_DNAME ||
			    desc->wireformat[x] ==
			    KNOT_RDATA_WF_LITERAL_DNAME) {
//            printf("freeing %p\n", rdata->items[x].dname);
				knot_dname_free(&(rdata->items[x].dname));
			}
		}

//		knot_rdata_free(&rdata);
	}

	return (errors == 0);
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Tests knot_rdata_get_item().
 *
 * \retval > 0 on success.
 * \retval 0 otherwise.
 */
static int test_rdata_get_item()
{
	const knot_rdata_t *rdata = &TEST_RDATA;

	if (knot_rdata_item(rdata, TEST_RDATA.count) != NULL) {
		diag("knot_rdata_get_item() called with"
		     "invalid position did not return NULL");
		return 0;
	}

	int errors = 0;
	if ((knot_rdata_item(rdata, 0)->dname)
	      != TEST_RDATA.items[0].dname) {
		diag("RDATA item on position 0 is wrong: %p (should be %p)",
		     knot_rdata_item(rdata, 0), TEST_RDATA.items[0]);
		++errors;
	}
	if ((knot_rdata_item(rdata, 1)->raw_data)
	      != TEST_RDATA.items[1].raw_data) {
		diag("RDATA item on position 0 is wrong: %p (should be %p)",
		     knot_rdata_item(rdata, 1), TEST_RDATA.items[1]);
		++errors;
	}
	if ((knot_rdata_item(rdata, 2)->raw_data)
	      != TEST_RDATA.items[2].raw_data) {
		diag("RDATA item on position 0 is wrong: %p (should be %p)",
		     knot_rdata_item(rdata, 2), TEST_RDATA.items[2]);
		++errors;
	}

	return (errors == 0);
}

/*----------------------------------------------------------------------------*/

static int test_rdata_compare()
{
	int errors = 0;

	uint8_t format_rawdata = KNOT_RDATA_WF_BINARY;

	uint8_t format_dname = KNOT_RDATA_WF_LITERAL_DNAME;

	/* 123456 \w 654321 -> result -1 */
	if (knot_rdata_compare(&test_rdata[0],
	                         &test_rdata[1],
	                         &format_rawdata) != -1) {
		diag("RDATA raw data comparison failed 0");
		errors++;
	}

	/* 123456 \w 123456 -> result 0 */
	if (knot_rdata_compare(&test_rdata[0],
	                         &test_rdata[0],
	                         &format_rawdata) != 0) {
		diag("RDATA raw data comparison failed 1 ");
		errors++;
	}

	/* 123456 \w 654321 -> result 1 */
	if (knot_rdata_compare(&test_rdata[1],
	                         &test_rdata[0],
	                         &format_rawdata) != 1) {
		diag("RDATA raw data comparison failed 2");
		errors++;
	}

	/* abcdef.example.com. \w abcdef.foo.com. -> result -1 */
	int ret = 0;
	if ((ret = knot_rdata_compare(&test_rdata[2],
	                         &test_rdata[3],
	                         &format_dname)) >= 0) {
		diag("RDATA dname comparison failed 3");
		errors++;
	}

	/* abcdef.example.com. \w abcdef.example.com. -> result 0 */
	if (knot_rdata_compare(&test_rdata[2],
	                         &test_rdata[2],
	                         &format_dname) != 0) {
		diag("RDATA dname comparison failed 4");
		errors++;
	}

	/* abcdef.example.com. \w abcdef.foo.com -> result 1 */
	if (knot_rdata_compare(&test_rdata[3],
	                         &test_rdata[2],
	                         &format_dname) != 1) {
		diag("RDATA dname comparison failed 5");
		errors++;
	}




	return (errors == 0);
}

/*----------------------------------------------------------------------------*/

//static int test_rdata_wire_size()
//{
//	knot_rdata_t *rdata;
//	int errors = 0;

//	// generate some random data
//	uint8_t data[KNOT_MAX_RDATA_WIRE_SIZE];
//	generate_rdata(data, KNOT_MAX_RDATA_WIRE_SIZE);

//	for (int i = 0; i <= KNOT_RRTYPE_LAST; ++i) {
//		rdata = knot_rdata_new();

//		int size =
//		fill_rdata(data, KNOT_MAX_RDATA_WIRE_SIZE, i, rdata);

//		if (size < 0) {
//			++errors;
//		} else {
//			int counted_size = knot_rdata_wire_size(rdata,
//			    knot_rrtype_descriptor_by_type(i)->wireformat);
//			if (size != counted_size) {
//				diag("Wrong wire size computed (type %d):"
//				     " %d (should be %d)",
//				     i, counted_size, size);
//				++errors;
//			}
//		}

//		knot_rrtype_descriptor_t *desc =
//		    knot_rrtype_descriptor_by_type(i);

//		for (int x = 0; x < desc->length; x++) {
//			if (desc->wireformat[x] ==
//			    KNOT_RDATA_WF_UNCOMPRESSED_DNAME ||
//			    desc->wireformat[x] ==
//			    KNOT_RDATA_WF_COMPRESSED_DNAME ||
//			    desc->wireformat[x] ==
//			    KNOT_RDATA_WF_LITERAL_DNAME) {
//				knot_dname_free(&(rdata->items[x].dname));
//			}
//		}
//		knot_rdata_free(&rdata);
//	}

//	return (errors == 0);
//}

/*----------------------------------------------------------------------------*/

//static int test_rdata_to_wire()
//{
//	knot_rdata_t *rdata;
//	int errors = 0;

//	// generate some random data
//	uint8_t data[KNOT_MAX_RDATA_WIRE_SIZE];
//	uint8_t data_wire[KNOT_MAX_RDATA_WIRE_SIZE];
//	uint8_t rdata_wire[KNOT_MAX_RDATA_WIRE_SIZE];
//	generate_rdata(data, KNOT_MAX_RDATA_WIRE_SIZE);

//	for (int i = 0; i <= KNOT_RRTYPE_LAST; ++i) {
//		rdata = knot_rdata_new();

//		int size =
//		fill_rdata(data, KNOT_MAX_RDATA_WIRE_SIZE, i, rdata);

//		int size_expected =
//	        convert_to_wire(data, KNOT_MAX_RDATA_WIRE_SIZE, i,
//			        data_wire);

//		if (size < 0) {
//			++errors;
//		} else {
//			if (size != size_expected) {
//				diag("Wire format size (%u) not"
//				     " as expected (%u)",
//				     size, size_expected);
//				++errors;
//			} else {
//				if (knot_rdata_to_wire(rdata,
//				    knot_rrtype_descriptor_by_type(i)->
//				    wireformat, rdata_wire,
//				    KNOT_MAX_RDATA_WIRE_SIZE) != 0) {
//					diag("Error while converting RDATA"
//					     " to wire format.");
//					++errors;
//				} else {
//					if (strncmp((char *)data_wire,
//						    (char *)rdata_wire, size)
//					                != 0) {
//						diag("RDATA converted to wire"
//						     "format does not match"
//						     " the expected value");
//						++errors;
//					}
//				}
//			}
//		}

//		knot_rrtype_descriptor_t *desc =
//		knot_rrtype_descriptor_by_type(i);

//		for (int x = 0; x < desc->length; x++) {
//			if (desc->wireformat[x] ==
//			    KNOT_RDATA_WF_UNCOMPRESSED_DNAME ||
//			    desc->wireformat[x] ==
//			    KNOT_RDATA_WF_COMPRESSED_DNAME ||
//			    desc->wireformat[x] ==
//			    KNOT_RDATA_WF_LITERAL_DNAME) {
//				knot_dname_free(&(rdata->items[x].dname));
//			}
//		}
//		knot_rdata_free(&rdata);
//	}

//	return (errors == 0);
//}

static int test_rdata_free()
{
	return 0;
//	knot_rdata_t *tmp_rdata;

//	tmp_rdata = knot_rdata_new();

//	knot_rdata_free(&tmp_rdata);

//	return (tmp_rdata == NULL);
}
/* Can't test this with current implementation
 * would be trying to free pointers on stack */
static int test_rdata_deep_free()
{
	return 0;

/*	int errors = 0;

	knot_rdata_t *tmp_rdata;

	uint8_t data[KNOT_MAX_RDATA_WIRE_SIZE];

	for (int i = 0; i <= KNOT_RRTYPE_LAST; i++) {
		tmp_rdata = knot_rdata_new();

		fill_rdata(data, KNOT_MAX_RDATA_WIRE_SIZE, i, tmp_rdata);

		knot_rdata_deep_free(&tmp_rdata, i, 0);
		errors += (tmp_rdata != NULL);
	}

	return (errors == 0); */
}

/*----------------------------------------------------------------------------*/

static const int KNOT_RDATA_TEST_COUNT = 8;

/*! This helper routine should report number of
 *  scheduled tests for given parameters.
 */
static int knot_rdata_tests_count(int argc, char *argv[])
{
	return KNOT_RDATA_TEST_COUNT;
}

/*! Run all scheduled tests for given parameters.
 */
static int knot_rdata_tests_run(int argc, char *argv[])
{
	int res = 0,
	    res_final = 1;

	res = test_rdata_create();
	ok(res, "rdata: create empty");
	res_final *= res;

	skip(!res, 6);

	todo();

	ok(res = test_rdata_delete(), "rdata: delete");
	//res_final *= res;

	endtodo;

	ok(res = test_rdata_get_item(), "rdata: get item");
	res_final *= res;

	skip(!res, 4)

	ok(res = test_rdata_set_items(), "rdata: set items all at once");
	res_final *= res;

	skip(!res, 3);

	ok(res = test_rdata_set_item(), "rdata: set items one-by-one");
	res_final *= res;

	ok(res = test_rdata_compare(), "rdata: compare");
	res_final *= res;

//	ok(res = test_rdata_wire_size(), "rdata: wire size");
//	res_final *= res;

//	skip(!res, 1);

//	ok(res = test_rdata_to_wire(), "rdata: to wire");
//	res_final *= res;

//	endskip;	/* test_rdata_wire_size() failed */

	endskip;	/* test_rdata_set_items() failed */

	endskip;	/* test_rdata_get_item() failed */

	endskip;	/* test_rdata_create() failed */

	todo();

	ok(res = test_rdata_deep_free(), "rdata: deep free");
	res_final *= res;

	ok(res = test_rdata_free(), "rdata: free");
	res_final *= res;

	endtodo;

	return res_final;
}
