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
#include "libknot/common.h"
#include "libknot/util/descriptor.h"
#include "libknot/rrset.h"
#include "libknot/dname.h"
#include "libknot/rdata.h"
#include "libknot/util/utils.h"
#include "libknot/zone/node.h"
#include "libknot/util/debug.h"

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
	{ {{}, (uint8_t *)"\7example\3com", 13, NULL}, //0's at the end are added
	  {{}, (uint8_t *)"\3ns1\7example\3com", 17, NULL},
	  {{}, (uint8_t *)"\3ns2\7example\3com", 17, NULL} };

/*                         192.168.1.1 */
static uint8_t address[4] = {0xc0, 0xa8, 0x01, 0x01};

static knot_rdata_item_t RR_ITEMS[RR_ITEMS_COUNT] =
	{ {.dname = &RR_DNAMES[1]},
	  {.dname = &RR_DNAMES[2]},
          {.raw_data = (uint16_t *)address} };

/*! \warning Do not change the order. */
/* TODO this does not work as expected */
static knot_rdata_t RR_RDATA[RR_RDATA_COUNT] =
	{ {&RR_ITEMS[0], 1, &RR_RDATA[0]}, /* first ns */
	  {&RR_ITEMS[1], 1, &RR_RDATA[1]}, /* second ns */
	  {&RR_ITEMS[0], 1, &RR_RDATA[3]}, /* both in cyclic list */
	  {&RR_ITEMS[1], 1, &RR_RDATA[2]} };

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

static struct test_rrset test_rrsets[TEST_RRSETS] = {
	{ "example.com.",  KNOT_RRTYPE_NS, KNOT_CLASS_IN,
	  3600, NULL, NULL },
	{ "example2.com.", KNOT_RRTYPE_NS, KNOT_CLASS_IN,
	  3600, NULL, NULL },
	{ "example3.com.", KNOT_RRTYPE_NS, KNOT_CLASS_IN,
	  3600, NULL, NULL },
	{ "example.com.", KNOT_RRTYPE_NS, KNOT_CLASS_IN,
	  3600, NULL, NULL },
	{ "example.com.", KNOT_RRTYPE_NS, KNOT_CLASS_IN,
	  3600, NULL, NULL },
	{ "example.com.", KNOT_RRTYPE_NS, KNOT_CLASS_IN,
	  3600, NULL, NULL }
};

static const struct test_rrset test_rrsigs[TEST_RRSIGS] = {
	{ "example.com.", 46, 1, 3600, NULL },
	{ "example2.com.", 46, 1, 3600, NULL },
	{ "example3.com.", 46, 1, 3600, NULL },
	{ "example4.com.", 46, 1, 3600,	NULL },
	{ "example5.com.", 46, 1, 3600,	NULL },
	{ "example6.com.", 46, 1, 3600, NULL }
};

static void generate_rdata(uint8_t *data, int size)
{
	for (int i = 0; i < size; ++i) {
		data[i] = rand() % 256;
	}
}

static int fill_rdata_r(uint8_t *data, int max_size, uint16_t rrtype,
		      knot_rdata_t *rdata)
{
	assert(rdata != NULL);
	assert(data != NULL);
	assert(max_size > 0);

	uint8_t *pos = data;
	int used = 0;
	int wire_size = 0;

//	note("Filling RRType %u", rrtype);

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
//			note("Created domain name: %s",
//				knot_dname_name(dname));
//			note("Domain name ptr: %p", dname);
			domain = 1;
			size = knot_dname_size(dname);
//			note("Size of created domain name: %u", size);
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

/* fills test_rrsets with random rdata when empty */
static void create_rdata()
{
	knot_rdata_t *r;

	uint8_t *data =
		malloc(sizeof(uint8_t) * KNOT_MAX_RDATA_WIRE_SIZE);

	assert(data);

	for (int i = 0; i < TEST_RRSETS; i++) {
		if (test_rrsets[i].rdata == NULL) {
			r = knot_rdata_new();

			/* from rdata tests */
			generate_rdata(data, KNOT_MAX_RDATA_WIRE_SIZE);
			if (fill_rdata_r(data, KNOT_MAX_RDATA_WIRE_SIZE,
				       test_rrsets[i].type, r) <= 0) {
				diag("Error creating rdata!");

			}

			test_rrsets[i].rdata = r;
		}
	}

	free(data);
}

static int check_rrset(const knot_rrset_t *rrset, int i,
                       int check_rdata, int check_items,
		       int check_rrsigs)
{
	/* following implementation should be self-explanatory */
	int errors = 0;

	if (rrset == NULL) {
		diag("RRSet not created!");
		return 1;
	}

	char *owner = knot_dname_to_str(rrset->owner);
	if (strcmp(owner, test_rrsets[i].owner) != 0) {
		diag("OWNER domain name wrong: '%s' (should be '%s')",
		     owner, test_rrsets[i].owner);
		++errors;
	}
	free(owner);

	if (rrset->type != test_rrsets[i].type) {
		diag("TYPE wrong: %u (should be: %u)", rrset->type,
		     test_rrsets[i].type);
		++errors;
	}

	if (rrset->rclass != test_rrsets[i].rclass) {
		diag("CLASS wrong: %u (should be: %u)", rrset->rclass,
		     test_rrsets[i].rclass);
		++errors;
	}

	if (rrset->ttl != test_rrsets[i].ttl) {
		diag("TTL wrong: %u (should be: %u)", rrset->ttl,
		     test_rrsets[i].ttl);
		++errors;
	}

	if (check_rdata) {
		/* TODO use rdata_compare */
		knot_rdata_t *rdata = rrset->rdata;

		if (rdata == NULL) {
			diag("There are no RDATAs in the RRSet");
			++errors;
		}

		if (rdata != NULL) {
			while (rdata->next != NULL &&
			       rdata->next != rrset->rdata) {
				rdata = rdata->next;
			}
			if (rdata->next == NULL) {
				diag("The list of RDATAs is not cyclic!");
				++errors;
			} else {
				assert(rdata->next == rrset->rdata);
			}
		}
	}

	if (check_items) {
		knot_rrtype_descriptor_t *desc =
			knot_rrtype_descriptor_by_type(rrset->type);
		if (knot_rdata_compare(rrset->rdata,
			                 test_rrsets[i].rdata,
					 desc->wireformat) != 0) {
			diag("Rdata items do not match.");
			errors++;
		}
	}

	/* TODO this deserves a major improvement!!! */

	/*
	 * Will work only with null terminated strings,
	 * consider changing to more versatile implementation
	 */

	/* How about, once it's tested, using rdata_compare */

	if (check_rrsigs) {

		const knot_rrset_t *rrsigs;

		rrsigs = knot_rrset_rrsigs(rrset);
		if (strcmp((const char *)rrsigs->rdata->items[0].raw_data,
		                signature_strings[i])) {
			diag("Signatures are not equal"
			     "to those set when creating."
			     "Comparing %s with %s",
			     rrsigs->rdata->items[0].raw_data,
			     signature_strings[i]);
			errors++;
		}
	}
	return errors;
}

static int test_rrset_create()
{
	int errors = 0;

	for (int i = 0; i < TEST_RRSETS; ++i) {
		knot_dname_t *owner = knot_dname_new_from_str(
		                            test_rrsets[i].owner,
		                            strlen(test_rrsets[i].owner),
		                            NODE_ADDRESS);
		if (owner == NULL) {
			diag("Error creating owner domain name!");
			return 0;
		}
		knot_rrset_t *rrset = knot_rrset_new(owner,
		                                         test_rrsets[i].type,
		                                         test_rrsets[i].rclass,
		                                         test_rrsets[i].ttl);

		errors += check_rrset(rrset, i, 0, 0, 0);

		knot_rrset_free(&rrset);
		knot_dname_free(&owner);
	}

	//diag("Total errors: %d", errors);

	return (errors == 0);
}

/* Not implemented - no way how to test unfreed memory from here (yet) */
static int test_rrset_delete()
{
	return 0;
}

static int test_rrset_add_rdata()
{
	/* rdata add */
	int errors = 0;
	for (int i = 0; i < TEST_RRSETS; i++) {
		knot_dname_t *owner = knot_dname_new_from_str(
		                            test_rrsets[i].owner,
		                            strlen(test_rrsets[i].owner),
		                            NODE_ADDRESS);
		if (owner == NULL) {
			diag("Error creating owner domain name!");
			return 0;
		}

		knot_rrset_t *rrset = knot_rrset_new(owner,
		                                         test_rrsets[i].type,
		                                         test_rrsets[i].rclass,
		                                         test_rrsets[i].ttl);

		knot_rrset_add_rdata(rrset, test_rrsets[i].rdata);

		errors += check_rrset(rrset, i, 1, 0, 0);

		knot_rrset_free(&rrset);
		knot_dname_free(&owner);
	}

	/* test whether adding works properly = keeps order of added elements */

	/*
	 * Beware, this is dependent on the internal structure of rrset and
	 * may change.
	 */

	knot_rrset_t *rrset = knot_rrset_new(NULL, 0, 0, 0);

	knot_rdata_t *r;

	knot_rdata_item_t *item;

	static const char *test_strings[10] =
	    { "-2", "9", "2", "10", "1", "5", "8", "4", "6", "7" };

	/* add items */

	for (int i = 0; i < 10; i++) {
		r = knot_rdata_new();
		item = malloc(sizeof(knot_rdata_item_t));
		item->raw_data = (uint16_t *)test_strings[i];
		//following statement creates a copy
		knot_rdata_set_items(r, item, 1);
		knot_rrset_add_rdata(rrset, r);
		free(item);
	}

	knot_rdata_t *tmp = rrset->rdata;

	/* check if order has been kept */

	int i = 0;
	while (tmp->next != rrset->rdata && !errors) {
		if (strcmp(test_strings[i], (char *)tmp->items[0].raw_data)) {
			diag("Adding RDATA error!, is %s should be %s",
			tmp->items[0].raw_data, test_strings[i]);
			errors++;
		}
		i++;
		tmp = tmp->next;

	}

	tmp = rrset->rdata;

	knot_rdata_t *next;

	while (tmp->next != rrset->rdata) {
		next = tmp->next;
		knot_rdata_free(&tmp);
		tmp = next;
	}

	knot_rdata_free(&tmp);

	knot_rrset_free(&rrset);

	return (errors == 0);
}

static int test_rrset_rrsigs()
{
	int errors = 0;

	knot_rdata_item_t *item;

	knot_rdata_t *tmp;

	knot_dname_t *owner;

	knot_rrset_t *rrset;

	/* Gets rrsigs and checks, if signatures are the same */

	for (int i = 0; i < TEST_RRSETS; i++) {
		owner = knot_dname_new_from_str(test_rrsets[i].owner,
		strlen(test_rrsets[i].owner), NODE_ADDRESS);
		if (owner == NULL) {
			diag("Error creating owner domain name!");
			return 0;
		}

		rrset = knot_rrset_new(owner, test_rrsets[i].type,
		test_rrsets[i].rclass, test_rrsets[i].ttl);

		knot_rrset_add_rdata(rrset, test_rrsets[i].rdata);

		//owners are the same

		assert(TEST_RRSETS == TEST_RRSIGS);

		knot_rrset_t *rrsig = knot_rrset_new(owner,
		                                         test_rrsigs[i].type,
		                                         test_rrsigs[i].rclass,
		                                         test_rrsigs[i].ttl);

		tmp = knot_rdata_new();
		item = malloc(sizeof(knot_rdata_item_t));
		/* signature is just a string,
		 * should be sufficient for testing */
		item->raw_data = (uint16_t *)signature_strings[i];
		knot_rdata_set_items(tmp, item, 1);
		knot_rrset_add_rdata(rrsig, tmp);

		if (knot_rrset_set_rrsigs(rrset, rrsig)
		      != 0) {
			diag("Could not set rrsig");
			errors++;
		}
		errors += check_rrset(rrset, i, 0, 0, 1);
		knot_rrset_free(&rrset);
		free(item);
		knot_rdata_free(&tmp);
		knot_rrset_free(&rrsig);
	}
	return (errors == 0);
}

static int test_rrset_merge()
{
	knot_rrset_t *merger1;
	knot_rrset_t *merger2;
	knot_dname_t *owner1;
	knot_dname_t *owner2;

	int r;

	owner1 = knot_dname_new_from_str(test_rrsets[3].owner,
					   strlen(test_rrsets[3].owner), NULL);
	merger1 = knot_rrset_new(owner1, test_rrsets[3].type,
	                           test_rrsets[3].rclass,
				   test_rrsets[3].ttl);

	knot_rrset_add_rdata(merger1, test_rrsets[3].rdata);

	owner2 = knot_dname_new_from_str(test_rrsets[4].owner,
					   strlen(test_rrsets[4].owner), NULL);
	merger2 = knot_rrset_new(owner2, test_rrsets[4].type,
	                           test_rrsets[4].rclass,
				   test_rrsets[4].ttl);

	knot_rrset_add_rdata(merger2, test_rrsets[4].rdata);

//	knot_rrset_dump(merger1, 1);

	int ret = 0;
	if ((ret = knot_rrset_merge((void **)&merger1,
	                              (void **)&merger2)) != 0) {
		diag("Could not merge rrsets. (reason %d)", ret);
		return 0;
	}

//	knot_rrset_dump(merger1, 1);

	r = check_rrset(merger1, 5, 1, 1, 0);

	knot_rrset_free(&merger1);
	knot_rrset_free(&merger2);

	if (r) {
		diag("Merged rdata are wrongly set.");
		return 0;
	}

	return 1;
}

static int test_rrset_owner(knot_rrset_t **rrsets)
{
	int errors = 0;
	for (int i = 0; i < TEST_RRSETS; i++) {
		char *dname_str =
			knot_dname_to_str(knot_rrset_owner(rrsets[i]));
		if (strcmp(dname_str, test_rrsets[i].owner)) {
			diag("Got wrong value for owner from rrset.");
			errors++;
		}
		free(dname_str);
	}
	return errors;
}

static int test_rrset_type(knot_rrset_t **rrsets)
{
	int errors = 0;
	for (int i = 0; i < TEST_RRSETS; i++) {
		if (knot_rrset_type(rrsets[i]) != test_rrsets[i].type) {
			errors++;
			diag("Got wrong value for type from rrset.");
		}
	}
	return errors;
}

static int test_rrset_class(knot_rrset_t **rrsets)
{
	int errors = 0;
	for (int i = 0; i < TEST_RRSETS; i++) {
		if (knot_rrset_class(rrsets[i]) != test_rrsets[i].rclass) {
			errors++;
			diag("Got wrong value for class from rrset.");
		}
	}

	return errors;
}

static int test_rrset_ttl(knot_rrset_t **rrsets)
{
	int errors = 0;
	for (int i = 0; i < TEST_RRSETS; i++) {
		if (knot_rrset_ttl(rrsets[i]) != test_rrsets[i].ttl) {
			errors++;
			diag("Got wrong value for ttl from rrset.");
		}
	}
	return errors;
}

static int test_rrset_ret_rdata(knot_rrset_t **rrsets)
{
	int errors = 0;

	knot_rrtype_descriptor_t *desc;

	for (int i = 0; i < TEST_RRSETS; i++) {

		desc = knot_rrtype_descriptor_by_type(rrsets[i]->type);
		assert(desc);

//		knot_rdata_dump(test_rrsets[i].rdata, 1);
	//	knot_rdata_dump(rrsets[i]->rdata, 1);

		if (knot_rdata_compare(knot_rrset_rdata(rrsets[i]),
			                 test_rrsets[i].rdata,
					 desc->wireformat)) {
			errors++;
			diag("Got wrong value for rdata from rrset.");
		}
	}
	return errors;
}

static int test_rrset_get_rdata(knot_rrset_t **rrsets)
{
	int errors = 0;

	knot_rrtype_descriptor_t *desc;

	for (int i = 0; i < TEST_RRSETS; i++) {
		desc = knot_rrtype_descriptor_by_type(rrsets[i]->type);
		assert(desc);
		if (knot_rdata_compare(knot_rrset_get_rdata(rrsets[i]),
			                 test_rrsets[i].rdata,
					 desc->wireformat)) {
			errors++;
			diag("Got wrong value for rdata from rrset. (Get)");
		}
	}
	return errors;
}

static int test_rrset_ret_rrsigs(knot_rrset_t **rrsets)
{
	int errors = 0;

	for (int i = 0; i < TEST_RRSETS; i++) {
		/* TODO should I test the insides of structure as well? */
		if (knot_rrset_rrsigs(rrsets[i]) != test_rrsets[i].rrsigs) {
			errors++;
			diag("Got wrong value for rrsigs from rrset.");
		}
	}
	return errors;
}

static int test_rrset_getters(uint type)
{
	int errors = 0;

	knot_rrset_t *rrsets[TEST_RRSETS];

	for (int i = 0; i < TEST_RRSETS; i++) {
		knot_dname_t *owner = knot_dname_new_from_str(
		                            test_rrsets[i].owner,
		                            strlen(test_rrsets[i].owner),
		                            NODE_ADDRESS);
		if (owner == NULL) {
			diag("Error creating owner domain name!");
			return 0;
		}
		rrsets[i] = knot_rrset_new(owner,
		                             test_rrsets[i].type,
		                             test_rrsets[i].rclass,
		                             test_rrsets[i].ttl);

		knot_rrset_add_rdata(rrsets[i], test_rrsets[i].rdata);
	}

	switch (type) {
		case 0: {
			errors += test_rrset_owner(rrsets);
			break;
		}
		case 1: {
			errors += test_rrset_type(rrsets);
			break;
		}
		case 2: {
			errors += test_rrset_class(rrsets);
			break;
		}
		case 3: {
			errors += test_rrset_ttl(rrsets);
			break;
		}
		case 4: {
			errors += test_rrset_ret_rdata(rrsets);
			break;
		}
		case 5: {
			errors += test_rrset_get_rdata(rrsets);
			break;
		}
		case 6: {
			errors += test_rrset_ret_rrsigs(rrsets);
			break;
		}
	} /* switch */

	for (int i = 0; i < TEST_RRSETS; i++) {
		knot_dname_free(&rrsets[i]->owner);
		knot_rrset_free(&rrsets[i]);
	}


	return (errors == 0);
}

static int test_rrset_deep_free()
{
	/*!< \warning Cannot be run when some rdata are on stack! */
	int errors = 0;

	knot_rrset_t  *tmp_rrset;
	knot_dname_t *owner;
	for (int i = 0; i < TEST_RRSETS; i++) {
		owner = knot_dname_new_from_str(
		                            test_rrsets[i].owner,
		                            strlen(test_rrsets[i].owner),
		                            NODE_ADDRESS);
		if (owner == NULL) {
			diag("Error creating owner domain name!");
			return 0;
		}

		tmp_rrset = knot_rrset_new(owner,
		                             test_rrsets[i].type,
		                             test_rrsets[i].rclass,
		                             test_rrsets[i].ttl);

		knot_rrset_add_rdata(tmp_rrset, test_rrsets[i].rdata);

		knot_rrset_deep_free(&tmp_rrset, 1, 1, 0);

		errors += (tmp_rrset != NULL);
	}

	return (errors == 0);
}

/*----------------------------------------------------------------------------*/

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
