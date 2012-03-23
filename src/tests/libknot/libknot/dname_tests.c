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

#include <string.h>
#include <assert.h>

#include "tests/libknot/libknot/dname_tests.h"
#include "libknot/dname.h"
#include "libknot/zone/node.h"

static int knot_dname_tests_count(int argc, char *argv[]);
static int knot_dname_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api dname_tests_api = {
	"DNS library - dname",        //! Unit name
	&knot_dname_tests_count,  //! Count scheduled tests
	&knot_dname_tests_run     //! Run scheduled tests
};

/*
 *  Unit implementation.
 */

// C will not accept const int in other const definition
enum { TEST_DOMAINS_OK = 8 };

enum { TEST_DOMAINS_BAD = 5 };

enum { TEST_DOMAINS_NON_FQDN = 6 };

static knot_node_t *NODE_ADDRESS = (knot_node_t *)0xDEADBEEF;

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

static const struct test_domain // sizes are strlen()s here
	test_domains_non_fqdn[TEST_DOMAINS_NON_FQDN] = {
		{ "www", "\3www", 4, "\x0", 1 },
		{ "example", "\7example", 8, "\x0", 1 },
		{ "com", "\3com", 4, "\x0", 1 },
		{ "www.example.com", "\3www\7example\3com", 16, "\x0\x4\xC",
		  3 },
		{ "some", "\4some", 5, "\x0", 1 },
		{ "example.com", "\7example\3com", 12, "\x0\x8", 2 }
	};

static const struct test_domain
		test_domains_bad[TEST_DOMAINS_BAD] = {
	{ NULL, "\2ex\3com", 0, "", 0 },
	{ "ex.com.", NULL, 0, "", 0 },
	{ "ex.com.\5", "\3ex\3com\0\5", 10, "", 0 },
	{ "example.com", "\3example\3com", 12, "\x0\x8", 2 },
	{ "example..", "\7example\0\0", 12, "\x0\x8", 2 }
};

static int test_dname_create()
{
	knot_dname_t *dname = knot_dname_new();
	if (dname == NULL
	    || knot_dname_name(dname) != NULL
	    || knot_dname_size(dname) != 0
	    || knot_dname_node(dname) != NULL) {
		diag("New domain name not initialized properly!");
		return 0;
	}
	knot_dname_free(&dname);
	if (dname != NULL) {
		diag("Pointer to the structure not set to"
		     "NULL when deallocating!");
		return 0;
	}
	return 1;
}

static int test_dname_delete()
{
	// how to test this??
	return 0;
}

static int check_domain_name(const knot_dname_t *dname,
                             const struct test_domain *test_domains, int i,
                             int check_node)
{
	int errors = 0;

	if (dname == NULL) {
		diag("Domain name #%d not created!", i);
		return 1;
	}

	// check size
	if (knot_dname_size(dname) != test_domains[i].size) {
		diag("Bad size of the created domain name: %u (should be %u).",
		     knot_dname_size(dname), test_domains[i].size);
		++errors;
	}
	// check wire format
	uint size = knot_dname_size(dname);
	if (strncmp((char *)knot_dname_name(dname), 
		    test_domains[i].wire, size) != 0) {
		diag("The wire format of the created domain name is wrong:"
		     " '%.*s' (should be '%.*s').", 
		     size, knot_dname_name(dname),
		     size, test_domains[i].wire);
		++errors;
	}
	// check labels
	if (test_domains[i].label_count != dname->label_count) {
		diag("Label count of the created domain name is wrong:"
		     " %d (should be %d)\n", dname->label_count,
		     test_domains[i].label_count);
		++errors;
	}
	if (strncmp((char *)dname->labels, test_domains[i].labels,
		    test_domains[i].label_count) != 0) {
		diag("Label offsets of the created domain name are wrong.\n");
		++errors;
	}

	if (check_node) {
		if (knot_dname_node(dname) != NODE_ADDRESS) {
			diag("Node pointer in the created domain name is wrong:"
			     "%p (should be %p)",
			     knot_dname_node(dname), NODE_ADDRESS);
			++errors;
		}
	}

	return errors;
}

static int test_dname_create_from_str()
{
	int errors = 0;
	knot_dname_t *dname = NULL;

	for (int i = 0; i < TEST_DOMAINS_OK && errors == 0; ++i) {
		//note("testing domain: %s", test_domains_ok[i].str);
		dname = knot_dname_new_from_str(test_domains_ok[i].str,
		          strlen(test_domains_ok[i].str), NODE_ADDRESS);
		errors += check_domain_name(dname, test_domains_ok, i, 1);
		knot_dname_free(&dname);
	}

	return (errors == 0);
}

static int test_dname_create_from_str_non_fqdn()
{
	int errors = 0;
	knot_dname_t *dname = NULL;

	for (int i = 0; i < TEST_DOMAINS_NON_FQDN; ++i) {
//		note("testing domain: %s, size: %zu",
//		     test_domains_non_fqdn[i].str,
//		     strlen(test_domains_non_fqdn[i].str));
		dname = knot_dname_new_from_str(test_domains_non_fqdn[i].str,
		          strlen(test_domains_non_fqdn[i].str), NULL);
		errors += check_domain_name(dname, test_domains_non_fqdn, i, 0);
		knot_dname_free(&dname);
	}

	return (errors == 0);
}

static int test_dname_cat()
{
	int errors = 0;

	/*
	 * This uses three particular dnames from test_domains structure
	 * where the third dname is a concatenation of the first two dnames.
	 */

	knot_dname_t *d1, *d2, *d3;

	d1 = knot_dname_new_from_str(test_domains_non_fqdn[0].str,
	                            strlen(test_domains_non_fqdn[0].str), NULL);
	d2 = knot_dname_new_from_str(test_domains_non_fqdn[1].str,
	                            strlen(test_domains_non_fqdn[1].str), NULL);
	d3 = knot_dname_new_from_str(test_domains_non_fqdn[2].str,
	                            strlen(test_domains_non_fqdn[2].str), NULL);

	knot_dname_cat(d1, d2);
	knot_dname_cat(d1, d3);

	errors += check_domain_name(d1, test_domains_non_fqdn, 3, 0);

	knot_dname_free(&d1);
	knot_dname_free(&d2);
	knot_dname_free(&d3);

	/*
	 * Same thing as above, only different case.
	 */

	d1 = knot_dname_new_from_str(test_domains_non_fqdn[4].str,
	                               strlen(test_domains_non_fqdn[4].str),
	                               NODE_ADDRESS);

	d2 = knot_dname_new_from_str(test_domains_ok[4].str,
	                               strlen(test_domains_ok[4].str),
	                               NODE_ADDRESS);

	knot_dname_cat(d1, d2);

	errors += check_domain_name(d1, test_domains_ok, 1, 1);

	knot_dname_free(&d1);
	knot_dname_free(&d2);

	return (errors == 0);
}

static int test_dname_left_chop()
{
	int errors = 0;

	/* Uses same principle as test_dname_cat(), only reversed */

	/* TODO this would maybe deserver separate structure */

	knot_dname_t *d1;

	d1 = knot_dname_new_from_str(test_domains_ok[1].str,
	                               strlen(test_domains_ok[1].str),
	                               NODE_ADDRESS);

	knot_dname_t *chopped;

	chopped = knot_dname_left_chop(d1);

	errors += check_domain_name(chopped, test_domains_ok, 4, 0);

	knot_dname_free(&d1);
	knot_dname_free(&chopped);

	d1 = knot_dname_new_from_str(test_domains_non_fqdn[3].str,
	                               strlen(test_domains_non_fqdn[3].str),
	                               NODE_ADDRESS);

	chopped = knot_dname_left_chop(d1);

	errors += check_domain_name(chopped, test_domains_non_fqdn, 5, 0);

	knot_dname_free(&d1);
	knot_dname_free(&chopped);

	return (errors == 0);
}

static int test_dname_create_from_wire()
{
	int errors = 0;
	knot_dname_t *dname = NULL;

	for (int i = 0; i < TEST_DOMAINS_OK && errors == 0; ++i) {
		assert(strlen(test_domains_ok[i].wire) + 1 == 
		       test_domains_ok[i].size);
		dname = knot_dname_new_from_wire(
		            (uint8_t *)test_domains_ok[i].wire,
		            test_domains_ok[i].size, NODE_ADDRESS);
		errors += check_domain_name(dname, test_domains_ok, i, 1);
		knot_dname_free(&dname);
	}

	return (errors == 0);
}

static int test_dname_to_str()
{
	int errors = 0;

	/*
	 * Converts dname wireformat to string represenation, which is compared
	 * with entries in test_domains structure.
	 */

	knot_dname_t *dname = NULL;

	for (int i = 0; i < TEST_DOMAINS_OK && errors == 0; ++i) {
		dname = knot_dname_new_from_wire(
		            (uint8_t *)test_domains_ok[i].wire,
		            test_domains_ok[i].size, NODE_ADDRESS);
		char *name_str = knot_dname_to_str(dname);
		if (strcmp(name_str, test_domains_ok[i].str) != 0) {
			diag("Presentation format of domain name wrong:"
			     " %s (should be %s)",
			     name_str, test_domains_ok[i].str);
			++errors;
		}
		free(name_str);
		knot_dname_free(&dname);
	}

	return (errors == 0);
}

/* called by lives_ok */
static int test_faulty_data()
{
	knot_dname_t *dname = NULL;

	/*
	 * This takes dnames from test_domains_bad array, which contains
	 * malformed dnames. TODO add something like: 2www3foo - it's gonna fail
	 */

	for (int i = 0; i < TEST_DOMAINS_BAD; i++) {

		if (test_domains_bad[i].str != NULL) {
			dname = knot_dname_new_from_str(
			            test_domains_bad[i].str,
			            strlen(test_domains_bad[i].str),
			            NODE_ADDRESS);
		} else {
			dname = knot_dname_new_from_str(
			    test_domains_bad[i].str, 0, NODE_ADDRESS);
		}

		knot_dname_free(&dname);

		dname = knot_dname_new_from_wire(
		            (uint8_t *)test_domains_bad[i].wire,
		            test_domains_bad[i].size, NODE_ADDRESS);

		knot_dname_free(&dname);
	}

	return 1; //did it get here? success
}

static int test_dname_compare()
{
	knot_dname_t *dnames[TEST_DOMAINS_OK];

	/* This uses particular dnames from TEST_DOMAINS_OK array */

	for (int i = 0; i < TEST_DOMAINS_OK; ++i) {
		dnames[i] = knot_dname_new_from_wire(
		                (uint8_t *)test_domains_ok[i].wire,
		                test_domains_ok[i].size, NODE_ADDRESS);
	}

	int errors = 0;
	/* abc < some */
	if (knot_dname_compare(dnames[0], dnames[1]) >= 0) {
		diag("Dname comparison error");
		errors++;
        }

	/* abc.test.domain.com. < foo.bar.net. */
	if (knot_dname_compare(dnames[0], dnames[6]) >= 0) {
		diag("Dname comparison error");
		errors++;
	}

        /* foo.bar.net. < . */
	if (knot_dname_compare(dnames[5], dnames[0]) >= 0) {
		diag("Dname comparison error");
		errors++;
	}

        /* bar.net. < foo.bar.net. */
	if (knot_dname_compare(dnames[7], dnames[6]) >= 0) {
		diag("Dname comparison error");
		errors++;
	}

        /* some == some */
	if (knot_dname_compare(dnames[1], dnames[3]) != 0) {
		diag("Dname comparison error");
		errors++;
	}

        /*xyz > some */
	if (knot_dname_compare(dnames[2], dnames[1]) <= 0) {
		diag("Dname comparison error");
		errors++;
	}

        /*foo.bar.net. > xyz.test.domain.com. */
	if (knot_dname_compare(dnames[6], dnames[3]) <= 0) {
		diag("Dname comparison error");
		errors++;
	}

//        /* xyz.test.domain.com. > . */
//	if (knot_dname_compare(dnames[3], dnames[5]) <= 0) {
//		diag("Dname comparison error");
//		errors++;
//	}

        /* bar.net. < foo.bar.net. */
	if (knot_dname_compare(dnames[6], dnames[7]) <= 0) {
		diag("Dname comparison error");
		errors++;
	}

        for (int i = 0; i < TEST_DOMAINS_OK; i++) {
		knot_dname_free(&dnames[i]);
	}

	return (errors == 0);
}

static int test_dname_is_fqdn()
{
	int errors = 0;

	knot_dname_t *dname;

	/* All dnames in TEST_DOMAINS_OK are fqdn */

	for (int i = 0; i < TEST_DOMAINS_OK && !errors; ++i) {
		dname = knot_dname_new_from_wire(
		                (uint8_t *)test_domains_ok[i].wire,
		                test_domains_ok[i].size, NODE_ADDRESS);
		errors += !knot_dname_is_fqdn(dname);
		knot_dname_free(&dname);
	}

	/* None of the following dnames should be fqdn */

	for (int i = 0; i < TEST_DOMAINS_NON_FQDN && !errors; ++i) {
		dname = knot_dname_new_from_str(test_domains_non_fqdn[i].str,
		          strlen(test_domains_non_fqdn[i].str), NULL);
		errors += knot_dname_is_fqdn(dname);
		knot_dname_free(&dname);
	}

	return (errors == 0);
}

static int test_dname_is_subdomain()
{
	int errors = 0;

	knot_dname_t *dnames_fqdn[TEST_DOMAINS_OK];
	knot_dname_t *dnames_non_fqdn[TEST_DOMAINS_NON_FQDN];

	for (int i = 0; i < TEST_DOMAINS_OK; ++i) {
		dnames_fqdn[i] = knot_dname_new_from_wire(
		                (const uint8_t *)test_domains_ok[i].wire,
		                test_domains_ok[i].size, NULL);
		assert(dnames_fqdn[i] != NULL);
	}

	for (int i = 0; i < TEST_DOMAINS_NON_FQDN; ++i) {
		dnames_non_fqdn[i] = knot_dname_new_from_str(
		                test_domains_non_fqdn[i].str,
		                strlen(test_domains_non_fqdn[i].str), NULL);
		assert(dnames_non_fqdn[i] != NULL);
	}

	// fqdn names 0 - 3 should be subdomains of name 4
	knot_dname_t *parent = dnames_fqdn[4];
	for (int i = 0; i < 3; ++i) {
		if (!knot_dname_is_subdomain(dnames_fqdn[i], parent)) {
			diag("(fqdn 1-%d) "
			     "Name %s was not considered subdomain of %s", i,
			     knot_dname_name(dnames_fqdn[i]),
			     knot_dname_name(parent));
			++errors;
		}
	}

	// fqdn names 0 - 4 should be subdomains of name 5 (root)
	parent = dnames_fqdn[5];
	for (int i = 0; i < 4; ++i) {
		if (!knot_dname_is_subdomain(dnames_fqdn[i], parent)) {
			diag("(fqdn 2-%d) "
			     "Name %s was not considered subdomain of %s", i,
			     knot_dname_name(dnames_fqdn[i]),
			     knot_dname_name(parent));
			++errors;
		}
	}

	// non-fqdn names 3 and 5 should be subdomains of non-fqdn name 2
	parent = dnames_non_fqdn[2];
	if (!knot_dname_is_subdomain(dnames_non_fqdn[3], parent)) {
		diag("(non-fqdn 1) "
		     "Name %.*s was not considered subdomain of %.*s",
		     knot_dname_size(dnames_non_fqdn[3]),
		     knot_dname_name(dnames_non_fqdn[3]),
		     knot_dname_size(parent),
		     knot_dname_name(parent));
		++errors;
	}
	if (!knot_dname_is_subdomain(dnames_non_fqdn[5], parent)) {
		diag("(non-fqdn 2) "
		     "Name %.*s was not considered subdomain of %.*s",
		     knot_dname_size(dnames_non_fqdn[5]),
		     knot_dname_name(dnames_non_fqdn[5]),
		     knot_dname_size(parent),
		     knot_dname_name(parent));
		++errors;
	}

	// non-fqdn name 3 should be subdomain of non-fqdn name 5
	parent = dnames_non_fqdn[5];
	if (!knot_dname_is_subdomain(dnames_non_fqdn[3], parent)) {
		diag("(non-fqdn 3) "
		     "Name %.*s was not considered subdomain of %.*s",
		     knot_dname_size(dnames_non_fqdn[3]),
		     knot_dname_name(dnames_non_fqdn[3]),
		     knot_dname_size(parent),
		     knot_dname_name(parent));
		++errors;
	}

	// identical names should not be considered subdomains
	if (knot_dname_is_subdomain(dnames_fqdn[0], dnames_fqdn[0])) {
		diag("(identical names) "
		     "Name %s was considered subdomain of itself",
		     knot_dname_name(dnames_fqdn[0]));
		++errors;
	}
	if (knot_dname_is_subdomain(dnames_fqdn[1], dnames_fqdn[3])) {
		diag("(identical names) "
		     "Name %s was considered subdomain of %s",
		     knot_dname_name(dnames_fqdn[1]),
		     knot_dname_name(dnames_fqdn[3]));
		++errors;
	}

	// fqdn name should not be considered subdomain of non-fqdn name
	if (knot_dname_is_subdomain(dnames_fqdn[1], dnames_non_fqdn[2])) {
		diag("(fqdn subdomain of non-fqdn) "
		     "Name %s was considered subdomain of %.*s",
		     knot_dname_name(dnames_fqdn[1]),
		     knot_dname_size(dnames_non_fqdn[2]),
		     knot_dname_name(dnames_non_fqdn[2]));
		++errors;
	}

	// non-fqdn name should not be considered subdomain of fqdn name
	if (knot_dname_is_subdomain(dnames_fqdn[1], dnames_non_fqdn[2])) {
		diag("(non-fqdn subdomain of fqdn) "
		     "Name %s was considered subdomain of %.*s",
		     knot_dname_name(dnames_fqdn[1]),
		     knot_dname_size(dnames_non_fqdn[2]),
		     knot_dname_name(dnames_non_fqdn[2]));
		++errors;
	}

	// parent name should not be considered subdomain of its subdomain
	if (knot_dname_is_subdomain(dnames_fqdn[4], dnames_fqdn[0])) {
		diag("(ancestor subdomain of name) "
		     "Name %s was considered subdomain of %s",
		     knot_dname_name(dnames_fqdn[4]),
		     knot_dname_name(dnames_fqdn[0]));
		++errors;
	}

	for (int i = 0; i < TEST_DOMAINS_OK; ++i) {
		knot_dname_free(&dnames_fqdn[i]);
	}

	for (int i = 0; i < TEST_DOMAINS_NON_FQDN; ++i) {
		knot_dname_free(&dnames_non_fqdn[i]);
	}

	return (errors == 0);
}

static int test_dname_deep_copy() {
	int errors = 0;

	knot_dname_t *dnames_fqdn[TEST_DOMAINS_OK];
	knot_dname_t *dnames_non_fqdn[TEST_DOMAINS_NON_FQDN];
	knot_dname_t *dnames_fqdn_copy[TEST_DOMAINS_OK];
	knot_dname_t *dnames_non_fqdn_copy[TEST_DOMAINS_NON_FQDN];

	for (int i = 0; i < TEST_DOMAINS_OK; ++i) {
		dnames_fqdn[i] = knot_dname_new_from_wire(
		                (const uint8_t *)test_domains_ok[i].wire,
		                test_domains_ok[i].size, NODE_ADDRESS);
		assert(dnames_fqdn[i] != NULL);
	}

	for (int i = 0; i < TEST_DOMAINS_NON_FQDN; ++i) {
		dnames_non_fqdn[i] = knot_dname_new_from_str(
		                test_domains_non_fqdn[i].str,
		                strlen(test_domains_non_fqdn[i].str),
		                NODE_ADDRESS);
//		note("Created name: %.*s\n", dnames_non_fqdn[i]->size,
//		     dnames_non_fqdn[i]->name);
		assert(dnames_non_fqdn[i] != NULL);
	}

	/*
	 * Create copies of the domain names.
	 */
	for (int i = 0; i < TEST_DOMAINS_OK; ++i) {
//		note("Testing %d. FQDN domain.\n", i);
		dnames_fqdn_copy[i] = knot_dname_deep_copy(dnames_fqdn[i]);
		assert(dnames_fqdn_copy[i] != NULL);
		errors += check_domain_name(dnames_fqdn_copy[i],
		                            test_domains_ok, i, 1);
		knot_dname_free(&dnames_fqdn_copy[i]);
		knot_dname_free(&dnames_fqdn[i]);
	}

	for (int i = 0; i < TEST_DOMAINS_NON_FQDN; ++i) {
//		note("Testing %d. non-FQDN domain: ", i);
//		note("%.*s\n", dnames_non_fqdn[i]->size,
//		     dnames_non_fqdn[i]->name);
		dnames_non_fqdn_copy[i] =
		                knot_dname_deep_copy(dnames_non_fqdn[i]);
		assert(dnames_non_fqdn_copy[i] != NULL);
		errors += check_domain_name(dnames_non_fqdn_copy[i],
		                            test_domains_non_fqdn, i, 1);
		knot_dname_free(&dnames_non_fqdn_copy[i]);
		knot_dname_free(&dnames_non_fqdn[i]);
	}

	return (errors == 0);
}

static int check_wires(const uint8_t *wire1, uint size1,
                         uint8_t *wire2, uint size2)
{
	if (size1 != size2) {
		return 0;
	}

	int i;

	for (i = 0; (i < size1); i++) {
		if (wire1[i] != wire2[i]) {
			return 0;
		}
	}

	return 1;
}

/*!< \note not to be run separately */
static int test_dname_name(knot_dname_t **dnames_fqdn,
                           knot_dname_t **dnames_non_fqdn)
{
	assert(dnames_fqdn);
	assert(dnames_non_fqdn);

	int errors = 0;

	for (int i = 0; i < TEST_DOMAINS_OK; i++) {
		const uint8_t *tmp_name;

		tmp_name = knot_dname_name(dnames_fqdn[i]);
		if (!check_wires(tmp_name, dnames_fqdn[i]->size,
			        (uint8_t *)test_domains_ok[i].wire,
				test_domains_ok[i].size)) {
			diag("Got bad name value from structure: "
			     "%s, should be: %s. Sizes: %d and: %d",
			     tmp_name, test_domains_ok[i].wire,
			     dnames_fqdn[i]->size,
			     test_domains_ok[i].size);
			errors++;
		}
	}

	for (int i = 0; i < TEST_DOMAINS_NON_FQDN; i++) {
		const uint8_t *tmp_name;
		tmp_name = knot_dname_name(dnames_non_fqdn[i]);
		if (!check_wires(tmp_name, dnames_non_fqdn[i]->size,
			        (uint8_t *)test_domains_non_fqdn[i].wire,
				test_domains_non_fqdn[i].size)) {
			diag("Got bad name value from structure: "
			     "%s, should be: %s. Sizes: %d and %d\n",
			     tmp_name, test_domains_non_fqdn[i].wire,
			     dnames_non_fqdn[i]->size,
			     test_domains_non_fqdn[i].size);
//			hex_print(dnames_non_fqdn[i]->name,
//			         dnames_non_fqdn[i]->size);
//			hex_print(test_domains_non_fqdn[i].wire,
//			         test_domains_non_fqdn[i].size);
//			diag("%s and %s\n",
//			     knot_dname_to_str(dnames_non_fqdn[i]),
//			     test_domains_non_fqdn[i]);
			errors++;
		}
	}

	return errors;
}

/* \note not to be run separately */
static int test_dname_size(knot_dname_t **dnames_fqdn,
                           knot_dname_t **dnames_non_fqdn)
{
	assert(dnames_fqdn);
	assert(dnames_non_fqdn);

	int errors = 0;

	for (int i = 0; i < TEST_DOMAINS_OK; i++) {
		uint8_t tmp_size;
		if ((tmp_size = knot_dname_size(dnames_fqdn[i])) !=
		    test_domains_ok[i].size) {
			diag("Got bad size value from structure: "
			     "%u, should be: %u",
			     tmp_size, test_domains_ok[i].size);
			errors++;
		}
	}

	for (int i = 0; i < TEST_DOMAINS_NON_FQDN; i++) {
		uint8_t tmp_size;
		if ((tmp_size = knot_dname_size(dnames_non_fqdn[i])) !=
		    test_domains_non_fqdn[i].size) {
			diag("Got bad size value from structure: "
			     "%u, should be: %u",
			     tmp_size, test_domains_non_fqdn[i].size);
			errors++;
		}
	}

	return errors;
}

/* \note not to be run separately */
static int test_dname_node(knot_dname_t **dnames_fqdn,
                           knot_dname_t **dnames_non_fqdn)
{
	assert(dnames_fqdn);
	assert(dnames_non_fqdn);

	int errors = 0;

	for (int i = 0; i < TEST_DOMAINS_OK; i++) {
		const knot_node_t *tmp_node;
		if ((tmp_node = knot_dname_node(dnames_fqdn[i])) !=
		    NODE_ADDRESS) {
			diag("Got bad node value from structure: "
			     "%p, should be: %p",
			     tmp_node, NODE_ADDRESS);
			errors++;
		}
	}

	for (int i = 0; i < TEST_DOMAINS_NON_FQDN; i++) {
		const knot_node_t *tmp_node;
		if ((tmp_node = knot_dname_node(dnames_non_fqdn[i])) !=
		    NODE_ADDRESS) {
			diag("Got bad node value from structure: "
			     "%s, should be: %s",
			     tmp_node, NODE_ADDRESS);
			errors++;
		}
	}

	return errors;
}

static int test_dname_getters(uint type)
{
	int errors = 0;

	knot_dname_t *dnames_fqdn[TEST_DOMAINS_OK];
	knot_dname_t *dnames_non_fqdn[TEST_DOMAINS_NON_FQDN];

	for (int i = 0; i < TEST_DOMAINS_OK; i++) {
		dnames_fqdn[i] = knot_dname_new_from_wire(
		                (uint8_t *)test_domains_ok[i].wire,
		                test_domains_ok[i].size, NODE_ADDRESS);
		assert(dnames_fqdn[i] != NULL);
	}

	for (int i = 0; i < TEST_DOMAINS_NON_FQDN; i++) {
//		note("Creating dname: %s size: %d\n",
//		     test_domains_non_fqdn[i].wire,
//		     test_domains_non_fqdn[i].size);
		dnames_non_fqdn[i] = knot_dname_new_from_str(
		                test_domains_non_fqdn[i].str,
		                strlen(test_domains_non_fqdn[i].str),
		                NODE_ADDRESS);
		assert(dnames_non_fqdn[i] != NULL);
	}

	switch (type) {
		case 0: {
			errors += test_dname_name(dnames_fqdn, dnames_non_fqdn);
			break;
		}

		case 1: {
			errors += test_dname_size(dnames_fqdn, dnames_non_fqdn);
			break;
		}

		case 2: {
			errors += test_dname_node(dnames_fqdn, dnames_non_fqdn);
			break;
		}
	} /* switch */

	for (int i = 0; i < TEST_DOMAINS_OK; i++) {
		knot_dname_free(&dnames_fqdn[i]);
	}

	for (int i = 0; i < TEST_DOMAINS_NON_FQDN; i++) {
		knot_dname_free(&dnames_non_fqdn[i]);
	}
	
	return (errors == 0);
}

static const int KNOT_DNAME_TEST_COUNT = 16;

/*! This helper routine should report number of
 *  scheduled tests for given parameters.
 */
static int knot_dname_tests_count(int argc, char *argv[])
{
	return KNOT_DNAME_TEST_COUNT;
}

/*! Run all scheduled tests for given parameters.
 */
static int knot_dname_tests_run(int argc, char *argv[])
{
	int res = 0,
	    res_str = 0,
	    res_wire = 0,
	    res_str_non_fqdn = 0,
	    res_final = 1;

	res = test_dname_create();
	ok(res, "dname: create empty");
	res_final *= res;

	skip(!res, 12);

	todo();

	ok((res = test_dname_delete()), "dname: delete");
	//res_final *= res;

	endtodo;

	ok((res_str = test_dname_create_from_str()), "dname: create from str");
	ok((res_wire = test_dname_create_from_wire()),
	   "dname: create from wire");
	ok((res_str_non_fqdn = test_dname_create_from_str_non_fqdn()),
	   "dname: create from str non fqdn");
	res_final *= res_str;
	res_final *= res_wire;
	res_final *= res_str_non_fqdn;

	res = test_dname_getters(0);
	ok(res, "dname: name");

	res = test_dname_getters(1);
	ok(res, "dname: size");

	res = test_dname_getters(2);
	ok(res, "dname: node");

	skip(!res_str || !res_wire || !res_str_non_fqdn, 2);

	ok((res = test_dname_to_str()), "dname: convert to str");
	res_final *= res;

	lives_ok(test_faulty_data(); , "dname: faulty data test");

	endskip;  /* !res_str || !res_wire */

        ok((res = test_dname_compare()), "dname: compare");
        res_final *= res;

	ok((res = test_dname_cat()), "dname: cat");
	res_final *= res;

	ok((res = test_dname_is_fqdn()), "dname: fqdn");
	res_final *= res;

	ok((res = test_dname_left_chop()), "dname: left chop");
	res_final *= res;

	ok((res = test_dname_is_subdomain()), "dname: is subdomain");
	res_final *= res;

	ok((res = test_dname_deep_copy()), "dname: deep copy");
	res_final *= res;

	endskip;  /* create failed */

	return res_final;
}
