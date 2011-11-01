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
#include <stdarg.h>

#include "tests/libknot/realdata/libknot_tests_loader_realdata.h"
#include "tests/libknot/realdata/libknot/dname_tests_realdata.h"
#include "libknot/dname.h"
#include "libknot/common.h"

#include "common/print.h"
#include "common/lists.h"

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

int check_domain_name(const knot_dname_t *dname,
                      const test_dname_t *test_dname)
{
	int errors = 0;

	if (dname == NULL) {
		diag("Domain name not created!");
		return 1;
	}

//	diag("test_dname: %p, dname: %p", test_dname, dname);
	// check size
	if (knot_dname_size(dname) != test_dname->size) {
		diag("Bad size of the created domain name: %u (should be %u).",
		     knot_dname_size(dname), test_dname->size);
		++errors;
	} else {
		// check wire format
		uint size = knot_dname_size(dname);
		if (strncmp((char *)knot_dname_name(dname),
		            (char *)test_dname->wire, size) != 0) {
			diag("The wire format of the created "
			     "domain name is wrong:"
			     " '%.*s' (should be '%.*s').",
			     size, knot_dname_name(dname),
			     size, test_dname->wire);
			++errors;
		}
	}
	// check labels
	if (test_dname->label_count != dname->label_count) {
		diag("Label count of the created domain name is wrong:"
		     " %d (should be %d)\n", dname->label_count,
		     test_dname->label_count);
		++errors;
	}
	if (strncmp((char *)dname->labels, (char *)test_dname->labels,
		    test_dname->label_count) != 0) {
		diag("Label offsets of the created domain name are wrong.\n");
		hex_print((char *)dname->labels, test_dname->label_count);
		hex_print((char *)test_dname->labels, test_dname->label_count);
		++errors;
	}

	return errors;
}

static int test_dname_create_from_str(const list *dname_list)
{
	int errors = 0;
	knot_dname_t *dname = NULL;

	/* Test with real data. */
	node *n = NULL;
	WALK_LIST(n, *dname_list) {
		//note("testing domain: %s", test_domains_ok[i].str);
		test_dname_t *test_dname = (test_dname_t *)n;
		dname = knot_dname_new_from_str(test_dname->str,
			  strlen(test_dname->str), NULL);
		errors += check_domain_name(dname, test_dname);
		knot_dname_free(&dname);
	}

	return (errors == 0);
}

static int test_dname_create_from_wire(const list *dname_list)
{
	int errors = 0;
	knot_dname_t *dname = NULL;

	node *n = NULL;
	WALK_LIST(n, *dname_list) {
		test_dname_t *test_dname = (test_dname_t *)n;
		dname = knot_dname_new_from_wire(test_dname->wire,
		                                   test_dname->size, NULL);
		errors += check_domain_name(dname, test_dname);
		knot_dname_free(&dname);
	}

	return (errors == 0);
}

static int test_dname_to_str(const list *dname_list)
{
	int errors = 0;

	/*
	 * Converts dname wireformat to string represenation, which is compared
	 * with entries in test_domains structure.
	 */

	knot_dname_t *dname = NULL;

	/* Test with real data. */
	node *n = NULL;
	WALK_LIST(n, *dname_list) {
		//note("testing domain: %s", test_domains_ok[i].str);
		test_dname_t *test_dname = (test_dname_t *)n;
		dname = knot_dname_new_from_wire(
		                        test_dname->wire,
		                        test_dname->size,
		                        NULL);
		if (dname == NULL) {
			ERR_ALLOC_FAILED;
			return 0;
		}

		char *name_str = knot_dname_to_str(dname);
		if (strcmp(name_str, test_dname->str) != 0) {
			diag("Presentation format of domain name wrong:"
			     " %s (should be %s)",
			     name_str, test_dname->str);
			++errors;
		}
		free(name_str);
		knot_dname_free(&dname);
	}

	return (errors == 0);
}

static int test_dname_is_fqdn(const list *dname_list)
{
	int errors = 0;

	knot_dname_t *dname;

	/* All dnames from real data are fqdn */

	node *n = NULL;
	WALK_LIST(n, *dname_list) {
		test_dname_t *test_dname = (test_dname_t *)n;
		dname = knot_dname_new_from_wire(test_dname->wire,
		                                   test_dname->size, NULL);
		errors += !knot_dname_is_fqdn(dname);
		knot_dname_free(&dname);
	}

	return (errors == 0);
}

//static int check_wires(const uint8_t *wire1, uint size1,
//			 uint8_t *wire2, uint size2)
//{
//	if (size1 != size2) {
//		return 0;
//	}

//	int i;

//	for (i = 0; (i < size1); i++) {
//		if (wire1[i] != wire2[i]) {
//			return 0;
//		}
//	}

//	return 1;
//}

///* \note not to be run separately */
//static int test_dname_name(knot_dname_t **dnames_fqdn,
//			   knot_dname_t **dnames_non_fqdn)
//{
//	assert(dnames_fqdn);
//	assert(dnames_non_fqdn);

//	int errors = 0;

//	for (int i = 0; i < TEST_DOMAINS_OK; i++) {
//		const uint8_t *tmp_name;
//		tmp_name = knot_dname_name(dnames_fqdn[i]);
//		if (!check_wires(tmp_name, dnames_fqdn[i]->size,
//				(uint8_t *)test_domains_ok[i].wire,
//				test_domains_ok[i].size)) {
//			diag("Got bad name value from structure: "
//			     "%s, should be: %s",
//			     tmp_name, test_domains_ok[i].wire);
//			errors++;
//		}
//	}

//	for (int i = 0; i < TEST_DOMAINS_NON_FQDN; i++) {
//		const uint8_t *tmp_name;
//		tmp_name = knot_dname_name(dnames_non_fqdn[i]);
//		if (!check_wires(tmp_name, dnames_non_fqdn[i]->size,
//				(uint8_t *)test_domains_non_fqdn[i].wire,
//				test_domains_non_fqdn[i].size)) {
//			diag("Got bad name value from structure: "
//			     "%s, should be: %s",
//			     tmp_name, test_domains_non_fqdn[i].wire);
//			errors++;
//		}
//	}

//	return errors;
//}

///* \note not to be run separately */
//static int test_dname_size(knot_dname_t **dnames_fqdn,
//			   knot_dname_t **dnames_non_fqdn)
//{
//	assert(dnames_fqdn);
//	assert(dnames_non_fqdn);

//	int errors = 0;

//	for (int i = 0; i < TEST_DOMAINS_OK; i++) {
//		uint8_t tmp_size;
//		if ((tmp_size = knot_dname_size(dnames_fqdn[i])) !=
//		    test_domains_ok[i].size) {
//			diag("Got bad size value from structure: "
//			     "%u, should be: %u",
//			     tmp_size, test_domains_ok[i].size);
//			errors++;
//		}
//	}

//	for (int i = 0; i < TEST_DOMAINS_NON_FQDN; i++) {
//		uint8_t tmp_size;
//		if ((tmp_size = knot_dname_size(dnames_non_fqdn[i])) !=
//		    test_domains_non_fqdn[i].size) {
//			diag("Got bad size value from structure: "
//			     "%u, should be: %u",
//			     tmp_size, test_domains_non_fqdn[i].size);
//			errors++;
//		}
//	}

//	return errors;
//}

///* \note not to be run separately */
//static int test_dname_node(knot_dname_t **dnames_fqdn,
//			   knot_dname_t **dnames_non_fqdn)
//{
//	assert(dnames_fqdn);
//	assert(dnames_non_fqdn);

//	int errors = 0;

//	for (int i = 0; i < TEST_DOMAINS_OK; i++) {
//		const knot_node_t *tmp_node;
//		if ((tmp_node = knot_dname_node(dnames_fqdn[i])) !=
//		    NODE_ADDRESS) {
//			diag("Got bad node value from structure: "
//			     "%p, should be: %p",
//			     tmp_node, NODE_ADDRESS);
//			errors++;
//		}
//	}

//	for (int i = 0; i < TEST_DOMAINS_NON_FQDN; i++) {
//		const knot_node_t *tmp_node;
//		if ((tmp_node = knot_dname_node(dnames_non_fqdn[i])) !=
//		    NODE_ADDRESS) {
//			diag("Got bad node value from structure: "
//			     "%s, should be: %s",
//			     tmp_node, NODE_ADDRESS);
//			errors++;
//		}
//	}

//	return errors;
//}

//static int test_dname_getters(uint type)
//{
//	int errors = 0;

//	knot_dname_t *dnames_fqdn[TEST_DOMAINS_OK];
//	knot_dname_t *dnames_non_fqdn[TEST_DOMAINS_NON_FQDN];

//	for (int i = 0; i < TEST_DOMAINS_OK; i++) {
//		dnames_fqdn[i] = knot_dname_new_from_wire(
//				(uint8_t *)test_domains_ok[i].wire,
//				test_domains_ok[i].size, NODE_ADDRESS);
//		assert(dnames_fqdn[i] != NULL);
//	}

//	for (int i = 0; i < TEST_DOMAINS_NON_FQDN; i++) {
//		dnames_non_fqdn[i] = knot_dname_new_from_wire(
//				(uint8_t *)test_domains_non_fqdn[i].wire,
//				test_domains_non_fqdn[i].size, NODE_ADDRESS);
//		assert(dnames_non_fqdn[i] != NULL);
//	}

//	switch (type) {
//		case 0: {
//			errors += test_dname_name(dnames_fqdn, dnames_non_fqdn);
//			break;
//		}

//		case 1: {
//			errors += test_dname_size(dnames_fqdn, dnames_non_fqdn);
//			break;
//		}

//		case 2: {
//			errors += test_dname_node(dnames_fqdn, dnames_non_fqdn);
//			break;
//		}
//	} /* switch */

//	for (int i = 0; i < TEST_DOMAINS_OK; i++) {
//		knot_dname_free(&dnames_fqdn[i]);
//	}

//	for (int i = 0; i < TEST_DOMAINS_NON_FQDN; i++) {
//		knot_dname_free(&dnames_non_fqdn[i]);
//	}

//	return (errors == 0);
//}

static const int KNOT_DNAME_TEST_COUNT = 4;

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
	const test_data_t *data = data_for_knot_tests;

	int res = 0,
	    res_str = 0,
	    res_wire = 0,
	    res_str_non_fqdn = 0,
	    res_final = 1;

	ok((res_str = test_dname_create_from_str(&data->dname_list)),
	   "dname: create from string");
	ok((res_wire = test_dname_create_from_wire(&data->dname_list)),
	   "dname: create from wire");

	res_final *= res_str;
	res_final *= res_wire;
	res_final *= res_str_non_fqdn;

//	res = test_dname_getters(0);
//	ok(res, "dname: name");

//	res = test_dname_getters(1);
//	ok(res, "dname: size");

//	res = test_dname_getters(2);
//	ok(res, "dname: node");

//	skip(!res_str || !res_wire || !res_str_non_fqdn, 2);

	ok((res = test_dname_to_str(&data->dname_list)),
	   "dname: convert to str");
	res_final *= res;

//	endskip;  /* !res_str || !res_wire */

	ok((res = test_dname_is_fqdn(&data->dname_list)), "dname: fqdn");
	res_final *= res;

	return res_final;
}
