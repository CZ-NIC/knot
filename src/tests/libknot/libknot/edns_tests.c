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

#include "tests/libknot/libknot/edns_tests.h"
#include "libknot/common.h"
#include "libknot/edns.h"

static int knot_edns_tests_count(int argc, char *argv[]);
static int knot_edns_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api edns_tests_api = {
	"DNS library - EDNS",      //! Unit name
	&knot_edns_tests_count,  //! Count scheduled tests
	&knot_edns_tests_run     //! Run scheduled tests
};

/*
 *  Unit implementation.
 */

enum { TEST_EDNS = 1, OPTION_COUNT = 3 };

struct test_edns_options {
	uint16_t code;
	uint16_t length;
	uint8_t *data;
};

struct test_edns {
	struct test_edns_options *options;
	uint16_t payload;
	uint8_t ext_rcode;
	uint8_t version;
	uint16_t flags;
	short option_count;
	short options_max;
	short size;
};

typedef struct test_edns test_edns_t;

struct test_edns_options test_options_data[OPTION_COUNT] = {
	{5, 7, (uint8_t *)"123456"},
	{4, 3, (uint8_t *)"12"},
	{1, 5, (uint8_t *)"13333"}
};

test_edns_t test_edns_data[TEST_EDNS] = {
{ NULL, 4096, 2, 0, 0, 0, 10, 11}
};

enum edns_mask {
	KNOT_EDNS_DO_MASK = (uint16_t)0x8000
};

/* Creates actual knot_opt_rr_t variable from test_edns_t variable */
static knot_opt_rr_t *opt_rr_from_test_edns(test_edns_t *test_edns)
{
	knot_opt_rr_t *ret = knot_edns_new();

	CHECK_ALLOC_LOG(ret, NULL);

	ret->flags = test_edns->flags;
	ret->ext_rcode = test_edns->ext_rcode;
	ret->payload = test_edns->payload;
	ret->version = test_edns->version;

	for (int i = 0; i < test_edns->option_count; i++) {
		if (knot_edns_add_option(ret, test_edns->options[i].code,
					   test_edns->options[i].length,
					   test_edns->options[i].data) != 0) {
			knot_edns_free(&ret);
			return NULL;
		}
	}

	return ret;
}

/* simple wire compare - 0 if same, 1 otherwise */
static int edns_compare_wires(uint8_t *wire1,
			      uint8_t *wire2,
			      uint16_t length)
{
	for (uint i = 0; i < length; i++) {
		if (wire1[i] != wire2[i]) {
			return 1;
		}
	}

	return 0;
}

static int check_edns(const knot_opt_rr_t *edns,
		      const test_edns_t *test_edns)
{
	if (edns->option_count != test_edns->option_count) {
		diag("Option count is wrong");
		return -1;
	}

	for (int i = 0; i < edns->option_count; i++) {
		/* check options */
		if (edns->options[i].code != test_edns->options[i].code) {
			diag("Code in options is wrong");
			return -1;
		}

		if (edns->options[i].length != test_edns->options[i].length) {
			diag("Length in options is wrong");
			return -1;
		}

		if (edns_compare_wires(edns->options[i].data,
				       test_edns->options[i].data,
				       edns->options[i].length) != 0)  {
			diag("Data in options are wrong");
			return -1;
		}
	}

	if (edns->version != test_edns->version) {
		diag("Version is wrong");
		return -1;
	}

	if (edns->flags != test_edns->flags) {
		diag("Flags are wrong");
		return -1;
	}

	if (edns->size != test_edns->size) {
		diag("Size is wrong");
		return -1;
	}

	return 0;
}

static int test_edns_get_payload(const knot_opt_rr_t *edns,
				 test_edns_t *test_edns)
{
	if (knot_edns_get_payload(edns) !=
	    test_edns->payload) {
		return 0;
	} else {
		return 1;
	}
}

static int test_edns_get_ext_rcode(const knot_opt_rr_t *edns,
				   test_edns_t *test_edns)
{
	if (knot_edns_get_ext_rcode(edns) !=
	    test_edns->ext_rcode) {
		return 0;
	} else {
		return 1;
	}
}

static int test_edns_get_flags(const knot_opt_rr_t *edns,
			       test_edns_t *test_edns)
{
	if (knot_edns_get_flags(edns) !=
	    test_edns->flags) {
		return 0;
	} else {
		return 1;
	}
}

static int test_edns_get_version(const knot_opt_rr_t *edns,
				 test_edns_t *test_edns)
{
	if (knot_edns_get_version(edns) !=
	    test_edns->version) {
		return 0;
	} else {
		return 1;
	}
}

static int test_edns_do(const knot_opt_rr_t *edns,
			test_edns_t *test_edns)
{
	if (knot_edns_do(edns) !=
	    (test_edns->flags & KNOT_EDNS_DO_MASK)) {
		return 0;
	} else {
		return 1;
	}
}

static int test_edns_size(knot_opt_rr_t *edns, test_edns_t *test_edns)
{
	if (knot_edns_size(edns) !=
	    test_edns->size) {
		return 0;
	} else {
		return 1;
	}
}

static int test_edns_set_payload(knot_opt_rr_t *edns,
				 test_edns_t *test_edns)
{
	knot_edns_set_payload(edns, test_edns->payload);

	if (edns->payload !=
	    test_edns->payload) {
		return 0;
	} else {
		return 1;
	}
}

static int test_edns_set_ext_rcode(knot_opt_rr_t *edns,
				   test_edns_t *test_edns)
{
	knot_edns_set_ext_rcode(edns, test_edns->ext_rcode);
	if (edns->ext_rcode !=
	    test_edns->ext_rcode) {
		return 0;
	} else {
		return 1;
	}
}

static int test_edns_set_version(knot_opt_rr_t *edns,
				 test_edns_t *test_edns)
{
	knot_edns_set_version(edns,
				test_edns->version);

	if (edns->version !=
	    test_edns->version) {
		return 0;
	} else {
		return 1;
	}
}

static int test_edns_set_do(knot_opt_rr_t *edns)
{
	knot_edns_set_do(edns);

	if (!knot_edns_do(edns)) {
		return 0;
	} else {
		return 1;
	}
}

static int test_edns_getters(uint type)
{
	int errors = 0;
	for (int i = 0; i < TEST_EDNS; i++) {
		knot_opt_rr_t *edns =
			opt_rr_from_test_edns(&(test_edns_data[i]));
		if (edns == NULL) {
			ERR_ALLOC_FAILED;
			return -1;
		}

		switch(type) {
		case 0:
			if (test_edns_get_payload(edns,
						  &test_edns_data[i]) != 1) {
				diag("Got wrong payload!");
				errors++;
			}
			break;
		case 1:
			if (test_edns_get_ext_rcode(edns,
						    &test_edns_data[i]) != 1) {
				diag("Got wrong extended RCODE!");
				errors++;
			}
			break;
		case 2:
			if (test_edns_get_flags(edns,
						&test_edns_data[i]) != 1) {
				diag("Got wrong flags!");

				errors++;
			}
			break;
		case 3:
			if (test_edns_get_version(edns,
						  &test_edns_data[i]) != 1) {
				diag("Got wrong version!");
				errors++;
			}
			break;
		case 4:
			if (test_edns_do(edns,
					 &test_edns_data[i]) != 1) {
				diag("Got wrong DO bit!");
				errors++;
			}
			break;
		case 5:
			if (test_edns_size(edns,
					   &test_edns_data[i]) != 1) {
				diag("Got wrong size!");
				errors++;
			}
			break;
		default:
			diag("Unknown option");
			errors++;
		} /* switch */

		knot_edns_free(&edns);
	}

	return (errors == 0);
}

static int test_edns_setters(uint type)
{
	int errors = 0;
	for (int i = 0; i < TEST_EDNS; i++) {
		knot_opt_rr_t *edns =
			opt_rr_from_test_edns(&(test_edns_data[i]));
		if (edns == NULL) {
			ERR_ALLOC_FAILED;
			return -1;
		}

		switch(type) {
		case 0:
			if (test_edns_set_payload(edns,
						  &test_edns_data[i]) != 1) {
				diag("Set wrong payload!");
				errors++;
			}
			break;
		case 1:
			if (test_edns_set_ext_rcode(edns,
						    &test_edns_data[i]) != 1) {
				diag("Set wrong ext_rcode");
				errors++;
			}
			break;
		case 2:
			if (test_edns_set_version(edns,
						  &test_edns_data[i]) != 1) {
				diag("Set wrong version!");
				errors++;
			}
			break;
		case 3:
			if (test_edns_set_do(edns) != 1) {
				diag("Set wrong DO bit!");
				errors++;
			}
			break;
		default:
			diag("Unknown option");
			errors++;
		} /* switch */

		knot_edns_free(&edns);
	}

	return (errors == 0);
}

static int test_edns_wire()
{
	/*
	 * Tests to_wire and from_wire in one test.
	 */
	for (int i = 0; i < TEST_EDNS; i++) {
		/* Creates instance from test_edns_t. */
		knot_opt_rr_t *edns =
			opt_rr_from_test_edns(&(test_edns_data[i]));
		if (edns == NULL) {
			ERR_ALLOC_FAILED;
			return -1;
		}

		uint8_t *wire = NULL;
		wire = malloc(sizeof(uint8_t) * edns->size);
		CHECK_ALLOC_LOG(wire, 0);

		/* Converts EDNS to wire. */
		short wire_size = knot_edns_to_wire(edns, wire, 100);

		if (wire_size == -1) {
			diag("Could not create EDNS wire");
			return 0;
		}

		knot_opt_rr_t *edns_from_wire = knot_edns_new();
		if (edns == NULL) {
			return 0;
		}

		/* TODO use some constant */
		/* Creates new EDNS from wire */
		if (knot_edns_new_from_wire(edns_from_wire,
					      wire,
					      100) <= 0) {
			diag("Could not create from wire");
			return 0;
		}

		/* Checks whether EDNS created from wire is the same */
		if (check_edns(edns_from_wire,
			      &(test_edns_data[i])) != 0) {
			diag("EDNS created from wire is different from the "
			     "original one");
		}

		free(wire);
		knot_edns_free(&edns_from_wire);
		knot_edns_free(&edns);
	}
	return 1;
}

static int test_edns_add_option()
{
	/*
	 * Create empty EDNS and add options one by one, testing their presence.
	 */
	for (int i = 0; i < TEST_EDNS; i++) {
		knot_opt_rr_t *edns = knot_edns_new();
		assert(edns->option_count == 0);

		if (edns == NULL) {
			ERR_ALLOC_FAILED;
			return 0;
		}

		for (int j = 0; j < test_edns_data[i].option_count; j++) {
			if (knot_edns_add_option(edns,
					   test_edns_data[i].options[j].code,
					   test_edns_data[i].options[j].length,
					   test_edns_data[i].options[j].
					   data) != 0) {
				diag("Could not add option");
				return 0;
			}

			if (edns->options[j].code !=
			    test_edns_data[i].options[j].code) {
				diag("Option code wrongly added!");
				return 0;
			}

			if (edns->options[j].length !=
			    test_edns_data[i].options[j].length) {
				diag("Option length wrongly added!");
				return 0;
			}

			if (edns_compare_wires(edns->options[j].data,
					       test_edns_data[i].
					       options[j].data,
					       edns->options[j].length) != 0) {
				diag("Option wire wrongly added!");
				return 0;
			}
		}
		knot_edns_free(&edns);
	}
	return 1;
}

static int test_edns_has_option()
{
	/*
	 * Create empty EDNS and add options one by one, testing their presence
	 */
	for (int i = 0; i < TEST_EDNS; i++) {
		knot_opt_rr_t *edns = knot_edns_new();
		assert(edns->option_count == 0);

		if (edns == NULL) {
			ERR_ALLOC_FAILED;
			return 0;
		}

		for (int j = 0; j < test_edns_data[i].option_count; j++) {
			if (knot_edns_add_option(edns,
					   test_edns_data[i].options[j].code,
					   test_edns_data[i].options[j].length,
					   test_edns_data[i].options[j].
					   data) != 0) {
				diag("Could not add option");
				return 0;
			}

			if (knot_edns_has_option(edns,
				   test_edns_data[i].options[j].code) != 1) {
				diag("Option not found!");
				return 0;
			}
		}
		knot_edns_free(&edns);
	}
	return 1;
}

static const int KNOT_EDNS_TESTS_COUNT = 12;

/*! This helper routine should report number of
 *  scheduled tests for given parameters.
 */
static int knot_edns_tests_count(int argc, char *argv[])
{
	return KNOT_EDNS_TESTS_COUNT;
}

/*! Run all scheduled tests for given parameters.
 */
static int knot_edns_tests_run(int argc, char *argv[])
{
	int res = 0;
	int res_final = 1;

	res = test_edns_getters(0);
	ok(res, "ends: get payload");
	res_final *= res;

	res = test_edns_getters(1);
	ok(res, "ends: get extenden RCODE");
	res_final *= res;

	res = test_edns_getters(2);
	ok(res, "ends: get flags");
	res_final *= res;

	res = test_edns_getters(3);
	ok(res, "ends: get version");
	res_final *= res;

	res = test_edns_getters(4);
	ok(res, "ends: do");
	res_final *= res;

	res = test_edns_getters(5);
	ok(res, "ends: size");
	res_final *= res;

	res = test_edns_setters(0);
	ok(res, "ends: set payload");
	res_final *= res;

	res = test_edns_setters(1);
	ok(res, "ends: set extended RCODE");
	res_final *= res;

	res = test_edns_setters(2);
	ok(res, "ends: set version");
	res_final *= res;

	res = test_edns_setters(3);
	ok(res, "ends: set DO");
	res_final *= res;

	res = test_edns_add_option();
	ok(res, "ends: add option");
	res_final *= res;

	res = test_edns_has_option();
	ok(res, "ends: has option");
	res_final *= res;

	res = test_edns_wire();
	ok(res, "ends: to_wire and from_wire");
	res_final *= res;

	return res_final;
}
