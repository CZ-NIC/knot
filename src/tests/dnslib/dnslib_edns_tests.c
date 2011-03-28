/*!
 * \file dnslib_edns_tests.c
 *
 * \author Jan Kadlec <jan.kadlec@nic.cz>
 *
 * Contains unit tests for ENDS API
 *
 * Contains tests for:
 * - ENDS API
 */

#include "dnslib/edns.h"

static int dnslib_edns_tests_count(int argc, char *argv[]);
static int dnslib_edns_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api dnslib_edns_tests_api = {
	"DNS library - EDNS",      //! Unit name
	&dnslib_edns_tests_count,  //! Count scheduled tests
	&dnslib_edns_tests_run     //! Run scheduled tests
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

//static edns_t test_edns[TEST_EDNS] = {
//{ &root_domain,
//  DNSLIB_RRTYPE_OPT,
//  4096,
//  0,
//  0 }
//};

//uint8_t wire[7] =
//{ 0x00, /* root */
//  0x00, 0x29, /* type OPT */
//  0x10, 0x00, /* UDP payload size */
//  0x00, /* higher bits in extended rcode */
//  0x00 }; /* ENDS version */

enum edns_mask {
	DNSLIB_EDNS_DO_MASK = (uint16_t)0x8000
};

static dnslib_opt_rr_t *opt_rr_from_test_edns(test_edns_t *test_edns)
{
	dnslib_opt_rr_t *ret = dnslib_edns_new();

	ret->flags = test_edns->flags;
	ret->ext_rcode = test_edns->ext_rcode;
	ret->payload = test_edns->payload;
	ret->version = test_edns->version;

	for (int i = 0; i < test_edns->option_count; i++) {
		if (dnslib_edns_add_option(ret, test_edns->options[i].code,
					   test_edns->options[i].length,
					   test_edns->options[i].data) != 0) {
			dnslib_edns_free(&ret);
			return NULL;
		}
	}

	return ret;
}

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

/*
  return 0 if same, 1 otherwise (not real compare!)
 */
/*static int compare_edns(const dnslib_opt_rr_t *edns1,
			const dnslib_opt_rr_t *edns2)
{
	if (edns1->ext_rcode != edns2->ext_rcode) {
		return 1;
	}

	if (edns1->payload != edns2->payload) {
		return 1;
	}

	if (edns1->options_max != edns2->options_max) {
		return 1;
	}

	if (edns1->flags != edns2->flags) {
		return 1;
	}

	if (edns1->size != edns2->size) {
		return 1;
	}

	if (edns1->version != edns2->version) {
		return 1;
	}

	if (edns1->version != edns2->version) {
		return 1;
	}

	for (int i = 0)

	return 0;
}*/

static int check_edns(const dnslib_opt_rr_t *edns,
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

static int test_edns_get_payload(const dnslib_opt_rr_t *edns,
				 test_edns_t *test_edns)
{
	if (dnslib_edns_get_payload(edns) !=
	    test_edns->payload) {
		return 0;
	} else {
		return 1;
	}
}

static int test_edns_get_ext_rcode(const dnslib_opt_rr_t *edns,
				   test_edns_t *test_edns)
{
	if (dnslib_edns_get_ext_rcode(edns) !=
	    test_edns->ext_rcode) {
		return 0;
	} else {
		return 1;
	}
}

static int test_edns_get_flags(const dnslib_opt_rr_t *edns,
			       test_edns_t *test_edns)
{
	if (dnslib_edns_get_flags(edns) !=
	    test_edns->flags) {
		return 0;
	} else {
		return 1;
	}
}

static int test_edns_get_version(const dnslib_opt_rr_t *edns,
				 test_edns_t *test_edns)
{
	if (dnslib_edns_get_version(edns) !=
	    test_edns->version) {
		return 0;
	} else {
		return 1;
	}
}

static int test_edns_do(const dnslib_opt_rr_t *edns,
			test_edns_t *test_edns)
{
	if (dnslib_edns_do(edns) !=
	    test_edns->flags & DNSLIB_EDNS_DO_MASK) {
		return 0;
	} else {
		return 1;
	}
}

static int test_edns_size(dnslib_opt_rr_t *edns, test_edns_t *test_edns)
{
	if (dnslib_edns_size(edns) !=
	    test_edns->size) {
		return 0;
	} else {
		return 1;
	}
}

static int test_edns_set_payload(dnslib_opt_rr_t *edns,
				 test_edns_t *test_edns)
{
	dnslib_edns_set_payload(edns, test_edns->payload);

	if (edns->payload !=
	    test_edns->payload) {
		return 0;
	} else {
		return 1;
	}
}

static int test_edns_set_ext_rcode(dnslib_opt_rr_t *edns,
				   test_edns_t *test_edns)
{
	dnslib_edns_set_ext_rcode(edns, test_edns->ext_rcode);
	if (edns->ext_rcode !=
	    test_edns->ext_rcode) {
		return 0;
	} else {
		return 1;
	}
}

/*static int test_edns_set_flags(dnslib_opt_rr_t *edns,
			       test_edns_t *test_edns)
{
	dnslib_edns_set_flags(edns, test_edns->flags);

	if (edns->flags != test_edns->flags) {
		return 0;
	} else {
		return 1;
	}
}*/

static int test_edns_set_version(dnslib_opt_rr_t *edns,
				 test_edns_t *test_edns)
{
	dnslib_edns_set_version(edns,
				test_edns->version);

	if (edns->version !=
	    test_edns->version) {
		return 0;
	} else {
		return 1;
	}
}

static int test_edns_set_do(dnslib_opt_rr_t *edns)
{
	dnslib_edns_set_do(edns);

	if (!dnslib_edns_do(edns)) {
		return 0;
	} else {
		return 1;
	}
}

static int test_edns_getters(uint type)
{
	int errors = 0;
	for (int i = 0; i < TEST_EDNS; i++) {
		dnslib_opt_rr_t *edns =
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

		dnslib_edns_free(&edns);
	}

	return (errors == 0);
}

static int test_edns_setters(uint type)
{
	int errors = 0;
	for (int i = 0; i < TEST_EDNS; i++) {
		dnslib_opt_rr_t *edns =
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

		dnslib_edns_free(&edns);
	}

	return (errors == 0);
}

static int test_edns_wire()
{
	int errors = 0;
	for (int i = 0; i < TEST_EDNS; i++) {
		dnslib_opt_rr_t *edns =
			opt_rr_from_test_edns(&(test_edns_data[i]));
		if (edns == NULL) {
			ERR_ALLOC_FAILED;
			return -1;
		}

		uint8_t *wire = NULL;
		wire = malloc(sizeof(uint8_t) * edns->size);
		CHECK_ALLOC_LOG(wire, 0);

		short wire_size = dnslib_edns_to_wire(edns, wire, 100);

		if (wire_size == -1) {
			diag("Could not create EDNS wire");
			return 0;
		}

		dnslib_opt_rr_t *edns_from_wire = dnslib_edns_new();
		if (edns == NULL) {
			return 0;
		}

		if (dnslib_edns_new_from_wire(edns_from_wire,
					      wire,
					      100) <= 0) {
			diag("Could not create from wire");
			return 0;
		}

		if (check_edns(edns_from_wire,
			      &(test_edns_data[i])) != 0) {
			diag("EDNS created from wire is different from the "
			     "original one");
		}

		free(wire);
		dnslib_edns_free(&edns_from_wire);
		dnslib_edns_free(&edns);
	}
	return 1;
}

static int test_edns_add_option()
{
	/* Create empty EDNS and add options one by one, testing their
	   presence
	*/
	for (int i = 0; i < TEST_EDNS; i++) {
		dnslib_opt_rr_t *edns = dnslib_edns_new();
		assert(edns->option_count == 0);

		if (edns == NULL) {
			ERR_ALLOC_FAILED;
			return 0;
		}

		for (int j = 0; j < test_edns_data[i].option_count; j++) {
			if (dnslib_edns_add_option(edns,
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
		dnslib_edns_free(&edns);
	}
	return 1;
}

static int test_edns_has_option()
{
	/* Create empty EDNS and add options one by one, testing their
	   presence
	*/
	for (int i = 0; i < TEST_EDNS; i++) {
		dnslib_opt_rr_t *edns = dnslib_edns_new();
		assert(edns->option_count == 0);

		if (edns == NULL) {
			ERR_ALLOC_FAILED;
			return 0;
		}

		for (int j = 0; j < test_edns_data[i].option_count; j++) {
			if (dnslib_edns_add_option(edns,
					   test_edns_data[i].options[j].code,
					   test_edns_data[i].options[j].length,
					   test_edns_data[i].options[j].
					   data) != 0) {
				diag("Could not add option");
				return 0;
			}

			if (dnslib_edns_has_option(edns,
				   test_edns_data[i].options[j].code) != 1) {
				diag("Option not found!");
				return 0;
			}
		}
		dnslib_edns_free(&edns);
	}
	return 1;
}

//static int test_edns_get_payload()
//{
//	int errors = 0;

//	for (int i = 0; i < TEST_EDNS; i++) {
//		if (dnslib_edns_get_payload(edns_wire[i]) != test_edns[i].payload) {
//			diag("Got wrong payload from wire");
//			errors++;
//		}
//	}
//	return (errors == 0);
//}

//static int test_edns_get_ext_rcode()
//{
//	int errors = 0;

//	for (int i = 0; i < TEST_EDNS; i++) {
//		if (dnslib_edns_get_ext_rcode(edns_wire[i]) != test_edns[i].ext_rcode) {
//			diag("Got wrong extended rcode from wire");
//			errors++;
//		}
//	}
//	return (errors == 0);
//}

//static int test_edns_get_version()
//{
//	int errors = 0;

//	for (int i = 0; i < TEST_EDNS; i++) {
//		if (dnslib_edns_get_version(edns_wire[i]) != test_edns[i].version) {
//			diag("Got wrong version from wire");
//			errors++;
//		}
//	}
//	return (errors == 0);
//}

//static int test_edns_set_payload()
//{
//	int errors = 0;

//	uint16_t payload = 1024;

//	for (int i = 0; i < TEST_EDNS; i++) {
//		dnslib_edns_set_payload(edns_wire[i], payload);

//		if (dnslib_edns_get_payload(edns_wire[i]) != payload) {
//			diag("Set wrong payload");
//			errors++;
//		}
//	}
//	return (errors == 0);
//}

//static int test_edns_set_ext_rcode()
//{
//	int errors = 0;

//	uint8_t rcode = 0x12;

//	for (int i = 0; i < TEST_EDNS; i++) {
//		dnslib_edns_set_ext_rcode(edns_wire[i], rcode);

//		if (dnslib_edns_get_ext_rcode(edns_wire[i]) != rcode) {
//			diag("Set wrong rcode");
//			errors++;
//		}
//	}
//	return (errors == 0);
//}

//static int test_edns_set_version()
//{
//	int errors = 0;

//	uint8_t version = 1;

//	for (int i = 0; i < TEST_EDNS; i++) {
//		dnslib_edns_set_version(edns_wire[i], version);

//		if (dnslib_edns_get_version(edns_wire[i]) != version) {
//			diag("Set wrong version");
//			errors++;
//		}
//	}
//	return (errors == 0);
//}

static const int DNSLIB_EDNS_TESTS_COUNT = 12;

/*! This helper routine should report number of
 *  scheduled tests for given parameters.
 */
static int dnslib_edns_tests_count(int argc, char *argv[])
{
	return DNSLIB_EDNS_TESTS_COUNT;
}

/*! Run all scheduled tests for given parameters.
 */
static int dnslib_edns_tests_run(int argc, char *argv[])
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
