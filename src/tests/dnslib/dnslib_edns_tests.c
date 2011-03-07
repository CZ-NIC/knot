/*!
 * \file dnslib_ends_tests.c
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
unit_api dnslib_ends_tests_api = {
	"DNS library - EDNS",      //! Unit name
	&dnslib_edns_tests_count,  //! Count scheduled tests
	&dnslib_edns_tests_run     //! Run scheduled tests
};

/*
 *  Unit implementation.
 */

dnslib_dname_t root_domain = { (uint8_t *)"0", 1, (uint8_t *)"0" , 1, NULL };

enum { TEST_EDNS = 1 };

struct edns {
	dnslib_dname_t *owner;
	uint16_t type;
	uint16_t payload;
	uint8_t ext_rcode;
	uint8_t version;
};

typedef struct edns edns_t;

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

//static uint8_t *edns_wire[TEST_EDNS] = { wire };

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

static const int DNSLIB_EDNS_TESTS_COUNT = 0;

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
//	int res = 0;
	int res_final = 1;

//	res = test_edns_get_payload();
//	ok(res, "ends: get payload");
//	res_final *= res;

//	res = test_edns_get_ext_rcode();
//	ok(res, "ends: get ext. rcode");
//	res_final *= res;

//	res = test_edns_get_version();
//	ok(res, "ends: get version");
//	res_final *= res;

//	res = test_edns_set_payload();
//	ok(res, "ends: set payload");
//	res_final *= res;

//	res = test_edns_set_ext_rcode();
//	ok(res, "ends: set ext. rcode");
//	res_final *= res;

//	res = test_edns_set_version();
//	ok(res, "ends: set version");
//	res_final *= res;

	return res_final;
}
