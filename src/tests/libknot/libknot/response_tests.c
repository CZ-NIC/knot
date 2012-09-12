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
#include <inttypes.h>

//#define RESP_TEST_DEBUG
#include "tests/libknot/realdata/libknot_tests_loader_realdata.h"
#include "tests/libknot/libknot/response_tests.h"
#include "common/lists.h"
#include "libknot/common.h"
#include "libknot/packet/response.h"
#include "libknot/rdata.h"
#include "libknot/rrset.h"
#include "libknot/dname.h"
#include "libknot/util/wire.h"
#include "libknot/util/descriptor.h"
#include "libknot/edns.h"

#ifdef TEST_WITH_LDNS
#include "ldns/ldns.h"
#endif

static int knot_response_tests_count(int argc, char *argv[]);
static int knot_response_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api response_tests_api = {
	"DNS library - response",      //! Unit name
	&knot_response_tests_count,  //! Count scheduled tests
	&knot_response_tests_run     //! Run scheduled tests
};

static int test_response_init()
{
	int errors = 0;
	int lived = 0;
	lives_ok({
		if (knot_response_init(NULL) != KNOT_EINVAL) {
			diag("Calling response_init with NULL packet did "
			     "not return KNOT_EINVAL!");
			errors++;
		}
		lived = 1;
	}, "response: init NULL tests");
	errors += lived != 1;

	knot_packet_t *response =
		knot_packet_new(KNOT_PACKET_PREALLOC_QUERY);
	assert(response);
	response->max_size = KNOT_WIRE_HEADER_SIZE - 1;
	if (knot_response_init(response) != KNOT_ESPACE) {
		diag("Calling response_init too small packet did "
		     "not return KNOT_ESPACE!");
		errors++;
	}

	return (errors == 0);
}

static int test_response_init_query()
{
	int errors = 0;
	int lived = 0;
	lives_ok({
		if (knot_response_init_from_query(NULL, NULL) !=
		    KNOT_EINVAL) {
			diag("Calling response_init_query with NULL packet and "
			     "NULL query did not return KNOT_EINVAL!");
			errors++;
		}
		lived = 1;
		knot_packet_t *response =
			knot_packet_new(KNOT_PACKET_PREALLOC_RESPONSE);
		assert(response);
		knot_packet_set_max_size(response,
		                           KNOT_PACKET_PREALLOC_RESPONSE);
		knot_response_init(response);
		lived = 0;
		if (knot_response_init_from_query(response, NULL) !=
		    KNOT_EINVAL) {
			diag("Calling response_init_query with NULL query "
			     "did not return KNOT_EINVAL!");
			errors++;
		}
		lived = 1;
		knot_packet_t *query =
			knot_packet_new(KNOT_PACKET_PREALLOC_QUERY);
		if (knot_response_init_from_query(NULL, query) !=
		    KNOT_EINVAL) {
			diag("Calling response_init_query with NULL response "
			     "did not return KNOT_EINVAL!");
			errors++;
		}
	}, "response: init from query NULL tests");
	errors += lived != 1;

	/* Cannot test the rest of return values, since there is now constant
	 * controlling value that could return KNOT_EDNAMEPTR */

	return (errors == 0);
}

int compare_wires_simple(uint8_t *wire1, uint8_t *wire2, uint count)
{
	int i = 0;
	while (i < count &&
	       wire1[i] == wire2[i]) {
		i++;
	}
	return (!(count == i));
}


//static int test_response_clear()
//{
//	int errors = 0;
//	int lived = 0;
//	lives_ok({
//		knot_response_clear(NULL, 1);
//		lived = 1;
//	}, "response: clear NULL tests");
//	errors += lived != 1;

//	/*
//	 * Create new response, convert to wire, then add something, clear
//	 * the response, convert to wire again and compare wires.
//	 */

//	knot_packet_t *response =
//		knot_packet_new(KNOT_PACKET_PREALLOC_RESPONSE);
//	knot_packet_set_max_size(response, KNOT_WIRE_HEADER_SIZE * 100);
//	assert(knot_response_init(response) == KNOT_EOK);

//	uint8_t *original_wire = NULL;
//	size_t original_size = 0;
//	assert(knot_packet_to_wire(response, &original_wire,
//	                             &original_size) ==
//	       KNOT_EOK);
//	/* Do something in question section. */
////	test_dname_t test_dname;
////	test_dname.str = "ns8.nic.cz.";
////	knot_dname_t *dname = dname_from_test_dname_str(&test_dname);
////	assert(dname);

//	response->question.qtype = KNOT_RRTYPE_HINFO;
//	response->question.qclass = KNOT_CLASS_CH;

//	uint8_t *question_changed_wire = NULL;
//	size_t question_changed_size = 0;
//	assert(knot_packet_to_wire(response,
//	                             &question_changed_wire,
//	                             &question_changed_size) ==
//	       KNOT_EOK);

//	knot_response_set_aa(response);
//	knot_response_set_tc(response);
//	knot_response_set_rcode(response, knot_quick_rand());

//	knot_response_clear(response, 0);
//	uint8_t *new_wire = NULL;
//	size_t new_size = 0;
//	assert(knot_packet_to_wire(response, &new_wire, &new_size) ==
//	       KNOT_EOK);
//	if (question_changed_size != new_size) {
//		diag("Wrong wire size after calling response_clear! "
//		     "got %d should be %d", new_size, question_changed_size);
//		errors++;
//	} else {
//		if (compare_wires_simple(question_changed_wire,
//		                         new_wire, new_size)) {
//			diag("Wrong wire after calling response_clear! ");
//			errors++;
//		}
//	}
//	free(new_wire);

//	new_wire = NULL;
//	new_size = 0;

//	/*!< \todo figure out this segfault! */

////	knot_response_clear(response, 1);
////	assert(knot_packet_to_wire(response, &new_wire, &new_size) ==
////	       KNOT_EOK);

////	if (original_size != new_size) {
////		diag("Wrong wire size after calling response_clear!");
////		errors++;
////	} else {
////		if (compare_wires_simple(original_wire,
////		                         new_wire, new_size)) {
////			diag("Wrong wire after calling response_clear!");
////			errors++;
////		}
////	}

////	free(new_wire);
////	free(original_wire);
////	free(question_changed_wire);
////	knot_packet_free(&response);

//	return (errors == 0);
//}

static int test_response_add_opt()
{
	int errors = 0;
	int lived = 0;

	knot_opt_rr_t opt;
	opt.payload = 512;
	opt.ext_rcode = 0;
	opt.version = EDNS_VERSION_0;
	opt.flags = 0;
	opt.options = NULL;
	opt.option_count = 0;
	opt.options_max = 0;
	opt.size = 25; // does it matter?

	lives_ok({
		if (knot_response_add_opt(NULL, NULL, 0, 0) != KNOT_EINVAL) {
			diag("Calling response add opt with NULL arguments "
			     "did not result to KNOT_EINVAL");
			errors++;
		}
		lived = 1;
		knot_packet_t *response =
			knot_packet_new(KNOT_PACKET_PREALLOC_RESPONSE);
		assert(response);
		lived = 0;
		if (knot_response_add_opt(response,
		                             NULL, 0, 0) != KNOT_EINVAL) {
			diag("Calling response add opt with NULL OPT RR "
			     "did not result to KNOT_EINVAL");
			errors++;
		}
		lived = 1;

		lived = 0;
		if (knot_response_add_opt(NULL,
		                             &opt, 0, 0) != KNOT_EINVAL) {
			diag("Calling response add opt with NULL response "
			     "did not result to KNOT_EINVAL");
			errors++;
		}
		lived = 1;
		knot_packet_free(&response);
	}, "response: add opt NULL tests");
	errors += lived != 1;

	knot_packet_t *response =
		knot_packet_new(KNOT_PACKET_PREALLOC_RESPONSE);
	assert(response);
	knot_packet_set_max_size(response, KNOT_PACKET_PREALLOC_RESPONSE * 100);
	assert(knot_response_init(response) == KNOT_EOK);;

	if (knot_response_add_opt(response, &opt, 0, 0) != KNOT_EOK) {
		diag("Adding valid OPT RR to response "
		     "did not return KNOT_EOK");
		errors++;
	}

	opt.payload = response->max_size + 1;
	if (knot_response_add_opt(response, &opt, 1, 0) != KNOT_EPAYLOAD) {
		diag("If OPT RR payload is bigger than response max size "
		     "response_add_opt does not return KNOT_EPAYLOAD!");
		errors++;
	}

	opt.payload = 0;
	if (knot_response_add_opt(response, &opt, 1, 0) != KNOT_EINVAL) {
		diag("Calling response_add_opt with OPT RR payload set to 0 "
		     "did not return KNOT_EINVAL");
	}

	knot_packet_free(&response);
	return (errors == 0);
}

static int test_response_add_generic(int (*func)(knot_packet_t *,
                                                 knot_rrset_t *,
                                                 int, int, int, int))
{
	int errors = 0;
	int lived = 0;

	lives_ok({
		if (func(NULL, NULL, 0, 0, 0, 0) != KNOT_EINVAL) {
			diag("Calling response add rrset with NULL "
			     "arguments did not return KNOT_EINVAL!");
			errors++;
		}
		lived = 1;
		knot_packet_t *response =
			knot_packet_new(KNOT_PACKET_PREALLOC_RESPONSE);
		assert(response);
		lived = 0;
		if (func(response, NULL, 0, 0, 0, 0) != KNOT_EINVAL) {
			diag("Calling response add rrset with NULL rrset "
			     "did not return KNOT_EINVAL!");
			errors++;
		}
		lived = 1;
		knot_dname_t *owner =
			knot_dname_new_from_str("ns.nic.cz.",
			                          strlen("ns.nic.cz."),
			                          NULL);
		assert(owner);
		knot_rrset_t *rrset =
			knot_rrset_new(owner, KNOT_RRTYPE_A,
			                 KNOT_CLASS_IN, 3600);
		assert(rrset);
		lived = 0;
		if (func(NULL, rrset, 0, 0, 0, 0) != KNOT_EINVAL) {
			diag("Calling response add rrset with NULL response "
			     "did not return KNOT_EINVAL!");
			errors++;
		}
		lived = 1;
		knot_rrset_deep_free(&rrset, 1, 0, 0);
		knot_packet_free(&response);
	}, "response: rrset adding NULL tests");
	errors += lived != 1;

	/*!< \todo Test case when KNOT_ESPACE should be returned. */
	/*!< \todo Compression and so on - should it be tested here? */

	knot_packet_t *response =
		knot_packet_new(KNOT_PACKET_PREALLOC_RESPONSE);
	assert(response);

	knot_dname_t *owner =
		knot_dname_new_from_str("ns12.nic.cz.",
		                          strlen("ns12.nic.cz."),
		                          NULL);
	assert(owner);
	knot_rrset_t *rrset =
		knot_rrset_new(owner, KNOT_RRTYPE_NS,
		                 KNOT_CLASS_IN, 3600);
	assert(rrset);
	if (func(response, rrset, 0, 0, 0, 0) != KNOT_EOK) {
		diag("Adding valid RRSet to response did not result to "
		     "KNOT_EOK");
		errors++;
	}

	knot_rrset_deep_free(&rrset, 1, 0, 0);
	knot_packet_free(&response);

	return (errors == 0);
}

static void test_response_add_rrset()
{
	ok(test_response_add_generic(knot_response_add_rrset_answer),
	   "response: add answer rrset");
	ok(test_response_add_generic(knot_response_add_rrset_authority),
	   "response: add answer authority");
	ok(test_response_add_generic(knot_response_add_rrset_additional),
	   "response: add answer additional");
}

static int test_response_add_nsid()
{
	int errors = 0;
	int lived = 0;

	knot_packet_t *response =
		knot_packet_new(KNOT_PACKET_PREALLOC_RESPONSE);
	assert(response);

	uint8_t *nsid = (uint8_t *)"knotDNS";
	uint16_t nsid_size = strlen((char *)nsid);
	lives_ok({
		if (knot_response_add_nsid(NULL,
		                              NULL, 1) != KNOT_EINVAL) {
			diag("Calling response add nsid with NULL arguments "
			     "did not return KNOT_EINVAL");
			errors++;
		}
		lived = 1;

		lived = 0;
		if (knot_response_add_nsid(NULL, nsid,
		                              nsid_size) != KNOT_EINVAL) {
			diag("Calling response add nsid with NULL response "
			     "did not return KNOT_EINVAL");
			errors++;
		}
		lived = 1;
//		lived = 0;
//		if (knot_response_add_nsid(response, nsid,
//		                              0) != KNOT_EINVAL) {
//			diag("Calling response add nsid with zero size "
//			     "did not return KNOT_EINVAL");
//			errors++;
//		}
//		lived = 1;
	}, "response: add nsid NULL tests");
	errors += lived != 1;

	if (knot_response_add_nsid(response, nsid,
	                              nsid_size) != KNOT_EOK) {
		diag("Adding valid nsid to response did not return KNOT_EOK");
		errors++;
	}

	knot_packet_free(&response);
	return (errors == 0);
}

static const int KNOT_response_TEST_COUNT = 14;

/*! This helper routine should report number of
 *  scheduled tests for given parameters.
 */
static int knot_response_tests_count(int argc, char *argv[])
{
	return KNOT_response_TEST_COUNT;
}


/*! Run all scheduled tests for given parameters.
 */
static int knot_response_tests_run(int argc, char *argv[])
{
	ok(test_response_init(), "response: init");
	ok(test_response_init_query(), "response: init from query");
//	ok(test_response_clear(), "response: clear");
	ok(test_response_add_opt(), "response: add opt");
	test_response_add_rrset();
	ok(test_response_add_nsid(), "response: add nsid");
	return 1;
}
