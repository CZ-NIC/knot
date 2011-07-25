#include <assert.h>
#include <inttypes.h>

//#define RESP_TEST_DEBUG
#include "dnslib/tests/realdata/dnslib_tests_loader_realdata.h"
#include "dnslib/tests/dnslib/response2_tests.h"
#include "common/lists.h"
#include "dnslib/dnslib-common.h"
#include "dnslib/response2.h"
#include "dnslib/rdata.h"
#include "dnslib/rrset.h"
#include "dnslib/dname.h"
#include "dnslib/wire.h"
#include "dnslib/descriptor.h"
#include "dnslib/edns.h"

#ifdef TEST_WITH_LDNS
#include "ldns/ldns.h"
#endif

static int dnslib_response2_tests_count(int argc, char *argv[]);
static int dnslib_response2_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api response2_tests_api = {
	"DNS library - response",      //! Unit name
	&dnslib_response2_tests_count,  //! Count scheduled tests
	&dnslib_response2_tests_run     //! Run scheduled tests
};

static int test_response_init()
{
	int errors = 0;
	int lived = 0;
	lives_ok({
		if (dnslib_response2_init(NULL) != DNSLIB_EBADARG) {
			diag("Calling response_init with NULL packet did "
			     "not return DNSLIB_EBADARG!");
			errors++;
		}
		lived = 1;
	}, "response2: init NULL tests");
	errors += lived != 1;

	dnslib_packet_t *response =
		dnslib_packet_new(DNSLIB_PACKET_PREALLOC_QUERY);
	response->max_size = DNSLIB_WIRE_HEADER_SIZE - 1;
	if (dnslib_response2_init(response) != DNSLIB_ESPACE) {
		diag("Calling response_init too small packet did "
		     "not return DNSLIB_ESPACE!");
		errors++;
	}

	return (errors == 0);
}

static int test_response_init_query()
{
	int errors = 0;
	int lived = 0;
	lives_ok({
		if (dnslib_response2_init_from_query(NULL, NULL) !=
		    DNSLIB_EBADARG) {
			diag("Calling response_init_query with NULL packet and "
			     "NULL query did not return DNSLIB_EBADARG!");
			errors++;
		}
		lived = 1;
		dnslib_packet_t *response =
			dnslib_packet_new(DNSLIB_PACKET_PREALLOC_RESPONSE);
		lived = 0;
		if (dnslib_response2_init_from_query(response, NULL) !=
		    DNSLIB_EBADARG) {
			diag("Calling response_init_query with NULL query "
			     "did not return DNSLIB_EBADARG!");
			errors++;
		}
		lived = 1;
		dnslib_packet_t *query =
			dnslib_packet_new(DNSLIB_PACKET_PREALLOC_QUERY);
		if (dnslib_response2_init_from_query(NULL, query) !=
		    DNSLIB_EBADARG) {
			diag("Calling response_init_query with NULL response "
			     "did not return DNSLIB_EBADARG!");
			errors++;
		}
	}, "response2: init from query NULL tests");
	errors += lived != 1;

	/* Cannot test the rest of return values, since there is now constant
	 * controlling value that could return DNSLIB_EDNAMEPTR */

	return (errors == 0);
}

static int test_response_clear()
{
	int errors = 0;
	int lived = 0;
	lives_ok({
		dnslib_response2_clear(NULL, 1);
	}, "response2: clear NULL tests");

	/*
	 * Create new response, convert to wire, then add something, clear
	 * the response, convert to wire again and compare wires.
	 */

	dnslib_packet_t *response =
		dnslib_response_new(DNSLIB_PACKET_PREALLOC_RESPONSE);

	uint8_t *original_wire = NULL;
	size_t original_size = 0;
	assert(dnslib_packet_to_wire(response, &original_wire,
	                             &original_size) ==
	       DNSLIB_EOK);
	/* Do something in question section. */
//	test_dname_t test_dname;
//	test_dname.str = "ns8.nic.cz.";
//	dnslib_dname_t *dname = dname_from_test_dname_str(&test_dname);
//	assert(dname);

	response->question.qtype = DNSLIB_RRTYPE_HINFO;
	response->question.qclass = DNSLIB_CLASS_CH;

	uint8_t *question_changed_wire = NULL;
	uint8_t question_changed_size = 0;
	assert(dnslib_packet_to_wire(response,
	                             &question_changed_wire,
	                             &question_changed_size) ==
	       DNSLIB_EOK);

	dnslib_response2_set_aa(response);
	dnslib_response2_set_tc(response);
	dnslib_response2_set_rcode(response, dnslib_quick_rand());

	dnslib_response2_clear(response, 0);
	uint8_t *new_wire = NULL;
	size_t new_size = 0;
	assert(dnslib_packet_to_wire(response, &new_wire, &new_size) ==
	       DNSLIB_EOK);
	if (question_changed_size != new_size) {
		diag("Wrong wire size after calling response_clear!");
		errors++;
	} else {
		if (compare_wires_simple(question_changed_wire,
		                         new_wire, new_size)) {
			diag("Wrong wire after calling response_clear!");
			errors++;
		}
	}
	free(new_wire);

	dnslib_response2_clear(response, 1);
	assert(dnslib_packet_to_wire(response, &new_wire, &new_size) ==
	       DNSLIB_EOK);

	if (original_size != new_size) {
		diag("Wrong wire size after calling response_clear!");
		errors++;
	} else {
		if (compare_wires_simple(original_wire,
		                         new_wire, new_size)) {
			diag("Wrong wire after calling response_clear!");
			errors++;
		}
	}

	free(new_wire);
	free(original_wire);
	free(question_changed_wire);
	dnslib_packet_free(&response);

	return (errors == 0);
}

static int test_response_add_opt()
{
	int errors = 0;
	int lived = 0;

	dnslib_opt_rr_t opt;
	opt.payload = 512;
	opt.ext_rcode = 0;
	opt.version = EDNS_VERSION_0;
	opt.flags = 0;
	opt.options = NULL;
	opt.option_count = 0;
	opt.options_max = 0;
	opt.size = 25; // does it matter?

	lives_ok({
		if (dnslib_response2_add_opt(NULL, NULL, 0) != DNSLIB_EBADARG) {
			diag("Calling response add opt with NULL arguments "
			     "did not result to DNSLIB_EBADARG");
			errors++;
		}
		lived = 1;
		dnslib_packet_t *response =
			dnslib_packet_new(DNSLIB_PACKET_PREALLOC_RESPONSE);
		assert(response);
		lived = 0;
		if (dnslib_response2_add_opt(response,
		                             NULL, 0) != DNSLIB_EBADARG) {
			diag("Calling response add opt with NULL OPT RR "
			     "did not result to DNSLIB_EBADARG");
			errors++;
		}
		lived = 1;

		lived = 0;
		if (dnslib_response2_add_opt(NULL,
		                             &opt, 0) != DNSLIB_EBADARG) {
			diag("Calling response add opt with NULL response "
			     "did not result to DNSLIB_EBADARG");
			errors++;
		}
		lived = 1;
		dnslib_packet_free(&response);
	}, "response2: add opt NULL tests");
	errors += lived != 1;

	dnslib_packet_t *response =
		dnslib_packet_new(DNSLIB_PACKET_PREALLOC_RESPONSE);
	assert(response);

	if (dnslib_response2_add_opt(response, &opt, 0) != DNSLIB_EOK) {
		diag("Adding valid OPT RR to response "
		     "did not return DNSLIB_EOK");
		errors++;
	}

	opt.payload = response->max_size + 1;
	if (dnslib_response2_add_opt(response, &opt, 1) != DNSLIB_EPAYLOAD) {
		diag("If OPT RR payload is bigger than response max size "
		     "response_add_opt does not return DNSLIB_EPAYLOAD!");
		errors++;
	}

	opt.payload = 0;
	if (dnslib_response2_add_opt(response, &opt, 1) != DNSLIB_EBADARG) {
		diag("Calling response_add_opt with OPT RR payload set to 0 "
		     "did not return DNSLIB_EBADARG");
	}

	dnslib_packet_free(&response);
	return (errors == 0);
}

static int test_response_add_generic(int (func*)(dnslib_packet_t *,
                                                 const dnslib_rrset_t *,
                                                 int, int, int))
{
	int errors = 0;
	int lived = 0;

	lives_ok({
		if (func(NULL, NULL, 0, 0, 0) != DNSLIB_EBADARG) {
			diag("Calling response add rrset with NULL "
			     "arguments did not return DNSLIB_EBADARG!");
			errors++;
		}
		lived = 1;
		dnslib_packet_t *response =
			dnslib_packet_new(DNSLIB_PACKET_PREALLOC_RESPONSE);
		assert(response);
		lived = 0;
		if (func(response, NULL, 0, 0, 0) != DNSLIB_EBADARG) {
			diag("Calling response add rrset with NULL rrset "
			     "did not return DNSLIB_EBADARG!");
			errors++;
		}
		lived = 1;
		dnslib_dname_t *owner =
			dnslib_dname_new_from_str("ns.nic.cz.",
			                          strlen("ns.nic.cz."),
			                          NULL);
		assert(owner);
		dnslib_rrset_t *rrset =
			dnslib_rrset_new(owner, DNSLIB_RRTYPE_A,
			                 DNSLIB_CLASS_IN, 3600);
		assert(rrset);
		lived = 0;
		if (func(NULL, rrset, 0, 0, 0) != DNSLIB_EBADARG) {
			diag("Calling response add rrset with NULL response "
			     "did not return DNSLIB_EBADARG!");
			errors++;
		}
		lived = 1;
		dnslib_rrset_deep_free(&rrset, 1, 0, 0,);
		dnslib_packet_free(&response);
	}, "response2: rrset adding NULL tests");
	errors += lived != 1;

	/*!< \todo Test case when DNSLIB_ESPACE should be returned. */
	/*!< \todo Compression and so on - should it be tested here? */

	dnslib_packet_t *response =
		dnslib_packet_new(DNSLIB_PACKET_PREALLOC_RESPONSE);
	assert(response);

	dnslib_dname_t *owner =
		dnslib_dname_new_from_str("ns12.nic.cz.",
		                          strlen("ns12.nic.cz."),
		                          NULL);
	assert(owner);
	dnslib_rrset_t *rrset =
		dnslib_rrset_new(owner, DNSLIB_RRTYPE_NS,
		                 DNSLIB_CLASS_IN, 3600);
	assert(rrset);
	if (func(response, rrset, 0, 0, 0) != DNSLIB_EOK) {
		diag("Adding valid RRSet to response did not result to "
		     "DNSLIB_EOK");
		errors++;
	}

	dnslib_rrset_deep_free(&rrset, 1, 0, 0);
	dnslib_packet_free(&response);

	return (errors == 0);
}

static void test_response_add_rrset()
{
	ok(test_response_add_generic(dnslib_response2_add_rrset_answer),
	   "response: add answer rrset");
	ok(test_response_add_generic(dnslib_response2_add_rrset_authority),
	   "response: add answer authority");
	ok(test_response_add_generic(dnslib_response2_add_rrset_additional),
	   "response: add answer additional");
}

static int test_response_add_nsid()
{
	int errors = 0;
	int lived = 0;

	dnslib_packet_t *response =
		dnslib_packet_new(DNSLIB_PACKET_PREALLOC_RESPONSE);
	assert(response);

	uint8_t *nsid = (uint8_t *)"knotDNS";
	uint16_t nsid_size = length((char *)nsid);
	lives_ok({
		if (dnslib_response2_add_nsid(NULL,
		                              NULL, 1) != DNSLIB_EBADARG) {
			diag("Calling response add nsid with NULL arguments "
			     "did not return DNSLIB_EBADARG");
			errors++;
		}
		lives = 1;

		lives = 0;
		if (dnslib_response2_add_nsid(NULL, nsid,
		                              nsid_size) != DNSLIB_EBADARG) {
			diag("Calling response add nsid with NULL response "
			     "did not return DNSLIB_EBADARG");
			errors++;
		}
		lived = 1;
		lives = 0;
		if (dnslib_response2_add_nsid(response, nsid,
		                              0) != DNSLIB_EBADARG) {
			diag("Calling response add nsid with zero size "
			     "did not return DNSLIB_EBADARG");
			errors++;
		}
		lived = 1;
	}, "response: add nsid NULL tests");

	if (dnslib_response2_add_nsid(response, nsid,
	                              nsid_size) != DNSLIB_EOK) {
		diag("Adding valid nsid to response did not return DNSLIB_EOK");
		errors++;
	}

	dnslib_packet_free(&response);
	return (errors == 0);
}

static const int DNSLIB_RESPONSE2_TEST_COUNT = 12;

/*! This helper routine should report number of
 *  scheduled tests for given parameters.
 */
static int dnslib_response2_tests_count(int argc, char *argv[])
{
	return DNSLIB_RESPONSE2_TEST_COUNT;
}


/*! Run all scheduled tests for given parameters.
 */
static int dnslib_response2_tests_run(int argc, char *argv[])
{

}
