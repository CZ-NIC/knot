/* blame: jan.kadlec@nic.cz */

#include <assert.h>
#include <stdint.h>

#include "packet_tests.h"
#include "dnslib/error.h"
#include "dnslib/packet.h"
#include "dnslib/wire.h"
/* *test_t structures */
#include "dnslib/tests/realdata/dnslib_tests_loader_realdata.h"

static int packet_tests_count(int argc, char *argv[]);
static int packet_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api packet_tests_api = {
	"packet",     //! Unit name
	&packet_tests_count,  //! Count scheduled tests
	&packet_tests_run     //! Run scheduled tests
};

static int test_packet_new()
{
	int errors = 0;
	dnslib_packet_t *packet =
		dnslib_packet_new(DNSLIB_PACKET_PREALLOC_NONE);
	if (packet == NULL) {
		diag("Could not create packet using prealloc_node constant!");
		errors++;
	}
	dnslib_packet_free(&packet);

	packet = dnslib_packet_new(DNSLIB_PACKET_PREALLOC_QUERY);
	if (packet == NULL) {
		diag("Could not create packet using prealloc_query constant!");
		errors++;
	}
	dnslib_packet_free(&packet);

	packet = dnslib_packet_new(DNSLIB_PACKET_PREALLOC_RESPONSE);
	if (packet == NULL) {
		diag("Could not create packet using prealloc_resp constant!");
		errors++;
	}
	dnslib_packet_free(&packet);

	/*!< \todo Should it create packet using any size? */

	return (errors == 0);
}

static int test_packet_parse_from_wire()
{
	int errors = 0;
	dnslib_packet_t *packet =
		dnslib_packet_new(DNSLIB_PACKET_PREALLOC_QUERY);

	int tmp = 0;
	lives_ok({
		if (dnslib_packet_parse_from_wire(NULL, NULL, 0, 0) !=
		    DNSLIB_EBADARG) {
			diag("Trying to parse NULL packet with NULL wire "
			     "did not return DNSLIB_EBADARG!");
			errors++;
		}
		tmp = 1;
		tmp = 0;
		if (dnslib_packet_parse_from_wire(packet, NULL, 0, 0) !=
		    DNSLIB_EBADARG) {
			diag("Trying to parse with NULL wire "
			     "did not return DNSLIB_EBADARG!");
			errors++;
		}
		tmp = 1;
		tmp = 0;
		if (dnslib_packet_parse_from_wire(packet, (uint8_t *)0xbeef,
		                                  0, 0) !=
		    DNSLIB_EFEWDATA) {
			diag("Trying to parse 0 lengt"
			     "did not return DNSLIB_EOK!");
			errors++;
		}
		tmp = 1;
	}, "packet: parse from wire NULL tests.");
	errors += tmp != 1;

	dnslib_packet_free(&packet);

	return (errors == 0);
}

static int test_packet_parse_next_rr_answer()
{
	int errors = 0;
	dnslib_packet_t *packet =
		dnslib_packet_new(DNSLIB_PACKET_PREALLOC_RESPONSE);
	assert(packet);

	int tmp = 0;
	lives_ok({
		int ret = 0;
		if (dnslib_packet_parse_next_rr_answer(NULL, NULL) !=
		    DNSLIB_EBADARG) {
			diag("Trying to parse next RR answer with "
			     "NULL packet with and NULL RRSet "
			     "did not return DNSLIB_EBADARG!");
			errors++;
		}
		tmp = 1;
		tmp = 0;
		if ((ret = dnslib_packet_parse_next_rr_answer(packet,
		                                              NULL)) !=
		    DNSLIB_EBADARG) {
			diag("Trying to parse next RR with NULL RRSet pointer "
			     "did not return DNSLIB_EBADARG! Got %d.",
			     ret);
			errors++;
		}
		tmp = 1;
		dnslib_rrset_t *rrset = 0xaaaa;
		tmp = 0;
		if (dnslib_packet_parse_next_rr_answer(packet,
		                                       &rrset) !=
		    DNSLIB_EBADARG) {
			diag("Trying to parse next RR answer with rrset pointer"
			     " not pointing to NULL did not "
			     "return DNSLIB_EBADARG!");
			errors++;
		}
		tmp = 1;
	}, "packet: parse next rr answer NULL tests.");
	errors += tmp != 1;

	dnslib_packet_free(&packet);

	return (errors == 0);
}

static int test_packet_parse_rest()
{
	int res = 0;
	lives_ok({res *= dnslib_packet_parse_rest(NULL);},
	"packet: parse rest NULL test");

	dnslib_packet_t *packet =
		dnslib_packet_new(DNSLIB_PACKET_PREALLOC_NONE);
	assert(packet);

	lives_ok({res *= dnslib_packet_parse_rest(packet);},
	"packet: parser rest empty packet");

	dnslib_packet_free(&packet);

	return res;
}


static int test_packet_set_max_size()
{
	int errors = 0;
	dnslib_packet_t *packet =
		dnslib_packet_new(DNSLIB_PACKET_PREALLOC_NONE);
	assert(packet);

	int lived = 0;

	lives_ok({
		lived = 0;
		if (dnslib_packet_set_max_size(NULL, 1) != DNSLIB_EBADARG) {
			diag("Calling packet_set_max() with NULL packet "
			     "did not return DNSLIB_EBADARG");
			errors++;
		}
		lived = 1;
	}, "packet: set max size NULL test");

	errors += lived != 1;

	if (dnslib_packet_set_max_size(packet, 0) != DNSLIB_EBADARG) {
		diag("Calling packet_set_max() with size eqeal to 0 did not "
		     "return DNSLIB_EBADARG");
		errors++;
	}

	if (dnslib_packet_set_max_size(packet, 10) != DNSLIB_EOK) {
		diag("Calling packet_set_max() with valid arguments did not "
		     "return DNSLIB_EOK");
		errors++;
	}

	dnslib_packet_free(&packet);

	return (errors == 0);
}

static int test_packet_add_tmp_rrset()
{
	int errors = 0;
	int lived = 0;

	/* dnslib_packet_add_tmp_rrset only works with pointers. */
	dnslib_rrset_t *rrset = (dnslib_rrset_t *)0xabcdef;

	dnslib_packet_t *packet =
		dnslib_packet_new(DNSLIB_PACKET_PREALLOC_RESPONSE);
	assert(packet);

	lives_ok({
		if (dnslib_packet_add_tmp_rrset(NULL, rrset) !=
		    DNSLIB_EBADARG) {
			diag("Trying to add to NULL packet did not return "
			     "DNSLIB_EBADARG!");
			errors++;
		}
		lived = 1;

		lived = 0;
		if (dnslib_packet_add_tmp_rrset(packet, NULL) !=
		    DNSLIB_EBADARG) {
			diag("Trying to add NULL rrset did not return "
			     "DNSLIB_EBADARG!");
			errors++;
		}
		lived = 1;

		lived = 0;
		if (dnslib_packet_add_tmp_rrset(NULL, NULL) !=
		    DNSLIB_EBADARG) {
			diag("Trying to add NULL rrset to NULL packet "
			     "did not return DNSLIB_EBADARG!");
			errors++;
		}
		lived = 1;
	}, "packet: add tmp rrset NULL test");
	errors += lived != 1;

	if (dnslib_packet_add_tmp_rrset(packet, rrset) != DNSLIB_EOK) {
		diag("Could not add valid RRSet to packet!");
		errors++;
	}

	/* Not freeing because RRSet is fake. */
//	dnslib_packet_free(&packet);

	free(packet->wireformat);
	free(packet);

	return (errors == 0);
}

//static int test_packet_contains()
//{
//	int errors = 0;
//	int lives = 0;

//	dnslib_packet_t *packet =
//		dnslib_packet_new(DNSLIB_PACKET_PREALLOC_RESPONSE);
//	assert(packet);

//	lives_ok({
//		if (dnslib_packet_contains(packet, NULL,
//		                           DNSLIB_RRSET_COMPARE_PTR) !=
//		    DNSLIB_EBADARG{
//			diag();
//		}
//	}, "packet: contains NULL tests);

//	dnslib_packet_contains()

//}

static int test_packet_header_to_wire()
{
	int errors = 0;
	int lived = 0;
	dnslib_packet_t *packet =
		dnslib_packet_new(DNSLIB_PACKET_PREALLOC_RESPONSE);
	assert(packet);
	size_t size;

	lives_ok({
		dnslib_packet_header_to_wire(NULL, NULL, NULL);
		lived = 1;
		lived = 0;
		dnslib_packet_header_to_wire(&packet->header, NULL, &size);
		lived = 1;
		uint8_t *wire = 0xabcdef;
		lived = 0;
		dnslib_packet_header_to_wire(&packet->header, &wire, &size);
		lived = 1;
	}, "packet: header to wire NULL tests");
	errors += lived != 1;

	dnslib_packet_free(&packet);
	return (errors == 0);
}

static int test_packet_question_to_wire()
{
	int errors = 0 ;
	int lived = 0;
	dnslib_packet_t *packet =
		dnslib_packet_new(DNSLIB_PACKET_PREALLOC_RESPONSE);
	assert(packet);

	lives_ok({
		if (dnslib_packet_question_to_wire(NULL) != DNSLIB_EBADARG) {
			diag("Calling packet_question_to_wire with "
			     "NULL pointer did not result to DNSLIB_EBADARG!");
			errors++;
		}
		lived = 1;
	}, "packet: question to wire NULL tests");
	errors += lived != 1;

	packet->size = DNSLIB_WIRE_HEADER_SIZE + 1;
	if (dnslib_packet_question_to_wire(packet) != DNSLIB_ERROR) {
		diag("Calling packet_question_to_wire with oversized packet "
		     "did not return DNSLIB_ERROR!");
		errors++;
	}

	dnslib_packet_free(&packet);
	return (errors == 0);
}

static int test_packet_edns_to_wire()
{
	int errors = 0 ;
	int lived = 0;
	dnslib_packet_t *packet =
		dnslib_packet_new(DNSLIB_PACKET_PREALLOC_RESPONSE);
	assert(packet);

	lives_ok({
		dnslib_packet_edns_to_wire(NULL);
		lived = 1;
	}, "packet: question to wire NULL tests");
	errors += lived != 1;

	dnslib_packet_free(&packet);
	return (errors == 0);
}

static int test_packet_to_wire()
{
	int errors = 0 ;
	int lived = 0;
	dnslib_packet_t *packet =
		dnslib_packet_new(DNSLIB_PACKET_PREALLOC_RESPONSE);
	assert(packet);

	lives_ok({
		if (dnslib_packet_to_wire(NULL, NULL, NULL) != DNSLIB_EBADARG) {
			diag("Calling packet_to_wire with "
			     "NULL pointers did not return DNSLIB_EBADARG!");
			errors++;
		}
		lived = 1;
		size_t size;
		lived = 0;
		if (dnslib_packet_to_wire(packet, NULL, &size) !=
		    DNSLIB_EBADARG) {
			diag("Calling packet_to_wire with "
			     "NULL wire did not return DNSLIB_EBADARG!");
			errors++;
		}
		lived = 1;
		uint8_t *wire = 0xabcdef;
		lived = 0;
		if (dnslib_packet_to_wire(packet, &wire, &size) !=
		    DNSLIB_EBADARG) {
			diag("Calling packet_to_wire with "
			     "wire not pointing to NULL did not return"
			     " DNSLIB_EBADARG!");
			errors++;
		}
		lived = 1;
	}, "packet: to wire NULL tests");
	errors += lived != 1;

	dnslib_packet_free(&packet);
	return (errors == 0);
}

static const uint DNSLIB_PACKET_TEST_COUNT = 21;

static int packet_tests_count(int argc, char *argv[])
{
	return DNSLIB_PACKET_TEST_COUNT;
}

static int packet_tests_run(int argc, char *argv[])
{
	int res = 0;
	ok(res = test_packet_new(), "packet: new");
	skip(!res, 20);
	ok(test_packet_parse_rest(), "packet: parse rest");
	ok(test_packet_parse_from_wire(), "packet: parse from wire");
	ok(test_packet_parse_next_rr_answer(), "packet: parse next rr answer");
	ok(test_packet_set_max_size(), "packet: set max size");
	ok(test_packet_add_tmp_rrset(), "packet: add tmp rrset");
	ok(test_packet_header_to_wire(), "packet: header to wire");
	ok(test_packet_question_to_wire(), "packet: header to wire");
	ok(test_packet_edns_to_wire(), "packet: header to wire");
	ok(test_packet_to_wire(), "packet: to wire");
//	ok(res = test_packet_contains(), "Packet: contains");
	endskip;
	return 1;
}
