/* blame: jan.kadlec@nic.cz */

#include <assert.h>

#include "packet_tests.h"
#include "dnslib/error.h"
#include "dnslib/packet.h"
/* *test_t structures */
#include "dnslib/tests/realdata/dnslib_tests_loader_realdata.h"

static int packet_tests_count(int argc, char *argv[]);
static int packet_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api packet_tests_api = {
	"Packet",     //! Unit name
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
	}, "Packet: parse from wire NULL tests.");
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
	}, "Packet: parse next rr answer NULL tests.");
	errors += tmp != 1;

	dnslib_packet_free(&packet);

	return (errors == 0);
}

static int test_packet_parse_rest()
{
	int res = 0;
	lives_ok({res *= dnslib_packet_parse_rest(NULL);},
	"Packet: parse rest NULL test");

	dnslib_packet_t *packet =
		dnslib_packet_new(DNSLIB_PACKET_PREALLOC_NONE);
	assert(packet);

	lives_ok({res *= dnslib_packet_parse_rest(packet);},
	"Packet: parser rest empty packet");

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
	}, "Packet: set max size NULL test");

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
	}, "Packet: add tmp rrset NULL test");
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

//static int int test_packet_contains()
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

static const uint DNSLIB_PACKET_TEST_COUNT = 14;

static int packet_tests_count(int argc, char *argv[])
{
	return DNSLIB_PACKET_TEST_COUNT;
}

static int packet_tests_run(int argc, char *argv[])
{
	int res = 0;
	ok(res = test_packet_new(), "Packet: new");
	skip(!res, 6);
	ok(test_packet_parse_rest(), "Packet: parse rest");
	ok(test_packet_parse_from_wire(), "Packet: parse from wire");
	ok(test_packet_parse_next_rr_answer(), "Packet: parse next rr answer");
	ok(test_packet_set_max_size(), "Packet: set max size");
	ok(res = test_packet_add_tmp_rrset(), "Packet: add tmp rrset");
//	ok(res = test_packet_contains(), "Packet: contains");
	endskip;
	return 1;
}
