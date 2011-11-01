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
/* blame: jan.kadlec@nic.cz */

#include <assert.h>
#include <stdint.h>

#include "packet_tests.h"
#include "libknot/util/error.h"
#include "libknot/packet/packet.h"
#include "libknot/util/wire.h"
/* *test_t structures */
#include "tests/libknot/realdata/libknot_tests_loader_realdata.h"

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
	knot_packet_t *packet =
		knot_packet_new(KNOT_PACKET_PREALLOC_NONE);
	if (packet == NULL) {
		diag("Could not create packet using prealloc_node constant!");
		errors++;
	}
	knot_packet_free(&packet);

	packet = knot_packet_new(KNOT_PACKET_PREALLOC_QUERY);
	if (packet == NULL) {
		diag("Could not create packet using prealloc_query constant!");
		errors++;
	}
	knot_packet_free(&packet);

	packet = knot_packet_new(KNOT_PACKET_PREALLOC_RESPONSE);
	if (packet == NULL) {
		diag("Could not create packet using prealloc_resp constant!");
		errors++;
	}
	knot_packet_free(&packet);

	/*!< \todo Should it create packet using any size? */

	return (errors == 0);
}

static int test_packet_parse_from_wire()
{
	int errors = 0;
	knot_packet_t *packet =
		knot_packet_new(KNOT_PACKET_PREALLOC_QUERY);

	int tmp = 0;
	lives_ok({
		if (knot_packet_parse_from_wire(NULL, NULL, 0, 0) !=
		    KNOT_EBADARG) {
			diag("Trying to parse NULL packet with NULL wire "
			     "did not return KNOT_EBADARG!");
			errors++;
		}
		tmp = 1;
		tmp = 0;
		if (knot_packet_parse_from_wire(packet, NULL, 0, 0) !=
		    KNOT_EBADARG) {
			diag("Trying to parse with NULL wire "
			     "did not return KNOT_EBADARG!");
			errors++;
		}
		tmp = 1;
		tmp = 0;
		if (knot_packet_parse_from_wire(packet, (uint8_t *)0xbeef,
		                                  0, 0) !=
		    KNOT_EFEWDATA) {
			diag("Trying to parse 0 lengt"
			     "did not return KNOT_EOK!");
			errors++;
		}
		tmp = 1;
	}, "packet: parse from wire NULL tests.");
	errors += tmp != 1;

	knot_packet_free(&packet);

	return (errors == 0);
}

static int test_packet_parse_next_rr_answer()
{
	int errors = 0;
	knot_packet_t *packet =
		knot_packet_new(KNOT_PACKET_PREALLOC_RESPONSE);
	assert(packet);

	int tmp = 0;
	lives_ok({
		int ret = 0;
		if (knot_packet_parse_next_rr_answer(NULL, NULL) !=
		    KNOT_EBADARG) {
			diag("Trying to parse next RR answer with "
			     "NULL packet with and NULL RRSet "
			     "did not return KNOT_EBADARG!");
			errors++;
		}
		tmp = 1;
		tmp = 0;
		if ((ret = knot_packet_parse_next_rr_answer(packet,
		                                              NULL)) !=
		    KNOT_EBADARG) {
			diag("Trying to parse next RR with NULL RRSet pointer "
			     "did not return KNOT_EBADARG! Got %d.",
			     ret);
			errors++;
		}
		tmp = 1;
//		knot_rrset_t *rrset = (knot_rrset_t *)0xaaaa;
//		tmp = 0;
//		if (knot_packet_parse_next_rr_answer(packet,
//		                                       &rrset) !=
//		    KNOT_EBADARG) {
//			diag("Trying to parse next RR answer with rrset pointer"
//			     " not pointing to NULL did not "
//			     "return KNOT_EBADARG!");
//			errors++;
//		}
//		tmp = 1;
	}, "packet: parse next rr answer NULL tests.");
	errors += tmp != 1;

	knot_packet_free(&packet);

	return (errors == 0);
}

static int test_packet_parse_rest()
{
	int res = 0;
	lives_ok({res = knot_packet_parse_rest(NULL);},
	"packet: parse rest NULL test");

	if (res != KNOT_EBADARG) {
		diag("parse rest NULL did not return KNOT_EBADARG.\n");
		return 1;
	}

	knot_packet_t *packet =
		knot_packet_new(KNOT_PACKET_PREALLOC_NONE);
	assert(packet);

	todo();
	lives_ok({res = knot_packet_parse_rest(packet);},
	"packet: parser rest empty packet");
	endtodo;

	knot_packet_free(&packet);

	return 1;
}


static int test_packet_set_max_size()
{
	int errors = 0;
	knot_packet_t *packet =
		knot_packet_new(KNOT_PACKET_PREALLOC_NONE);
	assert(packet);

	int lived = 0;

	lives_ok({
		lived = 0;
		if (knot_packet_set_max_size(NULL, 1) != KNOT_EBADARG) {
			diag("Calling packet_set_max() with NULL packet "
			     "did not return KNOT_EBADARG");
			errors++;
		}
		lived = 1;
	}, "packet: set max size NULL test");

	errors += lived != 1;

	if (knot_packet_set_max_size(packet, 0) != KNOT_EBADARG) {
		diag("Calling packet_set_max() with size eqeal to 0 did not "
		     "return KNOT_EBADARG");
		errors++;
	}

	if (knot_packet_set_max_size(packet, 10) != KNOT_EOK) {
		diag("Calling packet_set_max() with valid arguments did not "
		     "return KNOT_EOK");
		errors++;
	}

	knot_packet_free(&packet);

	return (errors == 0);
}

static int test_packet_add_tmp_rrset()
{
	int errors = 0;
	int lived = 0;

	/* knot_packet_add_tmp_rrset only works with pointers. */
	knot_rrset_t *rrset = (knot_rrset_t *)0xabcdef;

	knot_packet_t *packet =
		knot_packet_new(KNOT_PACKET_PREALLOC_RESPONSE);
	assert(packet);

	lives_ok({
		if (knot_packet_add_tmp_rrset(NULL, rrset) !=
		    KNOT_EBADARG) {
			diag("Trying to add to NULL packet did not return "
			     "KNOT_EBADARG!");
			errors++;
		}
		lived = 1;

		lived = 0;
		if (knot_packet_add_tmp_rrset(packet, NULL) !=
		    KNOT_EBADARG) {
			diag("Trying to add NULL rrset did not return "
			     "KNOT_EBADARG!");
			errors++;
		}
		lived = 1;

		lived = 0;
		if (knot_packet_add_tmp_rrset(NULL, NULL) !=
		    KNOT_EBADARG) {
			diag("Trying to add NULL rrset to NULL packet "
			     "did not return KNOT_EBADARG!");
			errors++;
		}
		lived = 1;
	}, "packet: add tmp rrset NULL test");
	errors += lived != 1;

	if (knot_packet_add_tmp_rrset(packet, rrset) != KNOT_EOK) {
		diag("Could not add valid RRSet to packet!");
		errors++;
	}

	/* Not freeing because RRSet is fake. */
//	knot_packet_free(&packet);

	free(packet->wireformat);
	free(packet);

	return (errors == 0);
}

//static int test_packet_contains()
//{
//	int errors = 0;
//	int lives = 0;

//	knot_packet_t *packet =
//		knot_packet_new(KNOT_PACKET_PREALLOC_RESPONSE);
//	assert(packet);

//	lives_ok({
//		if (knot_packet_contains(packet, NULL,
//		                           KNOT_RRSET_COMPARE_PTR) !=
//		    KNOT_EBADARG{
//			diag();
//		}
//	}, "packet: contains NULL tests);

//	knot_packet_contains()

//}

static int test_packet_header_to_wire()
{
	int errors = 0;
	int lived = 0;
	knot_packet_t *packet =
		knot_packet_new(KNOT_PACKET_PREALLOC_RESPONSE);
	assert(packet);
	size_t size;

	lives_ok({
		knot_packet_header_to_wire(NULL, NULL, NULL);
		lived = 1;
		lived = 0;
		knot_packet_header_to_wire(&packet->header, NULL, &size);
		lived = 1;
	}, "packet: header to wire NULL tests");
	errors += lived != 1;

	knot_packet_free(&packet);
	return (errors == 0);
}

static int test_packet_question_to_wire()
{
	int errors = 0 ;
	int lived = 0;
	knot_packet_t *packet =
		knot_packet_new(KNOT_PACKET_PREALLOC_RESPONSE);
	assert(packet);

	lives_ok({
		if (knot_packet_question_to_wire(NULL) != KNOT_EBADARG) {
			diag("Calling packet_question_to_wire with "
			     "NULL pointer did not result to KNOT_EBADARG!");
			errors++;
		}
		lived = 1;
	}, "packet: question to wire NULL tests");
	errors += lived != 1;

	packet->size = KNOT_WIRE_HEADER_SIZE + 1;
	if (knot_packet_question_to_wire(packet) != KNOT_ERROR) {
		diag("Calling packet_question_to_wire with oversized packet "
		     "did not return KNOT_ERROR!");
		errors++;
	}

	knot_packet_free(&packet);
	return (errors == 0);
}

static int test_packet_edns_to_wire()
{
	int errors = 0 ;
	int lived = 0;
	knot_packet_t *packet =
		knot_packet_new(KNOT_PACKET_PREALLOC_RESPONSE);
	assert(packet);

	lives_ok({
		knot_packet_edns_to_wire(NULL);
		lived = 1;
	}, "packet: question to wire NULL tests");
	errors += lived != 1;

	knot_packet_free(&packet);
	return (errors == 0);
}

static int test_packet_to_wire()
{
	int errors = 0 ;
	int lived = 0;
	knot_packet_t *packet =
		knot_packet_new(KNOT_PACKET_PREALLOC_RESPONSE);
	assert(packet);

	lives_ok({
		if (knot_packet_to_wire(NULL, NULL, NULL) != KNOT_EBADARG) {
			diag("Calling packet_to_wire with "
			     "NULL pointers did not return KNOT_EBADARG!");
			errors++;
		}
		lived = 1;
		size_t size;
		lived = 0;
		if (knot_packet_to_wire(packet, NULL, &size) !=
		    KNOT_EBADARG) {
			diag("Calling packet_to_wire with "
			     "NULL wire did not return KNOT_EBADARG!");
			errors++;
		}
		lived = 1;
		uint8_t *wire = (uint8_t *)0xabcdef;
		lived = 0;
		if (knot_packet_to_wire(packet, &wire, &size) !=
		    KNOT_EBADARG) {
			diag("Calling packet_to_wire with "
			     "wire not pointing to NULL did not return"
			     " KNOT_EBADARG!");
			errors++;
		}
		lived = 1;
	}, "packet: to wire NULL tests");
	errors += lived != 1;

	knot_packet_free(&packet);
	return (errors == 0);
}

static const uint KNOT_PACKET_TEST_COUNT = 21;

static int packet_tests_count(int argc, char *argv[])
{
	return KNOT_PACKET_TEST_COUNT;
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
