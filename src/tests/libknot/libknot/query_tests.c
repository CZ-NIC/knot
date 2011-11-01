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
#include "libknot/packet/query.h"
/* *test_t structures */
#include "tests/libknot/realdata/libknot_tests_loader_realdata.h"

static int query_tests_count(int argc, char *argv[]);
static int query_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api query_tests_api = {
	"query",     //! Unit name
	&query_tests_count,  //! Count scheduled tests
	&query_tests_run     //! Run scheduled tests
};

static const uint KNOT_QUERY_TEST_COUNT = 1;

static int query_tests_count(int argc, char *argv[])
{
	return KNOT_QUERY_TEST_COUNT;
}

static int test_query_init()
{
	int errors = 0;
	int lived = 0;
	knot_packet_t *query =
		knot_packet_new(KNOT_PACKET_PREALLOC_QUERY);
	assert(query);
	lives_ok({
		if (knot_query_init(NULL) != KNOT_EBADARG) {
			diag("Calling query_init with NULL query did "
			     "not return KNOT_EBADARG!");
			errors++;
		}
		lived = 1;
	}, "query: init NULL tests");
	errors += lived != 1;

	assert(knot_packet_set_max_size(query, 1024 * 10) == KNOT_EOK);
	if (knot_query_init(query) != KNOT_EOK) {
		diag("Calling query_init with valid query did not return "
		     "KNOT_EOK!");
		errors++;
	}

	if (!knot_packet_is_query(query)) {
		diag("QR flag was not set!");
		errors++;
	}

	return (errors == 0);
}

static int test_query_set_question()
{
	int errors = 0;
	int lived = 0;

	knot_packet_t *query =
		knot_packet_new(KNOT_PACKET_PREALLOC_QUERY);
	assert(query);
	assert(knot_packet_set_max_size(query, 1024 * 10) == KNOT_EOK);
	knot_query_init(query);

	knot_rrset_t *rrset =
		knot_rrset_new(knot_dname_new_from_str("a.ns.cz.",
	                                                   strlen("a.ns.cz."),
	                                                   NULL),
	                         KNOT_RRTYPE_A, KNOT_CLASS_IN, 3600);
	assert(rrset);

	knot_question_t *question = malloc(sizeof(knot_question_t));
	assert(question);
	question->qname = rrset->owner;
	question->qtype = rrset->type;
	question->qclass = rrset->rclass;

	lives_ok({
		if (knot_query_set_question(NULL, NULL) != KNOT_EBADARG) {
			diag("Calling query_set_question with NULL");
			errors++;
		}
		lived = 1;
		lived = 0;
		if (knot_query_set_question(query, NULL) != KNOT_EBADARG) {
			diag("Calling query_set_question with NULL");
			errors++;
		}
		lived = 1;
		lived = 0;
		if (knot_query_set_question(NULL, question) != KNOT_EBADARG) {
			diag("Calling query_set_question with NULL");
			errors++;
		}
		lived = 1;
	}, "query: set question NULL tests");
	errors += lived != 1;

	if (knot_query_set_question(query, question) != KNOT_EOK) {
		diag("Calling query_set_question with valid arguments ");
		errors++;
	}

	if (query->question.qname != rrset->owner) {
		diag("Qname was not set right!");
		errors++;
	}

	if (query->question.qtype != rrset->type) {
		diag("Qtype was not set right!");
		errors++;
	}

	if (query->question.qclass != rrset->rclass) {
		diag("Qclass was not set right!");
		errors++;
	}

	if (query->header.qdcount != 1) {
		diag("Qdcount was not set right!");
		errors++;
	}

	knot_packet_free(&query);
	knot_rrset_deep_free(&rrset, 1, 0, 0);

	return (errors == 0);
}

static int query_tests_run(int argc, char *argv[])
{
	ok(test_query_init(), "query: init");
	ok(test_query_set_question(), "query: set question");
	return 1;
}
