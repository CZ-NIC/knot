/* blame: jan.kadlec@nic.cz */

#include <assert.h>
#include <stdint.h>

#include "packet_tests.h"
#include "dnslib/error.h"
#include "dnslib/packet.h"
#include "dnslib/wire.h"
#include "dnslib/query.h"
/* *test_t structures */
#include "dnslib/tests/realdata/dnslib_tests_loader_realdata.h"

static int query_tests_count(int argc, char *argv[]);
static int query_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api query_tests_api = {
	"query",     //! Unit name
	&query_tests_count,  //! Count scheduled tests
	&query_tests_run     //! Run scheduled tests
};

static const uint DNSLIB_QUERY_TEST_COUNT = 1;

static int query_tests_count(int argc, char *argv[])
{
	return DNSLIB_QUERY_TEST_COUNT;
}

static int test_query_init()
{
	int errors = 0;
	int lived = 0;
	dnslib_packet_t *query =
		dnslib_packet_new(DNSLIB_PACKET_PREALLOC_QUERY);
	assert(query);
	lives_ok({
		if (dnslib_query_init(NULL) != DNSLIB_EBADARG) {
			diag("Calling query_init with NULL query did "
			     "not return DNSLIB_EBADARG!");
			errors++;
		}
		lived = 1;
	}, "query: init NULL tests");
	errors += lived != 1;

	assert(dnslib_packet_set_max_size(query, 1024 * 10) == DNSLIB_EOK);
	if (dnslib_query_init(query) != DNSLIB_EOK) {
		diag("Calling query_init with valid query did not return "
		     "DNSLIB_EOK!");
		errors++;
	}

	if (!dnslib_packet_is_query(query)) {
		diag("QR flag was not set!");
		errors++;
	}

	return (errors == 0);
}

static int test_query_set_question()
{
	int errors = 0;
	int lived = 0;

	dnslib_packet_t *query =
		dnslib_packet_new(DNSLIB_PACKET_PREALLOC_QUERY);
	assert(query);
	assert(dnslib_packet_set_max_size(query, 1024 * 10) == DNSLIB_EOK);
	dnslib_query_init(query);

	dnslib_rrset_t *rrset =
		dnslib_rrset_new(dnslib_dname_new_from_str("a.ns.cz.",
	                                                   strlen("a.ns.cz."),
	                                                   NULL),
	                         DNSLIB_RRTYPE_A, DNSLIB_CLASS_IN, 3600);
	assert(rrset);

	dnslib_question_t *question = malloc(sizeof(dnslib_question_t));
	assert(question);
	question->qname = rrset->owner;
	question->qtype = rrset->type;
	question->qclass = rrset->rclass;

	lives_ok({
		if (dnslib_query_set_question(NULL, NULL) != DNSLIB_EBADARG) {
			diag("Calling query_set_question with NULL");
			errors++;
		}
		lived = 1;
		lived = 0;
		if (dnslib_query_set_question(query, NULL) != DNSLIB_EBADARG) {
			diag("Calling query_set_question with NULL");
			errors++;
		}
		lived = 1;
		lived = 0;
		if (dnslib_query_set_question(NULL, question) != DNSLIB_EBADARG) {
			diag("Calling query_set_question with NULL");
			errors++;
		}
		lived = 1;
	}, "query: set question NULL tests");
	errors += lived != 1;

	if (dnslib_query_set_question(query, question) != DNSLIB_EOK) {
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

	dnslib_packet_free(&query);
	dnslib_rrset_deep_free(&rrset, 1, 0, 0);

	return (errors == 0);
}

static int query_tests_run(int argc, char *argv[])
{
	ok(test_query_init(), "query: init");
	ok(test_query_set_question(), "query: set question");
	return 1;
}
