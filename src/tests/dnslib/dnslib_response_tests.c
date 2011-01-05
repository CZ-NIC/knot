/*!
 * \file dnslib_response_tests.c
 *
 * \author Jan Kadlec <jan.kadlec@nic.cz>
 *
 * Contains unit tests for RRSet (dnslib_rrset_t) and its API.
 *
 * Contains tests for:
 * - Response API
 */

#include <assert.h>

#include "tap_unit.h"

#include "response.h"
#include "rdata.h"
#include "rrset.h"
#include "dname.h"

static int dnslib_response_tests_count(int argc, char *argv[]);
static int dnslib_response_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api dnslib_response_tests_api = {
	"DNS library - response",      //! Unit name
	&dnslib_response_tests_count,  //! Count scheduled tests
	&dnslib_response_tests_run     //! Run scheduled tests
};

/*
 *  Unit implementation.
 */

enum {
	DNAMES_COUNT = 2,
	ITEMS_COUNT = 1,
	RDATA_COUNT = 1,
	RRSET_COUNT = 1
};

static dnslib_dname_t DNAMES[DNAMES_COUNT] =
	{ {(uint8_t *)"6example3com", 12, NULL},     //0's at the end are added
          {(uint8_t *)"2ns6example3com", 15, NULL} };

//TODO I want to initialize .raw_data too...this is C89 style
static dnslib_rdata_item_t ITEMS[ITEMS_COUNT] = { {&DNAMES[0]} };

static dnslib_rdata_t RDATA[RDATA_COUNT] = { {&ITEMS[0], 1, &RDATA[0]} };

static dnslib_rrset_t RESPONSE_RRSETS[RRSET_COUNT] =
	{ {&DNAMES[0],1 ,1 ,3600, &RDATA[0], NULL} };

/* \note just checking the pointers probably would suffice */
static int compare_rrsets(const dnslib_rrset_t *rrset1,
                          const dnslib_rrset_t *rrset2) {
	return (!(dnslib_dname_compare(rrset1->owner, rrset2->owner) == 0 &&
	        rrset1->type == rrset2->type &&
		rrset1->rclass == rrset2->rclass &&
		rrset1->ttl == rrset2->ttl &&
		rrset1->rdata == rrset2->rdata));
}

static int test_response_new_empty() {
	dnslib_response_t *resp = dnslib_response_new_empty(NULL, 0);

	if (resp != NULL) {
		return 1;
	} else {
		return 0;
	}
}

static int test_response_add_rrset_answer() {
	dnslib_response_t *resp = dnslib_response_new_empty(NULL, 0);

	assert(resp);

	dnslib_response_add_rrset_answer(resp, &RESPONSE_RRSETS[0], 0);

	if (compare_rrsets(resp->answer[0], &RESPONSE_RRSETS[0]) == 0) {
		return 1;
	} else {
		return 0;
	}
}

static int test_response_add_rrset_authority() {
}
static int test_response_add_rrset_additional() {
}

static const int DNSLIB_RESPONSE_TEST_COUNT = 2;

/*! This helper routine should report number of
 *  scheduled tests for given parameters.
 */
static int dnslib_response_tests_count(int argc, char *argv[])
{
	return DNSLIB_RESPONSE_TEST_COUNT;
}

/*! Run all scheduled tests for given parameters.
 */
static int dnslib_response_tests_run(int argc, char *argv[])
{
	ok(test_response_new_empty(), "response: create empty");

	ok(test_response_add_rrset_answer(), "response: add rrset answer");

	return 0;
}
