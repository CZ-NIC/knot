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

static int load_raw_packets(uint8_t **raw_packets, uint8_t *count,
                            const char *filename)
{
	assert(raw_packets == NULL);

	FILE *f;
	uint8_t tmp_size = 0;

	f = fopen(filename, "rb");

	if (f == NULL) {
		return 0;
	}

	fread(count, sizeof(uint8_t), 1, f);

	raw_packets = malloc(sizeof(uint8_t *));

	for (int i = 0; i < *count; i++) {
		fread(&tmp_size, sizeof(uint8_t), 1, f);
		raw_packets[i] = malloc(sizeof(uint8_t) * tmp_size);
		fread(raw_packets[i], sizeof(uint8_t), tmp_size, f);
	}

	return 0;
}

enum {
	DNAMES_COUNT = 2,
	ITEMS_COUNT = 1,
	RDATA_COUNT = 1,
	RRSETS_COUNT = 1
};

static dnslib_dname_t DNAMES[DNAMES_COUNT] =
	{ {(uint8_t *)"6example3com", 12, NULL},     //0's at the end are added
          {(uint8_t *)"2ns6example3com", 15, NULL} };

static dnslib_rdata_item_t ITEMS[ITEMS_COUNT] = { {.dname = &DNAMES[0]} };

static dnslib_rdata_t RDATA[RDATA_COUNT] = { {&ITEMS[0], 1, &RDATA[0]} };

static dnslib_rrset_t RESPONSE_RRSETS[RRSETS_COUNT] =
	{ {&DNAMES[0],1 ,1 ,3600, &RDATA[0], NULL} };

/* \note just checking the pointers probably would suffice */
static int compare_rrsets(const dnslib_rrset_t *rrset1,
                          const dnslib_rrset_t *rrset2)
{
	assert(rrset1);
	assert(rrset2);

	return (!(dnslib_dname_compare(rrset1->owner, rrset2->owner) == 0 &&
	        rrset1->type == rrset2->type &&
		rrset1->rclass == rrset2->rclass &&
		rrset1->ttl == rrset2->ttl &&
		rrset1->rdata == rrset2->rdata));
}

static int test_response_new_empty()
{
	dnslib_response_t *resp = dnslib_response_new_empty(NULL, 0);

	if (resp != NULL) {
		dnslib_response_free(&resp);		
		return 1;
	} else {
		dnslib_response_free(&resp);
		return 0;
	}
}

static int test_response_add_rrset(int (*add_func)
                                   (dnslib_response_t *,
				   const dnslib_rrset_t *, int), 
				   int array_id)
{
	int errors = 0;

	dnslib_response_t *resp = dnslib_response_new_empty(NULL, 0);
	assert(resp);

	const dnslib_rrset_t **array;

	switch (array_id) {
		case 1: {
			array = resp->answer;
			break;
		}
		case 2: {
			array = resp->authority;
			break;
		}
		case 3:	{
			array = resp->additional;
			break;
		}
		default: {
			dnslib_response_free(&resp);
			return 0;
		}
	} /* switch */

	for (int i = 0; (i < RRSETS_COUNT) && !errors; i++) {
		add_func(resp, &RESPONSE_RRSETS[i], 0);
		errors += compare_rrsets(array[i], &RESPONSE_RRSETS[i]);
	}

	dnslib_response_free(&resp);

	return (errors == 0);
}

static int test_response_add_rrset_answer()
{
	return test_response_add_rrset(&dnslib_response_add_rrset_answer,
	                               1);
}

static int test_response_add_rrset_authority()
{
	return test_response_add_rrset(&dnslib_response_add_rrset_authority,
	                               2);
}
static int test_response_add_rrset_additional()
{
	return test_response_add_rrset(&dnslib_response_add_rrset_additional,
	                               3);
}

static const int DNSLIB_RESPONSE_TEST_COUNT = 4;

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
	int ret;
	
	ret = test_response_new_empty();
	ok(ret, "response: create empty");

	skip(!ret, 3);

	ok(test_response_add_rrset_answer(), "response: add rrset answer");
	ok(test_response_add_rrset_authority(), "response: add rrset authority");
	ok(test_response_add_rrset_additional(), "response: add rrset additional");

	endskip;

	return 0;
}
