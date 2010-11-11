/*!
 * \file dnslib_rrset_tests.c
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * Contains unit tests for RRSet (dnslib_rrset_t) and its API.
 *
 * Contains tests for:
 * -
 */

#include "tap_unit.h"

#include "common.h"
#include "rrset.h"
#include "dname.h"
#include "rdata.h"

static int dnslib_rrset_tests_count(int argc, char *argv[]);
static int dnslib_rrset_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api dnslib_rrset_tests_api = {
   "DNS library - rrset",        //! Unit name
   &dnslib_rrset_tests_count,  //! Count scheduled tests
   &dnslib_rrset_tests_run     //! Run scheduled tests
};

/*----------------------------------------------------------------------------*/
/*
 *  Unit implementation.
 */

enum { TEST_RRSETS = 1 };

static const void *RRSIG_ADDRESS = (void *)0xDEADBEEF;
static const void *RRSIG_FIRST = RRSIG_ADDRESS + 10;

struct test_rrset {
	char *owner;
	uint16_t type;
	uint16_t rclass;
	uint32_t  ttl;
	uint rdata_count;
	uint8_t **rdata;
	void *signatures;
	void *rrsig_first;
	uint rrsig_count;
};

static const struct test_rrset test_rrsets[TEST_RRSETS] = {
	{ "example.com.", 2, 1, 3600, 2,
	  { "some arbitrary data", "some other data" },
	  RRSIG_ADDRESS, RRSIG_ADDRESS, RRSIG_FIRST, 1 }
};

static int check_rrset( const dnslib_rrset_t *rrset, int i,
						int check_rdata, int check_rrsigs )
{
	int errors = 0;

	if (rrset == NULL) {
		diag("RRSet not created!");
		return 1;
	}

	char *owner = dnslib_dname_to_str(rrset->owner);
	if (strcmp(owner, test_rrsets[i].owner) != 0) {
		diag("OWNER domain name wrong: '%s' (should be '%s')",
			 owner, test_rrsets[i].owner);
		++errors;
	}
	free(owner);

	if (rrset->type != test_rrsets[i].type) {
		diag("TYPE wrong: %u (should be: %u)", rrset->type,
			 test_rrsets[i].type);
		++errors;
	}

	if (rrset->rclass != test_rrsets[i].rclass) {
		diag("CLASS wrong: %u (should be: %u)", rrset->rclass,
			 test_rrsets[i].rclass);
		++errors;
	}

	if (rrset->ttl != test_rrsets[i].ttl) {
		diag("TTL wrong: %u (should be: %u)", rrset->ttl,
			 test_rrsets[i].ttl);
		++errors;
	}

//	if (check_rdata) {
//		dnslib_rdata_t *rdata = rrset->rdata;
//		int count = 0;

//		if (rdata == NULL && test_rrsets[i].rdata_count > 0) {
//			diag("There are no RDATAs in the RRSet (should be %u)",
//				 test_rrsets[i].rdata_count);
//			++errors;
//		}
//		if (rdata != NULL) {
//			while (rdata->next != NULL && rdata->next != rrset->rdata) {

//			}

//			if (rdata->next == NULL) {
//				diag("The list of RDATAs is not cyclical!");
//				++errors;
//			} else {
//				assert(rdata == rrset->rdata);
//			}
//		}
//	}

//	if (check_rrsigs) {

//	}

	return errors;
}

/*!
 * \brief Tests dnslib_rrset_new().
 * \retval > 0 on success.
 * \retval 0 otherwise.
 */
static int test_rrset_create()
{
	int errors = 0;

	for (int i = 0; i < TEST_RRSETS; ++i) {
		dnslib_dname_t *owner = dnslib_dname_new_from_str(test_rrsets[i].owner,
										strlen(test_rrsets[i].owner));
		if (owner == NULL) {
			diag("Error creating owner domain name!");
			return 0;
		}
		dnslib_rrset_t *rrset = dnslib_rrset_new(owner, test_rrsets[i].type,
							test_rrsets[i].rclass, test_rrsets[i].ttl);

		errors += check_rrset(rrset, i, 0, 0);
		dnslib_rrset_free(&rrset);
		dnslib_dname_free(&owner);
	}

	diag("Total errors: %d", errors);

	return (errors == 0);
}

/*!
 * \brief Tests dnslib_rrset_free().
 * \retval > 0 on success.
 * \retval 0 otherwise.
 *
 * \todo How to test this?
 */
static int test_rrset_delete()
{
	return 0;
}

static int test_rrset_rdata()
{
	return 0;
}

static int test_rrset_rrsigs()
{
	return 0;
}

/*----------------------------------------------------------------------------*/

static const int DNSLIB_RRSET_TEST_COUNT = 4;

/*! This helper routine should report number of
 *  scheduled tests for given parameters.
 */
static int dnslib_rrset_tests_count(int argc, char *argv[])
{
   return DNSLIB_RRSET_TEST_COUNT;
}

/*! Run all scheduled tests for given parameters.
 */
static int dnslib_rrset_tests_run(int argc, char *argv[])
{
	int res_create = 0;

	res_create = test_rrset_create();
	ok(res_create, "rrset: create");

	skip(!res_create, 3);

	todo();

	ok(test_rrset_delete(), "rrset: delete");

	ok(test_rrset_rdata(), "rrset: rdata manipulation");

	ok(test_rrset_rrsigs(), "rrset: rrsigs manipulation");

	endtodo;

	endskip;	/* !res_create */

	return 0;
}
