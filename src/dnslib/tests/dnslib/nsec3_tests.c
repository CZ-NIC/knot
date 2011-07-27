/* blame: jan.kadlec@nic.cz */

#include <assert.h>

#include "dnslib/dnslib-common.h"
#include "dnslib/error.h"
#include "dnslib/nsec3.h"
#include "dnslib/utils.h"
#include "common/base32hex.h"
#include "nsec3_tests.h"

#ifdef TEST_WITH_LDNS
#include "ldns/ldns.h"
#endif

static int dnslib_nsec3_tests_count(int argc, char *argv[]);
static int dnslib_nsec3_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api nsec3_tests_api = {
	"NSEC3",      //! Unit name
	&dnslib_nsec3_tests_count,  //! Count scheduled tests
	&dnslib_nsec3_tests_run     //! Run scheduled tests
};

extern int compare_wires_simple(uint8_t *w1, uint8_t *w2, uint count);

static dnslib_nsec3_params_t nsec3_test_params;

static int test_nsec3_params_from_wire()
{
	/* Create sample NSEC3PARAM rdata */
	dnslib_rdata_item_t items[4];
	dnslib_rdata_t *rdata = dnslib_rdata_new();
	rdata->items = items;
	rdata->count = 4;
	dnslib_rdata_item_set_raw_data(rdata, 0, (uint16_t *)"\x1\x0\x1");
	dnslib_rdata_item_set_raw_data(rdata, 1, (uint16_t *)"\x1\x0\x0");
	dnslib_rdata_item_set_raw_data(rdata, 2, (uint16_t *)"\x2\x0\x0\x64");
	dnslib_rdata_item_set_raw_data(rdata, 3,
	                    (uint16_t *)"\xF\x0\xE20110331084524");

	dnslib_rrset_t *rrset =
		dnslib_rrset_new(dnslib_dname_new_from_str("cz.",
		                 strlen("cz."), NULL),
	                         DNSLIB_RRTYPE_NSEC3PARAM,
	                         DNSLIB_CLASS_IN,
	                         3600);
	assert(rrset);
	assert(dnslib_rrset_add_rdata(rrset, rdata) == DNSLIB_EOK);

	dnslib_nsec3_params_t nsec3_tests_params;

	int errors = 0;
	int lived = 0;
	lives_ok({
		if (dnslib_nsec3_params_from_wire(NULL, NULL) !=
		    DNSLIB_EBADARG) {
			errors++;
		}
		lived = 1;

		lived = 0;
		if (dnslib_nsec3_params_from_wire(&nsec3_test_params, NULL) !=
		    DNSLIB_EBADARG) {
			errors++;
		}
		lived = 1;

		lived = 0;
		if (dnslib_nsec3_params_from_wire(NULL, rrset) !=
		    DNSLIB_EBADARG) {
			errors++;
		}
		lived = 1;

	}, "nsec3 params from wire NULL tests");
	errors += lived != 1;

	if (dnslib_nsec3_params_from_wire(&nsec3_test_params, rrset) != DNSLIB_EOK) {
		diag("Could not convert nsec3 params to wire!");
		return 0;
	}

	if (nsec3_test_params.algorithm != 1) {
		diag("Algorithm error");
		errors++;
	}

	if (nsec3_test_params.flags != 2) {
		diag("Flags error");
		errors++;
	}

	if (nsec3_test_params.iterations != 15) {
		diag("Iterations error");
		errors++;
	}

	if (nsec3_test_params.salt_length != 8) {
		diag("Salt length error");
		return 0;
	}

	if (compare_wires_simple((uint8_t *)nsec3_test_params.salt,
	                         (uint8_t *)"\xF\xF\xF\xF\xF\xF\xF\xF",
	                         8) != 0) {
		diag("Salt wire error");
		errors++;
	}

	dnslib_rrset_free(&rrset);
	return (errors == 0);
}

static int test_nsec3_sha1()
{
	int errors = 0;
	int lived = 0;
	lives_ok({
		if (dnslib_nsec3_sha1(NULL, NULL, 1, NULL, NULL) !=
	            DNSLIB_EBADARG) {
			errors++;
		}
		lived = 1;
		lived = 0;
		if (dnslib_nsec3_sha1(&nsec3_test_params,
	                              NULL, 1, NULL, NULL) !=
	            DNSLIB_EBADARG) {
			errors++;
		}
		uint8_t data[20];
		lived = 1;
		lived = 0;
		if (dnslib_nsec3_sha1(&nsec3_test_params,
	                              data, 20, NULL, NULL) !=
	            DNSLIB_EBADARG) {
			errors++;
		}
		uint8_t *digest = NULL;
		lived = 1;
		lived = 0;
		if (dnslib_nsec3_sha1(&nsec3_test_params,
	                              data, 20, &digest, NULL) !=
	            DNSLIB_EBADARG) {
			errors++;
		}
		size_t size = 0;
		lived = 1;
		lived = 0;
		if (dnslib_nsec3_sha1(&nsec3_test_params,
	                              data, 20, &digest, &size) !=
	            DNSLIB_EBADARG) {
			errors++;
		}
		size = NULL;
		digest = 0xaaaaaa;
		lived = 1;
		lived = 0;
		if (dnslib_nsec3_sha1(&nsec3_test_params,
	                              data, 20, &digest, &size) !=
	            DNSLIB_EBADARG) {
			errors++;
		}
		lived = 1;
	}, "NSEC3: nsec3 sha1 NULL tests");
	if (errors) {
		diag("Does not return DNSLIB_EBADARG after "
		     "execution with wrong arguments!");
	}

	errors += lived != 1;

	uint8_t *digest = NULL;
	size_t digest_size = 0;
	if (dnslib_nsec3_sha1(&nsec3_test_params, "\2ns\3nic\2cz",
	                      strlen("\2ns\3nic\2cz"), &digest,
	                      &digest_size) != DNSLIB_EOK) {
		diag("Could not hash name!");
		return 0;
	}

#ifdef TEST_WITH_LDNS
	ldns_rdf *name = ldns_dname_new_frm_str("ns.nic.cz.");
	assert(name);
	ldns_rdf *hashed_name = ldns_nsec3_hash_name(name,
	                                          nsec3_test_params.algorithm,
	                                          nsec3_test_params.iterations,
	                                          nsec3_test_params.salt_length,
	                                          nsec3_test_params.salt);
	assert(hashed_name);
	dnslib_dname_t *dname_from_ldns =
		dnslib_dname_new_from_wire(ldns_rdf_data(hashed_name),
	                                   ldns_rdf_size(hashed_name),
	                                   NULL);

	char *name_b32 = NULL;
	size_t size_b32 = base32hex_encode_alloc((char *)digest, digest_size,
	                                     &name_b32);

//	hex_print(name_b32, size_b32);
//	hex_print(ldns_rdf_data(hashed_name), ldns_rdf_size(hashed_name));
	if (ldns_rdf_size(hashed_name) != size_b32) {
		diag("Wrong hashed name length! Should be: %d is: %d",
		     ldns_rdf_size(hashed_name), size_b32);
		return 0;
	}

	if (compare_wires_simple(ldns_rdf_data(hashed_name),
	                         (uint8_t *)name_b32, size_b32) != 0) {
		diag("Wrong hashed name wire!");
		errors++;
	}
#endif

#ifndef TEST_WITH_LDNS
	diag("Warning: without ldns this test is only partial!");
#endif
	return (errors == 0);
}

static const int DNSLIB_NSEC3_TESTS_COUNT = 2;

/*! This helper routine should report number of
 *  scheduled tests for given parameters.
 */
static int dnslib_nsec3_tests_count(int argc, char *argv[])
{
	return DNSLIB_NSEC3_TESTS_COUNT;
}

/*! Run all scheduled tests for given parameters.
 */
static int dnslib_nsec3_tests_run(int argc, char *argv[])
{
	ok(test_nsec3_params_from_wire(), "nsec3: params from wire");
	ok(test_nsec3_sha1(), "nsec3: sha1");
	return 1;
}
