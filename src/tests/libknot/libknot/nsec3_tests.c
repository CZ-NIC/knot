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

#include "libknot/common.h"
#include "libknot/util/error.h"
#include "libknot/nsec3.h"
#include "libknot/util/utils.h"
#include "common/base32hex.h"
#include "nsec3_tests.h"

#ifdef TEST_WITH_LDNS
#include "ldns/ldns.h"
#endif

static int knot_nsec3_tests_count(int argc, char *argv[]);
static int knot_nsec3_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api nsec3_tests_api = {
	"NSEC3",      //! Unit name
	&knot_nsec3_tests_count,  //! Count scheduled tests
	&knot_nsec3_tests_run     //! Run scheduled tests
};

extern int compare_wires_simple(uint8_t *w1, uint8_t *w2, uint count);

static int test_nsec3_params_from_wire()
{
	/* Create sample NSEC3PARAM rdata */
	knot_rdata_item_t items[4];
	knot_rdata_t *rdata = knot_rdata_new();
	rdata->items = items;
	rdata->count = 4;
	knot_rdata_item_set_raw_data(rdata, 0, (uint16_t *)"\x1\x0\x1");
	knot_rdata_item_set_raw_data(rdata, 1, (uint16_t *)"\x1\x0\x0");
	knot_rdata_item_set_raw_data(rdata, 2, (uint16_t *)"\x2\x0\x0\x64");
	knot_rdata_item_set_raw_data(rdata, 3,
	(uint16_t *)"\xF\x0\xE\xF\xF\xF\xF\xF\xF\xF\xF\xF\xF\xF\xF\xF\xF");

	knot_rrset_t *rrset =
		knot_rrset_new(knot_dname_new_from_str("cz.",
		                 strlen("cz."), NULL),
	                         KNOT_RRTYPE_NSEC3PARAM,
	                         KNOT_CLASS_IN,
	                         3600);
	assert(rrset);
	int ret = knot_rrset_add_rdata(rrset, rdata);
	assert(ret == KNOT_EOK);

	knot_nsec3_params_t nsec3_test_params;

	int errors = 0;
	int lived = 0;
	lives_ok({
		/* Create special variable for this block. */
		if (knot_nsec3_params_from_wire(NULL, NULL) !=
		    KNOT_EBADARG) {
			errors++;
		}
		lived = 1;

		lived = 0;
		if (knot_nsec3_params_from_wire(&nsec3_test_params, NULL) !=
		    KNOT_EBADARG) {
			errors++;
		}
		lived = 1;

		lived = 0;
		if (knot_nsec3_params_from_wire(NULL, rrset) !=
		    KNOT_EBADARG) {
			errors++;
		}
		lived = 1;

	}, "nsec3 params from wire NULL tests");
	errors += lived != 1;

	if (knot_nsec3_params_from_wire(&nsec3_test_params,
	                                rrset) != KNOT_EOK) {
		diag("Could not convert nsec3 params to wire!");
		return 0;
	}

	if (nsec3_test_params.algorithm != 1) {
		diag("Algorithm error");
		errors++;
	}

	if (nsec3_test_params.flags != 0) {
		diag("Flags error %d", nsec3_test_params.flags);
		errors++;
	}

	if (nsec3_test_params.iterations != 100) {
		diag("Iterations error %d", nsec3_test_params.iterations);
		errors++;
	}
		printf("salt length: %d\n", nsec3_test_params.salt_length);

	if (nsec3_test_params.salt_length != 14) {
		diag("Salt length error %d", nsec3_test_params.salt_length);
		return 0;
	}

	if (compare_wires_simple((uint8_t *)nsec3_test_params.salt,
		(uint8_t *)"\xF\xF\xF\xF\xF\xF\xF\xF\xF\xF\xF\xF\xF\xF",
		14) != 0) {
		diag("Salt wire error");
		errors++;
	}

	knot_rrset_free(&rrset);
	return (errors == 0);
}

static int test_nsec3_sha1()
{
	int errors = 0;
	int lived = 0;

	knot_nsec3_params_t nsec3_test_params;

	lives_ok({
		if (knot_nsec3_sha1(NULL, NULL, 1, NULL, NULL) !=
	            KNOT_EBADARG) {
			errors++;
		}
		lived = 1;
		lived = 0;
		if (knot_nsec3_sha1(&nsec3_test_params,
	                              NULL, 1, NULL, NULL) !=
	            KNOT_EBADARG) {
			errors++;
		}
		uint8_t data[20];
		lived = 1;
		lived = 0;
		if (knot_nsec3_sha1(&nsec3_test_params,
	                              data, 20, NULL, NULL) !=
	            KNOT_EBADARG) {
			errors++;
		}
		uint8_t *digest = NULL;
		lived = 1;
		lived = 0;
		if (knot_nsec3_sha1(&nsec3_test_params,
	                              data, 20, &digest, NULL) !=
	            KNOT_EBADARG) {
			errors++;
		}
//		size_t size = 0;
//		lived = 1;
//		lived = 0;
//		if (knot_nsec3_sha1(&nsec3_test_params,
//	                              data, 20, &digest, &size) !=
//	            KNOT_EBADARG) {
//			errors++;
//		}
		lived = 1;
	}, "NSEC3: nsec3 sha1 NULL tests");
	if (errors) {
		diag("Does not return KNOT_EBADARG after "
		     "execution with wrong arguments!");
	}

	errors += lived != 1;

	uint8_t *digest = NULL;
	size_t digest_size = 0;
	if (knot_nsec3_sha1(&nsec3_test_params,
	                      (uint8_t *)"\2ns\3nic\2cz",
	                      strlen("\2ns\3nic\2cz"), &digest,
	                      &digest_size) != KNOT_EOK) {
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
//	knot_dname_t *dname_from_ldns =
//		knot_dname_new_from_wire(ldns_rdf_data(hashed_name),
//	                                   ldns_rdf_size(hashed_name),
//	                                   NULL);

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

static const int KNOT_NSEC3_TESTS_COUNT = 2;

/*! This helper routine should report number of
 *  scheduled tests for given parameters.
 */
static int knot_nsec3_tests_count(int argc, char *argv[])
{
	return KNOT_NSEC3_TESTS_COUNT;
}

/*! Run all scheduled tests for given parameters.
 */
static int knot_nsec3_tests_run(int argc, char *argv[])
{
	ok(test_nsec3_params_from_wire(), "nsec3: params from wire");
	ok(test_nsec3_sha1(), "nsec3: sha1");
	return 1;
}
