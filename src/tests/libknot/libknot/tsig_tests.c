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

#include <assert.h>
#include <time.h>

#include "libknot/rrset.h"
#include "libknot/packet/response.h"
#include "libknot/dname.h"
#include "libknot/util/wire.h"
#include "libknot/tsig-op.h"
#include "libknot/common.h"
#include "common/print.h"

#include "tsig_tests.h"

static int knot_tsig_tests_count(int argc, char *argv[]);
static int knot_tsig_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api tsig_tests_api = {
	"DNS library - tsig",        //! Unit name
	&knot_tsig_tests_count,  //! Count scheduled tests
	&knot_tsig_tests_run     //! Run scheduled tests
};

static const int KNOT_TSIG_TEST_COUNT = 6;

static knot_rrset_t *create_dummy_tsig_rr()
{
	knot_dname_t *tsig_owner =
		knot_dname_new_from_str("dummy.key.name.",
	                                strlen("dummy.key.name."), NULL);
	assert(tsig_owner);

	/* Create dummy TSIG rr. */
	knot_rrset_t *tsig_rr = knot_rrset_new(tsig_owner, KNOT_RRTYPE_TSIG,
	                                       KNOT_CLASS_ANY, 0);
	assert(tsig_rr);

	knot_rdata_t *tsig_rdata = knot_rdata_new();
	assert(tsig_rr);
	/* Create TSIG items. */
	knot_rdata_item_t items[9];

	/*
	 * I am not sure if 9 is the right count in our impl,
	 * but it should work fine.
	 */
	knot_rdata_set_items(tsig_rdata, items, 9);
	knot_dname_t *alg_name =
		knot_dname_new_from_str("hmac-md5.sig-alg.reg.int.",
	                                strlen("hmac-md5.sig-alg.reg.int."),
	                                NULL);
	assert(alg_name);
	tsig_rdata_set_alg_name(tsig_rr, alg_name);

	/* Get current time and save it to TSIG rr. */
	time_t current_time = time(NULL);
	tsig_rdata_set_time_signed(tsig_rr, current_time);
	tsig_rdata_set_fudge(tsig_rr, 300);
	tsig_rdata_set_orig_id(tsig_rr, 0);
	tsig_rdata_set_tsig_error(tsig_rr, 0);
	tsig_rdata_set_mac(tsig_rr, strlen("nonsensemac"),
	                   (uint8_t *)"nonsensemac");

	return tsig_rr;
}

static int test_knot_tsig_sign()
{
	int errors = 0;
	/* Test bad arguments. */
	int lived = 0;
	lives_ok({
		int ret = knot_tsig_sign(NULL, NULL, 0, NULL, 0, NULL,
		               NULL, NULL, 0, 0);
		if (ret != KNOT_EINVAL) {
			diag("NULL argument did not return KNOT_EINVAL!");
			errors++;
		}
		lived = 1;

		lived = 0;
		ret = knot_tsig_sign((uint8_t *)0x1, NULL, 0, NULL, 0, NULL,
		               NULL, NULL, 0, 0);
		if (ret != KNOT_EINVAL) {
			diag("NULL argument did not return KNOT_EINVAL!");
			errors++;
		}
		lived = 1;

		lived = 0;
		ret = knot_tsig_sign((uint8_t *)0x1, (size_t *)0x1, 0, NULL,
		                     0, NULL,
		               NULL, NULL, 0, 0);
		if (ret != KNOT_EINVAL) {
			diag("NULL argument did not return KNOT_EINVAL!");
			errors++;
		}
		lived = 1;

		lived = 0;
		ret = knot_tsig_sign((uint8_t *)0x1, (size_t *)0x1, 0,
		                     (uint8_t *)0x1, 0, NULL,
		               NULL, NULL, 0, 0);
		if (ret != KNOT_EINVAL) {
			diag("NULL argument did not return KNOT_EINVAL!");
			errors++;
		}
		lived = 1;

		lived = 0;
		ret = knot_tsig_sign((uint8_t *)0x12345678, (size_t *)0x1,
		                     0,(uint8_t *)0x1, 0,(uint8_t *) 0x1,
		               NULL, NULL, 0, 0);
		if (ret != KNOT_EINVAL) {
			diag("NULL argument did not return KNOT_EINVAL!");
			errors++;
		}
		lived = 1;

		lived = 0;
		ret = knot_tsig_sign((uint8_t *)0x12345678, (size_t *)0x1, 0,
		                     (uint8_t *)0x1, 0,(uint8_t *) 0x1,
		               (size_t *)0x1, NULL, 0, 0);
		if (ret != KNOT_EINVAL) {
			diag("NULL argument did not return KNOT_EINVAL!");
			errors++;
		}
		lived = 1;
	}, "");

	errors += !lived;
	
	if (errors) {
		diag("NULL tests crashed!");
	}

	/* Create some dummy variables. */
	/* One NS rrset. */
	knot_dname_t *ns_dname = knot_dname_new_from_str("test.cz.",
	                                                 strlen("test.cz."),
	                                                 NULL);
	assert(ns_dname);
	knot_rrset_t *ns_rrset = knot_rrset_new(ns_dname, KNOT_RRTYPE_NS, 
	                                        KNOT_CLASS_IN, 3600);
	assert(ns_rrset);
	knot_packet_t *packet = knot_packet_new(KNOT_PACKET_PREALLOC_RESPONSE);
	assert(packet);
	
	/* Add rdata. */
	knot_rdata_t *ns_rdata = knot_rdata_new();
	assert(ns_rdata);
	
	knot_rdata_item_t items[1];
	items[0].dname = ns_dname;
	
	int ret = knot_rdata_set_items(ns_rdata, items, 1);
	assert(ret == KNOT_EOK);
	ret = knot_rrset_add_rdata(ns_rrset, ns_rdata);
	assert(ret == KNOT_EOK);
	
	knot_packet_set_max_size(packet, 2048);
	
	if ((ret = knot_response_add_rrset_answer(packet, ns_rrset,
	                                   0, 0, 0, 0)) != KNOT_EOK) {
		diag("Could not add rrset to packet!"
		     " %s\n", knot_strerror(ret));
		/* No point in continuing. */
		return 0;
	}

	uint8_t *msg = NULL;
	size_t msg_len;
	ret = knot_packet_to_wire(packet, &msg, &msg_len);
	assert(ret == KNOT_EOK);

	size_t msg_copy_length = msg_len;
	uint8_t msg_copy[msg_len];
	memcpy(msg_copy, msg, msg_len);
	
	size_t msg_max_len = 1024;
	uint8_t request_mac[16];
	size_t request_mac_length = 0;
	uint8_t digest[512];
	size_t digest_len;

	knot_key_t key;
	key.algorithm = KNOT_TSIG_ALG_HMAC_MD5;
	key.name = knot_dname_new_from_str("test.",
	                                   strlen("test."), NULL);
	key.secret = "abcdefgh";
	key.secret_size = strlen("abcdefgh");

	/* Test not enough space for wire. */
	ret = knot_tsig_sign(msg, &msg_len, msg_len + 1, request_mac,
	                     request_mac_length,
	               digest, &digest_len, &key, 0, 0);
	if (ret != KNOT_ESPACE) {
		diag("knot_tsig_sign did not return error when given too"
		     " litle space for wire!");
		errors++;
	}

	/* Test normal operation. */
	ret = knot_tsig_sign(msg, &msg_len, msg_max_len, request_mac,
	                     request_mac_length,
	               digest, &digest_len, &key, 0, 0);
	if (ret != KNOT_EOK) {
		diag("knot_tsig_sign failed when given right arguments!");
		return 0;
	}
	
	/*
	 * Now check that the initial wire remained the same.
	 * (Except for arcount)
	 */
	
	/* Read arcount. Should be 1. */
	if (knot_wire_get_arcount(msg) != 1) {
		diag("Signed wire did not have its arcount changed!");
		errors++;
	}
	
	knot_wire_set_arcount(msg, 0);
	/* Wire now should be identical. Compare with its pre-signing copy. */
	if (strncmp((char *)msg, (char *)msg_copy, msg_len) != 0) {
		hex_print((const char*)msg, msg_len);
		hex_print((const char*)msg_copy, msg_len);
		diag("knot_tsig_sign has changed the signed wire!");
		errors++;
	}

	/* Do exactly the same, but add the request_mac variable. */
	request_mac_length = 16;
	memcpy(msg, msg_copy, msg_copy_length);
	msg = msg_copy;
	ret = knot_tsig_sign(msg, &msg_len, msg_max_len, request_mac,
	                     request_mac_length,
	               digest, &digest_len, &key, 0, 0);
	if (ret != KNOT_EOK) {
		diag("knot_tsig_sign failed when given right arguments "
		     "(request mac set)!");
		return 0;
	}

	/* Read arcount. Should be 1. */
	if (knot_wire_get_arcount(msg) != 1) {
		diag("Signed wire did not have its arcount changed!");
		errors++;
	}

	knot_wire_set_arcount(msg, 0);
	/* Wire now should be identical. Compare with its pre-signing copy. */
	if (strncmp((char *)msg, (char *)msg_copy, msg_len) != 0) {
		hex_print((const char*)msg, msg_len);
		hex_print((const char*)msg_copy, msg_len);
		diag("knot_tsig_sign has changed the signed wire!");
		errors++;
	}

	/*
	 * Check that the wire is correctly signed
	 * using knot_tsig_server_check.
	 */

	/* Create dummy tsig_rr. */
	knot_rrset_t *tsig_rr = create_dummy_tsig_rr();
	assert(tsig_rr);

	/* Set the created digest. */
	tsig_rdata_set_mac(tsig_rr, digest_len, digest);

	ret = knot_tsig_server_check(tsig_rr, msg, msg_len, &key);
	if (ret != KNOT_EOK) {
		diag("Signed wire did not pass check!");
		errors++;
	}

//	free(msg);
	return errors == 0;
}

static int test_knot_tsig_sign_next()
{
	int errors = 0;
	/* Test bad arguments. */
	int lived = 0;
	lives_ok({
		int ret = knot_tsig_sign_next(NULL, NULL, 0, NULL, 0, NULL,
		               NULL, NULL, NULL, 0); /*! \todo FIX */
		if (ret != KNOT_EINVAL) {
			diag("NULL argument did not return KNOT_EINVAL!");
			errors++;
		}
		lived = 1;

		lived = 0;
		ret = knot_tsig_sign_next((uint8_t *)0x1, NULL, 0, NULL, 0,
		                          NULL,
		               NULL, NULL, NULL, 0); /*! \todo FIX */
		if (ret != KNOT_EINVAL) {
			diag("NULL argument did not return KNOT_EINVAL!");
			errors++;
		}
		lived = 1;

		lived = 0;
		ret = knot_tsig_sign_next((uint8_t *)0x1, (size_t *)0x1, 0,
		                          NULL, 0, NULL,
		               NULL, NULL, NULL, 0); /*! \todo FIX */
		if (ret != KNOT_EINVAL) {
			diag("NULL argument did not return KNOT_EINVAL!");
			errors++;
		}
		lived = 1;

		lived = 0;
		ret = knot_tsig_sign_next((uint8_t *)0x1, (size_t *)0x1, 0,
		                          (uint8_t *)0x1, 0, NULL,
		               NULL, NULL, NULL, 0); /*! \todo FIX */
		if (ret != KNOT_EINVAL) {
			diag("NULL argument did not return KNOT_EINVAL!");
			errors++;
		}
		lived = 1;

		lived = 0;
		ret = knot_tsig_sign_next((uint8_t *)0x12345678, (size_t *)0x1,
		                          0,(uint8_t *)0x1, 0,(uint8_t *) 0x1,
		               NULL, NULL, NULL, 0); /*! \todo FIX */
		if (ret != KNOT_EINVAL) {
			diag("NULL argument did not return KNOT_EINVAL!");
			errors++;
		}
		lived = 1;

		lived = 0;
		ret = knot_tsig_sign_next((uint8_t *)0x12345678, (size_t *)0x1,
		                          0, (uint8_t *)0x1, 0,(uint8_t *) 0x1,
		               (size_t *)0x1, NULL, NULL, 0); /*! \todo FIX */
		if (ret != KNOT_EINVAL) {
			diag("NULL argument did not return KNOT_EINVAL!");
			errors++;
		}
		lived = 1;
	}, "");

	errors += !lived;
	
	if (errors) {
		diag("NULL tests crashed!");
	}
	
	/* Create some dummy variables. */
	uint8_t msg[2048]; /* Should be random. */
	size_t msg_len = 512;
	size_t msg_max_len = 2048;
	uint8_t *prev_digest = NULL;
	size_t prev_digest_len = 0;
	uint8_t digest[512];
	size_t digest_len = 512;

	knot_key_t key;
	key.algorithm = KNOT_TSIG_ALG_HMAC_MD5;
	key.name = knot_dname_new_from_str("test.",
	                                   strlen("test."), NULL);
	key.secret = "abcdefgh";
	key.secret_size = strlen("abcdefgh");

	/* Test not enough space for wire. */
	int ret = knot_tsig_sign_next(msg, &msg_len, 513, prev_digest,
	                              prev_digest_len,
	               digest, &digest_len, &key, NULL, 0); /*! \todo FIX */
	if (ret != KNOT_ESPACE) {
		diag("knot_tsig_sign_next did not return error when "
		     "given too litle space for wire!"
		     " returned: %s", knot_strerror(ret));
		errors++;
	}
	
	digest_len = 512;

	/* Test normal operation. */
	ret = knot_tsig_sign_next(msg, &msg_len, msg_max_len, prev_digest,
	                          prev_digest_len,
	               digest, &digest_len, &key, NULL, 0); /*! \todo FIX */
	if (ret != KNOT_EOK) {
		diag("knot_tsig_sign_next failed when given right arguments!"
		     " returned: %s", knot_strerror(ret));
		errors++;
	}
	
	/*!< \todo test that the variables have changed and so on. */

	return errors == 0;
}

static int test_knot_tsig_server_check()
{
	int errors = 0;
	/* Test bad arguments. */
	int lived = 0;
	lives_ok({
		int ret = knot_tsig_server_check(NULL, NULL, 0, NULL);
		if (ret != KNOT_EINVAL) {
			diag("NULL argument did not return KNOT_EINVAL!");
			errors++;
		}
		lived = 1;
		
		lived = 0;
		ret = knot_tsig_server_check((knot_rrset_t *)0x1,
		                             (uint8_t *)0x1, 0,
		                                 NULL);
		if (ret != KNOT_EINVAL) {
			diag("NULL argument did not return KNOT_EINVAL!");
			errors++;
		}
		lived = 1;
	}, "");
		
	errors += !lived;
	
	if (errors) {
		diag("NULL tests crashed!");
	}

	/* Create dummy TSIG rr. */
	knot_rrset_t *tsig_rr = create_dummy_tsig_rr();
	assert(tsig_rr);

	
	/* Create dummy key. */
	knot_key_t key;
	key.algorithm = KNOT_TSIG_ALG_HMAC_MD5;
	key.secret = "supersecretsecret";
	key.secret_size = strlen("supersecretsecret");
	/* Bleeding eyes, I know. */
	key.name = (knot_dname_t *)knot_rrset_owner(tsig_rr);

	/* Create dummy wire. */
	uint8_t wire[500];
	size_t wire_size = 500;
	
	/*!< \note
	 * Since there are no meaningful data in the wire,
	 * the function should fail.
	 */
	int ret = knot_tsig_server_check(tsig_rr, wire, wire_size, &key);
	if (ret != KNOT_TSIG_EBADSIG) {
		diag("tsig_server_check did not return "
		     "TSIG_EBADSIG when given random wire!"
		     " returned: %s", knot_strerror(ret));
		errors++;
	}
	
	/* Set 0 time - the error should be TSIG_EBADTIME. */
	tsig_rdata_set_time_signed(tsig_rr, 0);
	ret = knot_tsig_server_check(tsig_rr, wire, wire_size, &key);
	if (ret != KNOT_TSIG_EBADTIME) {
		diag("tsig_server_check did not return TSIG_EBADTIME "
		     "when given zero time!");
		errors++;
	}
		
	return errors == 0;
}

static int test_knot_tsig_client_check()
{
	int errors = 0;
	/* Test bad arguments. */
	int lived = 0;
	lives_ok({
		int ret = knot_tsig_client_check(NULL, NULL, 0, NULL,
	                                         0, NULL, 0);
		if (ret != KNOT_EINVAL) {
			diag("NULL argument did not return KNOT_EINVAL!");
			errors++;
		}
		lived = 1;
	
		lived = 0;
		ret = knot_tsig_client_check((knot_rrset_t *)0x1, NULL, 0, NULL,
	                                         0, NULL, 0);
		if (ret != KNOT_EINVAL) {
			diag("NULL argument did not return KNOT_EINVAL!");
			errors++;
		}
		lived = 1;
	
		lived = 0;
		ret = knot_tsig_client_check((knot_rrset_t *)0x1,
		                             (uint8_t *)0x1, 0, NULL,
	                                         0, NULL, 0);
		if (ret != KNOT_EINVAL) {
			diag("NULL argument did not return KNOT_EINVAL!");
			errors++;
		}
		lived = 1;
		
		lived = 0;
		ret = knot_tsig_client_check((knot_rrset_t *)0x1,
		                             (uint8_t *)0x1, 0, NULL,
	                                         0, NULL, 0);
		if (ret != KNOT_EINVAL) {
			diag("NULL argument did not return KNOT_EINVAL!");
			errors++;
		}
		lived = 1;
	}, "");
		
	errors += !lived;
	
	if (errors) {
		diag("NULL tests crashed!");
	}
	
	knot_dname_t *tsig_owner =
		knot_dname_new_from_str("dummy.key.name.",
	                                strlen("dummy.key.name."), NULL);
	assert(tsig_owner);
	/* Create dummy key. */
	knot_key_t key;
	key.algorithm = KNOT_TSIG_ALG_HMAC_MD5;
	key.secret = "supersecretsecret";
	key.secret_size = strlen("supersecretsecret");
	key.name = tsig_owner;
	
	/* Create dummy TSIG rr. */
	knot_rrset_t *tsig_rr = knot_rrset_new(tsig_owner,
	                                       KNOT_RRTYPE_TSIG,
	                                       KNOT_CLASS_ANY, 0);
	assert(tsig_rr);
	
	knot_rdata_t *tsig_rdata = knot_rdata_new();
	assert(tsig_rr);
	/* Create TSIG items. */
	knot_rdata_item_t items[9];

	/*
	 * I am not sure if 9 is the right count in our impl.,
	 * but is should work fine.
	 */
	knot_rdata_set_items(tsig_rdata, items, 9);
	knot_dname_t *alg_name =
		knot_dname_new_from_str("hmac-md5.sig-alg.reg.int.",
	                                strlen("hmac-md5.sig-alg.reg.int."),
	                                NULL);
	assert(alg_name);
	tsig_rdata_set_alg_name(tsig_rr, alg_name);
	/* Get current time and save it to TSIG rr. */
	time_t current_time = time(NULL);
	tsig_rdata_set_time_signed(tsig_rr, current_time);
	tsig_rdata_set_fudge(tsig_rr, 300);
	tsig_rdata_set_orig_id(tsig_rr, 0);
	tsig_rdata_set_tsig_error(tsig_rr, 0);
	tsig_rdata_set_mac(tsig_rr, strlen("nonsensemac"),
	                   (uint8_t *)"nonsensemac");
		
	/* Create dummy wire. */
	uint8_t wire[500];
	size_t wire_size = 500;
	
	/*!< \note
	 * Since there are no meaningful data in the wire,
	 * the function should fail.
	 */
	int ret = knot_tsig_client_check(tsig_rr,
	                                 wire, wire_size, NULL, 0, &key, 0);
	if (ret != KNOT_TSIG_EBADSIG) {
		diag("tsig_server_check did not return TSIG_EBADSIG when "
		     "given random wire!");
		errors++;
	}
	
	/* Set 0 time - the error should be TSIG_EBADTIME. */
	tsig_rdata_set_time_signed(tsig_rr, 0);
	ret = knot_tsig_client_check(tsig_rr, wire, wire_size, NULL,
	                             0, &key, 0);
	if (ret != KNOT_TSIG_EBADTIME) {
		diag("tsig_server_check did not return "
		     "TSIG_EBADTIME when given zero time!");
		errors++;
	}
		
	return errors == 0;
}

static int test_knot_tsig_client_check_next()
{
	/*!< \todo think of extra test cases. */
	return test_knot_tsig_client_check();
}

static int test_knot_tsig_test_tsig_add()
{
	int errors = 0;
	
	/* Faulty arguments. */
	int lived = 0;
	lives_ok({
		int ret = knot_tsig_add(NULL, NULL, 0, 0, NULL);
		if (ret != KNOT_EINVAL) {
			diag("tsig_add did not return EINVAL "
			     "when given NULL parameters.");
			errors++;
		}
		lived = 1;
		
		lived = 0;
		ret = knot_tsig_add((uint8_t *)0x1, NULL, 0, 0, NULL);
		if (ret != KNOT_EINVAL) {
			diag("tsig_add did not return EINVAL when "
			     "given NULL parameters.");
			errors++;
		}
		lived = 1;
	}, "");
	
	errors += !lived;
	
	if (errors) {
		diag("NULL tests failed!");
	}
	
	size_t wire_size = 512;
	uint8_t wire[wire_size * 2];
	
	/*! \todo Fix */
	int ret = knot_tsig_add(wire, &wire_size, wire_size * 2, 0, NULL);
	if (ret != KNOT_EOK) {
		diag("tsig_add did not return EOK when given valid parameters."
		     " returned: %s", knot_strerror(ret));
		errors++;
	}
	
	return errors == 0;
}

/*! This helper routine should report number of
 *  scheduled tests for given parameters.
 */
static int knot_tsig_tests_count(int argc, char *argv[])
{
	return KNOT_TSIG_TEST_COUNT;
}

/*! Run all scheduled tests for given parameters.
 */
static int knot_tsig_tests_run(int argc, char *argv[])
{
	int res_final = 0;
	int res = 0;

	ok(res = test_knot_tsig_sign(), "tsig: sign");
	res_final *= res;
	ok(res = test_knot_tsig_sign_next(), "tsig: sign next");
	res_final *= res;
	ok(res = test_knot_tsig_server_check(), "tsig: server check");
	res_final *= res;
	ok(res = test_knot_tsig_client_check(), "tsig: client check");
	res_final *= res;
	ok(res = test_knot_tsig_client_check_next(), "tsig: client check next");
	res_final *= res;
	ok(res = test_knot_tsig_test_tsig_add(), "tsig: tsig add");
	res_final *= res;

	return res_final;
}
