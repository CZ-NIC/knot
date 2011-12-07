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

#include "tests/libknot/libknot/rrset_tests.h"
#include "libknot/common.h"
#include "libknot/util/descriptor.h"
#include "libknot/rrset.h"
#include "libknot/dname.h"
#include "libknot/util/error.h"
#include "libknot/tsig-op.h"
#include "libknot/util/utils.h"
#include "libknot/zone/node.h"
#include "libknot/util/debug.h"


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

static const int KNOT_TSIG_TEST_COUNT = 2;

static int test_knot_tsig_sign()
{
	int errors = 0;
	/* Test bad arguments. */
	int lived = 0;
	lives_ok(
		int ret = knot_tsig_sign(NULL, NULL, 0, NULL, 0, NULL,
		               NULL, NULL, 0, 0);
		if (ret != KNOT_EBADARG) {
			diag("NULL argument did not return KNOT_EBADARG!");
			errors++;
		}
		lived = 1;

		lived = 0;
		ret = knot_tsig_sign((uint8_t *)0x1, NULL, 0, NULL, 0, NULL,
		               NULL, NULL, 0, 0);
		if (ret != KNOT_EBADARG) {
			diag("NULL argument did not return KNOT_EBADARG!");
			errors++;
		}
		lived = 1;

		lived = 0;
		ret = knot_tsig_sign((uint8_t *)0x1, (size_t *)0x1, 0, NULL, 0, NULL,
		               NULL, NULL, 0, 0);
		if (ret != KNOT_EBADARG) {
			diag("NULL argument did not return KNOT_EBADARG!");
			errors++;
		}
		lived = 1;

		lived = 0;
		ret = knot_tsig_sign((uint8_t *)0x1, (size_t *)0x1, 0, (uint8_t *)0x1, 0, NULL,
		               NULL, NULL, 0, 0);
		if (ret != KNOT_EBADARG) {
			diag("NULL argument did not return KNOT_EBADARG!");
			errors++;
		}
		lived = 1;

		lived = 0;
		ret = knot_tsig_sign((uint8_t *)0x12345678, (size_t *)0x1, 0,(uint8_t *)0x1, 0,(uint8_t *) 0x1,
		               NULL, NULL, 0, 0);
		if (ret != KNOT_EBADARG) {
			diag("NULL argument did not return KNOT_EBADARG!");
			errors++;
		}
		lived = 1;

		lived = 0;
		ret = knot_tsig_sign((uint8_t *)0x12345678, (size_t *)0x1, 0, (uint8_t *)0x1, 0,(uint8_t *) 0x1,
		               (size_t *)0x1, NULL, 0, 0);
		if (ret != KNOT_EBADARG) {
			diag("NULL argument did not return KNOT_EBADARG!");
			errors++;
		}
		lived = 1;
	);

	errors += !lived;

	/* Create some dummy variables. */
	uint8_t msg[1024]; /* Should be random. */
	size_t msg_len = 512;
	size_t msg_max_len = 1024;
	uint8_t *request_mac = NULL;
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
	int ret = knot_tsig_sign(msg, &msg_len, 520, request_mac, request_mac_length,
	               digest, &digest_len, &key, 0, 0);
	if (ret != KNOT_ESPACE) {
		diag("knot_tsig_sign did not return error when given too litle space for wire!");
		errors++;
	}

	/* Test normal operation. */
	ret = knot_tsig_sign(msg, &msg_len, msg_max_len, request_mac, request_mac_length,
	               digest, &digest_len, &key, 0, 0);
	if (ret != KNOT_EOK) {
		diag("knot_tsig_sign failed when given right arguments!");
		errors++;
	}

	return errors == 0;
}

static int test_knot_tsig_sign_next()
{
	int errors = 0;
	/* Test bad arguments. */
	int lived = 0;
	lives_ok(
		int ret = knot_tsig_sign_next(NULL, NULL, 0, NULL, 0, NULL,
		               NULL, NULL);
		if (ret != KNOT_EBADARG) {
			diag("NULL argument did not return KNOT_EBADARG!");
			errors++;
		}
		lived = 1;

		lived = 0;
		ret = knot_tsig_sign_next((uint8_t *)0x1, NULL, 0, NULL, 0, NULL,
		               NULL, NULL);
		if (ret != KNOT_EBADARG) {
			diag("NULL argument did not return KNOT_EBADARG!");
			errors++;
		}
		lived = 1;

		lived = 0;
		ret = knot_tsig_sign_next((uint8_t *)0x1, (size_t *)0x1, 0, NULL, 0, NULL,
		               NULL, NULL);
		if (ret != KNOT_EBADARG) {
			diag("NULL argument did not return KNOT_EBADARG!");
			errors++;
		}
		lived = 1;

		lived = 0;
		ret = knot_tsig_sign_next((uint8_t *)0x1, (size_t *)0x1, 0, (uint8_t *)0x1, 0, NULL,
		               NULL, NULL);
		if (ret != KNOT_EBADARG) {
			diag("NULL argument did not return KNOT_EBADARG!");
			errors++;
		}
		lived = 1;

		lived = 0;
		ret = knot_tsig_sign_next((uint8_t *)0x12345678, (size_t *)0x1, 0,(uint8_t *)0x1, 0,(uint8_t *) 0x1,
		               NULL, NULL);
		if (ret != KNOT_EBADARG) {
			diag("NULL argument did not return KNOT_EBADARG!");
			errors++;
		}
		lived = 1;

		lived = 0;
		ret = knot_tsig_sign_next((uint8_t *)0x12345678, (size_t *)0x1, 0, (uint8_t *)0x1, 0,(uint8_t *) 0x1,
		               (size_t *)0x1, NULL);
		if (ret != KNOT_EBADARG) {
			diag("NULL argument did not return KNOT_EBADARG!");
			errors++;
		}
		lived = 1;
	);

	errors += !lived;


	return errors == 0;
}

static int test_knot_tsig_server_check()
{
	return 1;
}

static int test_knot_tsig_client_check()
{
	return 1;
}

static int test_knot_tsig_client_check_next()
{
	return 1;
}

static int test_knot_tsig_test_tsig_add()
{
	return 1;
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
