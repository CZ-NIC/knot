/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <string.h>
#include <tap/basic.h>

#include "crypto.h"
#include "error.h"
#include "nsec.h"

static const dnssec_binary_t RDATA = { .size = 9, .data = (uint8_t []) {
	0x01,			// algorithm
	0x00,			// flags
	0x00, 0x0a,		// iterations
	0x04,			// salt length
	'a', 'b', 'c', 'd'	// salt
}};

static void test_length(void)
{
	ok(dnssec_nsec3_hash_length(DNSSEC_NSEC3_ALGORITHM_SHA1) == 20,
	   "dnssec_nsec3_hash_length() for SHA1");
}

static void test_parsing(void)
{

	dnssec_nsec3_params_t params = { 0 };
	int result = dnssec_nsec3_params_from_rdata(&params, &RDATA);
	ok(result == DNSSEC_EOK, "dnssec_nsec3_params_from_rdata()");

	ok(params.algorithm == 1, "algorithm");
	ok(params.flags == 0, "flags");
	ok(params.iterations == 10, "iterations");
	ok(params.salt.size == 4, "salt length");
	ok(params.salt.data != NULL && memcmp(params.salt.data, "abcd", 4) == 0,
	   "salt content");

	dnssec_nsec3_params_free(&params);
	ok(params.salt.data == NULL, "dnssec_nsec3_params_free()");
}

static void test_hashing(void)
{
	const dnssec_binary_t dname = {
		.size = 13,
		.data = (uint8_t *) "\x08""knot-dns""\x02""cz"
	};

	const dnssec_nsec3_params_t params = {
		.algorithm = DNSSEC_NSEC3_ALGORITHM_SHA1,
		.flags = 0,
		.iterations = 7,
		.salt = { .size = 14, .data = (uint8_t *) "happywithnsec3" }
	};

	const dnssec_binary_t expected = { .size = 20, .data = (uint8_t []) {
		0x72, 0x40, 0x55, 0x83, 0x92, 0x93, 0x95, 0x28, 0xee, 0xa2,
		0xcc, 0xe1, 0x13, 0xbe, 0xcd, 0x41, 0xee, 0x8a, 0x71, 0xfd
	}};

	dnssec_binary_t hash = { 0 };

	int result = dnssec_nsec3_hash(&dname, &params, &hash);
	ok(result == DNSSEC_EOK, "dnssec_nsec3_hash()");

	ok(hash.size == expected.size && hash.data != NULL &&
	   memcmp(hash.data, expected.data, expected.size) == 0,
	   "valid hash");

	dnssec_binary_free(&hash);
}

static void test_clear(void)
{
	const dnssec_nsec3_params_t empty = { 0 };
	dnssec_nsec3_params_t params = { 0 };

	int result = dnssec_nsec3_params_from_rdata(&params, &RDATA);
	ok(result == DNSSEC_EOK, "dnssec_nsec3_params_from_rdata()");

	ok(memcmp(&params, &empty, sizeof(dnssec_nsec3_params_t)) != 0,
	   "non-empty after dnssec_nsec3_params_from_rdata()");

	dnssec_nsec3_params_free(&params);

	ok(memcmp(&params, &empty, sizeof(dnssec_nsec3_params_t)) == 0,
	   "cleared after dnssec_nsec3_params_free()");
}

int main(void)
{
	plan_lazy();

	test_length();
	test_parsing();
	test_hashing();
	test_clear();

	return 0;
}
