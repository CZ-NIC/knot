/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <tap/basic.h>
#include <string.h>

#include "binary.h"
#include "dname.c"
#include "tsig.h"

static const dnssec_binary_t payload = {
	.size = 40,
	.data = (uint8_t []){
		0xfd, 0x07, 0xca, 0x30, 0xf9, 0xff, 0x38, 0xb1, 0x32, 0x54,
		0xd1, 0x16, 0x24, 0xaa, 0x81, 0x2c, 0x97, 0xa0, 0x7a, 0xac,
		0x68, 0x7a, 0x3a, 0x60, 0xde, 0xc9, 0xf7, 0x7a, 0x5a, 0x58,
		0xff, 0xc9, 0x0c, 0xef, 0x31, 0xc7, 0x45, 0x2c, 0xee, 0x9d,
	}
};

static const dnssec_binary_t key = {
	.size = 16,
	.data = (uint8_t []){
		0xa8, 0x05, 0x9c, 0x5c, 0x20, 0xc5, 0x00, 0x22, 0x6f, 0xad,
		0xf2, 0x55, 0xdf, 0x89, 0x8a, 0x68
	}
};

typedef struct hmac {
	int algorithm;
	const char *name;
	const dnssec_binary_t hmac;
} hmac_t;

static const hmac_t HMACS[] = {
	{ DNSSEC_TSIG_HMAC_MD5, "md5", { .size = 16, .data = (uint8_t []) {
		0x12, 0x38, 0x17, 0x4f, 0xa9, 0xc7, 0x5b, 0xcf, 0xd7, 0x08,
		0x19, 0x97, 0xf9, 0x3d, 0x5e, 0xe7
	}}},
	{ DNSSEC_TSIG_HMAC_SHA1, "sha1", { .size = 20, .data = (uint8_t []) {
		0xb8, 0x18, 0x2a, 0x5d, 0xf8, 0x2e, 0xa0, 0xb7, 0xcc, 0xcc,
		0xed, 0xc1, 0xaa, 0x34, 0xeb, 0x92, 0x48, 0xf9, 0x65, 0x7b
	}}},
	{ DNSSEC_TSIG_HMAC_SHA224, "sha224", { .size = 28, .data = (uint8_t []) {
		0xb7, 0x43, 0xcd, 0x0d, 0x9d, 0x51, 0x8c, 0x61, 0xc6, 0x43,
		0x98, 0x73, 0x5c, 0x16, 0x01, 0x1b, 0xfc, 0x82, 0xe9, 0x99,
		0xc2, 0x21, 0xde, 0x16, 0xb1, 0x94, 0x2d, 0xd5
	}}},
	{ DNSSEC_TSIG_HMAC_SHA256, "sha256", { .size = 32, .data = (uint8_t []) {
		0x16, 0x5e, 0xf6, 0xed, 0x9b, 0x1a, 0xe5, 0x67, 0x58, 0x7b,
		0xf1, 0x35, 0x9e, 0x59, 0xbd, 0x50, 0x6d, 0x72, 0xf8, 0x87,
		0x0e, 0x22, 0xda, 0x65, 0x00, 0xd6, 0x76, 0x91, 0xde, 0x5f,
		0xec, 0xd8
	}}},
	{ DNSSEC_TSIG_HMAC_SHA384, "sha384", { .size = 48, .data = (uint8_t []) {
		0x8a, 0xcf, 0xf3, 0xb7, 0x1c, 0xbe, 0x5c, 0x3e, 0x05, 0x74,
		0x97, 0x46, 0x04, 0x79, 0x3a, 0xe7, 0x8a, 0x5b, 0x7b, 0x12,
		0xca, 0xcd, 0xf2, 0xe2, 0xdf, 0xa9, 0x17, 0xfc, 0x8e, 0x61,
		0xc5, 0x86, 0x3e, 0xdc, 0xad, 0x84, 0x9e, 0x13, 0x0d, 0xa0,
		0x04, 0xb6, 0x6f, 0x7c, 0x85, 0x1b, 0x5c, 0xdf
	}}},
	{ DNSSEC_TSIG_HMAC_SHA512, "sha512", { .size = 64, .data = (uint8_t []) {
		0xc3, 0x41, 0xd0, 0x96, 0x50, 0xd7, 0xf7, 0xfd, 0x59, 0x73,
		0xde, 0xd6, 0xc7, 0x4c, 0xda, 0xf1, 0x5d, 0xe1, 0x59, 0x34,
		0x79, 0xdc, 0x93, 0x23, 0xcb, 0xf2, 0x1f, 0x25, 0x4e, 0x35,
		0xb0, 0xd0, 0x9f, 0xfc, 0x22, 0xf1, 0xea, 0xbf, 0x9c, 0x18,
		0xd8, 0xcc, 0xcd, 0xb6, 0xb1, 0x4a, 0x06, 0x09, 0xc4, 0x3f,
		0x28, 0x93, 0x71, 0xd6, 0xca, 0xce, 0xf3, 0xa6, 0x08, 0x38,
		0xe3, 0x99, 0xc1, 0xb2
	}}},
	{ 0 }
};

static void test_lookup_dname(const uint8_t *dname, int algorithm)
{
	dnssec_tsig_algorithm_t alg = dnssec_tsig_algorithm_from_dname(dname);
	const char *name = dnssec_tsig_algorithm_to_name(algorithm);
	if (name == NULL) name = "invalid";
	ok(alg == algorithm, "dnssec_tsig_algorithm_from_dname(%s)", name);

	const uint8_t *reverse = dnssec_tsig_algorithm_to_dname(algorithm);
	ok((algorithm == DNSSEC_TSIG_UNKNOWN && reverse == NULL) ||
	   (algorithm != DNSSEC_TSIG_UNKNOWN && dname_equal(reverse, dname)),
	  "dnssec_tsig_algorithm_to_dname(%d)", algorithm);
}

static void test_lookup_name(const char *name, int algorithm)
{
	ok(dnssec_tsig_algorithm_from_name(name) == algorithm,
	   "dnssec_tsig_algorithm_from_name(%s)", name);

	const char *reverse = dnssec_tsig_algorithm_to_name(algorithm);
	ok((algorithm == DNSSEC_TSIG_UNKNOWN && reverse == NULL) ||
	   (algorithm != DNSSEC_TSIG_UNKNOWN && strcasecmp(reverse, name) == 0),
	   "dnssec_tsig_algorithm_to_name(%d)", algorithm);
}

static void test_tsig_hmac(const hmac_t *params)
{
	dnssec_tsig_ctx_t *ctx = NULL;
	dnssec_tsig_new(&ctx, params->algorithm, &key);
	dnssec_tsig_add(ctx, &payload);

	size_t size = dnssec_tsig_size(ctx);
	uint8_t hmac[size];
	memset(&hmac, 0, size);
	dnssec_tsig_write(ctx, hmac);
	dnssec_tsig_free(ctx);

	ok(size == params->hmac.size && memcmp(hmac, params->hmac.data, size) == 0,
	  "dnssec_tsig_write(%s)", params->name);
}

int main(void)
{
	plan_lazy();

	test_lookup_dname((uint8_t *)"\x08""HMAC-MD5""\x07""SIG-ALG""\x03""REG""\x03""INT",
	                  DNSSEC_TSIG_HMAC_MD5);
	test_lookup_dname((uint8_t *)"\x0B""hmac-sha224", DNSSEC_TSIG_HMAC_SHA224);
	test_lookup_dname((uint8_t *)"\x06""foobar", DNSSEC_TSIG_UNKNOWN);

	test_lookup_name("hmac-md5", DNSSEC_TSIG_HMAC_MD5);
	test_lookup_name("hmac-sha512", DNSSEC_TSIG_HMAC_SHA512);
	test_lookup_name("barfoo", DNSSEC_TSIG_UNKNOWN);
	test_lookup_name("hmac-foo", DNSSEC_TSIG_UNKNOWN);

	for (const hmac_t *h = HMACS; h->algorithm != 0; h++) {
		test_tsig_hmac(h);
	}

	return 0;
}
