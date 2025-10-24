/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <stdint.h>
#include <string.h>
#include <tap/basic.h>

#include "libknot/dnssec/binary.h"
#include "libknot/errcode.h"

typedef struct test_string {
	const char *encoded;
	size_t encoded_size;
	const char *decoded;
	size_t decoded_size;
} test_string_t;

static void test_base64(void)
{
	test_string_t data[] = {
		{ "",         0, "",       0 },
		{ "YQ==",     4, "a",      1 },
		{ "YWI=",     4, "ab",     2 },
		{ "YWJj",     4, "abc",    3 },
		{ "YWJjZA==", 8, "abcd",   4 },
		{ "YWJjZGU=", 8, "abcde",  5 },
		{ "YWJjZGVm", 8, "abcdef", 6 },
		{ NULL }
	};

	for (int i = 0; data[i].encoded != NULL; i++) {
		test_string_t *ts = &data[i];

		const dnssec_binary_t base64 = {
			.size = ts->encoded_size,
			.data = (uint8_t *) ts->encoded
		};

		dnssec_binary_t binary = { 0 };

		int r = dnssec_binary_from_base64(&base64, &binary);
		ok(r == KNOT_EOK &&
		   binary.size == ts->decoded_size &&
		   (binary.size == 0 || memcmp(binary.data, ts->decoded, binary.size) == 0),
		   "dnssec_binary_from_base64() for '%s'", ts->encoded);

		dnssec_binary_t encoded = { 0 };
		r = dnssec_binary_to_base64(&binary, &encoded);
		ok(r == KNOT_EOK &&
		   encoded.size == ts->encoded_size &&
		   memcmp(encoded.data, ts->encoded, encoded.size) == 0,
		   "dnssec_binary_to_base64() for '%s'", ts->encoded);

		dnssec_binary_free(&binary);
		dnssec_binary_free(&encoded);
	}
}

static void test_dup(void)
{
	dnssec_binary_t src = { .size = 5, .data = (uint8_t *) "ahoj" };
	dnssec_binary_t dst = { 0 };

	int r = dnssec_binary_dup(&src, &dst);
	ok(r == KNOT_EOK &&
	   src.size == dst.size && memcmp(src.data, dst.data, src.size) == 0,
	   "dnssec_binary_dup()");

	dnssec_binary_free(&dst);
}

int main(void)
{
	plan_lazy();

	test_base64();
	test_dup();

	return 0;
}
