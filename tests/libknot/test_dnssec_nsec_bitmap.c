/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <tap/basic.h>

#include "libknot/dnssec/nsec.h"
#include "libknot/descriptor.h"

#define TEST_BITMAP_SIZE 18

int main(void)
{
	plan_lazy();

	// Which rrtypes will be contained in the bitmap.
	int test_contains_count = 8;
	enum knot_rr_type test_contains[] = {
		KNOT_RRTYPE_A,
		KNOT_RRTYPE_NS,
		KNOT_RRTYPE_SOA,
		KNOT_RRTYPE_RRSIG,
		KNOT_RRTYPE_NSEC,
		KNOT_RRTYPE_DNSKEY,
		KNOT_RRTYPE_SPF,
		KNOT_RRTYPE_CAA
	};

	// Which rrtypes will not be contained in the bitmap.
	int test_not_contains_count = 4;
	enum knot_rr_type test_not_contains[] = {
		KNOT_RRTYPE_AAAA,
		KNOT_RRTYPE_MX,
		KNOT_RRTYPE_AXFR,
		KNOT_RRTYPE_CNAME
	};

	// Allocate new bitmap.
	dnssec_nsec_bitmap_t *bitmap = dnssec_nsec_bitmap_new();
	ok(bitmap != NULL, "allocate bitmap");
	if (!bitmap) {
		return 1;
	}

	// Add the desired RR types to bitmap.
	for (int i = 0; i < test_contains_count; i++) {
		dnssec_nsec_bitmap_add(bitmap, test_contains[i]);
	}

	size_t size = dnssec_nsec_bitmap_size(bitmap);
	ok(size == TEST_BITMAP_SIZE, "valid bitmap size");
	if (size != TEST_BITMAP_SIZE) {
		dnssec_nsec_bitmap_free(bitmap);
		return 1;
	}

	const uint8_t expected[TEST_BITMAP_SIZE] = {
		0x00, 0x0D, 0x62, 0x00, 0x00, 0x00, 0x00, 0x03, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
		0x01, 0x01, 0x40
	};
	uint8_t encoded[TEST_BITMAP_SIZE] = { 0 };
	dnssec_nsec_bitmap_write(bitmap, encoded);

	ok(memcmp(encoded, expected, TEST_BITMAP_SIZE) == 0, "valid bitmap");

	// Test contained types.
	char rrtype_str[50];
	for (int i = 0; i < test_contains_count; i++) {
		bool contains = dnssec_nsec_bitmap_contains(encoded, size, test_contains[i]);
		(void)knot_rrtype_to_string(test_contains[i], rrtype_str, 50);
		ok(contains, "bitmap contains %s", rrtype_str);
	}

	// Test not contained types.
	for (int i = 0; i < test_not_contains_count; i++) {
		bool contains = dnssec_nsec_bitmap_contains(encoded, size, test_not_contains[i]);
		(void)knot_rrtype_to_string(test_not_contains[i], rrtype_str, 50);
		ok(!contains, "bitmap does not contain %s", rrtype_str);
	}

	dnssec_nsec_bitmap_clear(bitmap);
	ok(dnssec_nsec_bitmap_size(bitmap) == 0, "bitmap clear");

	dnssec_nsec_bitmap_free(bitmap);
	return 0;
}
