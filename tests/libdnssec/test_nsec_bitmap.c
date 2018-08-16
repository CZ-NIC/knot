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
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <tap/basic.h>

#include "nsec.h"
#include "libknot/descriptor.h"

int main(void)
{
	plan_lazy();

	dnssec_nsec_bitmap_t *bitmap = dnssec_nsec_bitmap_new();
	ok(bitmap != NULL, "allocate bitmap");
	if (!bitmap) {
		return 1;
	}

	dnssec_nsec_bitmap_add(bitmap, 1);	// A
	dnssec_nsec_bitmap_add(bitmap, 2);	// NS
	dnssec_nsec_bitmap_add(bitmap, 6);	// SOA
	dnssec_nsec_bitmap_add(bitmap, 46);	// RRSIG
	dnssec_nsec_bitmap_add(bitmap, 47);	// NSEC
	dnssec_nsec_bitmap_add(bitmap, 48);	// DNSKEY
	dnssec_nsec_bitmap_add(bitmap, 99);	// SPF
	dnssec_nsec_bitmap_add(bitmap, 257);	// CAA

	size_t size = dnssec_nsec_bitmap_size(bitmap);
	/*
	ok(size == 9, "valid bitmap size");
	if (size != 9) {
		dnssec_nsec_bitmap_free(bitmap);
		return 1;
	}

	const uint8_t expected[9] = {
		0x00, 0x07, 0x62, 0x01, 0x80, 0x08, 0x00, 0x0b, 0x80
	};
	*/
	uint8_t encoded[50] = { 0 };
	dnssec_nsec_bitmap_write(bitmap, encoded);

	//ok(memcmp(encoded, expected, 9) == 0, "valid bitmap");

	bool contains = dnssec_nsec_bitmap_contains(encoded, size, KNOT_RRTYPE_AAAA);
	ok(!contains, "bitmap contains AAAA");
	contains = dnssec_nsec_bitmap_contains(encoded, size, KNOT_RRTYPE_A);
	ok(contains, "bitmap contains A");
	contains = dnssec_nsec_bitmap_contains(encoded, size, KNOT_RRTYPE_CNAME);
	ok(!contains, "bitmap does not contain CNAME");

	dnssec_nsec_bitmap_clear(bitmap);
	ok(dnssec_nsec_bitmap_size(bitmap) == 0, "bitmap clear");

	dnssec_nsec_bitmap_free(bitmap);

	return 0;
}
