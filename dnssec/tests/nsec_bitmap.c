#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <tap/basic.h>

#include "nsec/bitmap.h"

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
	dnssec_nsec_bitmap_add(bitmap, 15);	// MX
	dnssec_nsec_bitmap_add(bitmap, 16);	// TXT
	dnssec_nsec_bitmap_add(bitmap, 28);	// AAAA
	dnssec_nsec_bitmap_add(bitmap, 44);	// SSHFP
	dnssec_nsec_bitmap_add(bitmap, 46);	// RRSIG
	dnssec_nsec_bitmap_add(bitmap, 47);	// NSEC
	dnssec_nsec_bitmap_add(bitmap, 48);	// DNSKEY

	size_t size = dnssec_nsec_bitmap_size(bitmap);
	ok(size == 9, "valid bitmap size");
	if (size != 9) {
		dnssec_nsec_bitmap_free(bitmap);
		return 1;
	}

	const uint8_t expected[9] = {
		0x00, 0x07, 0x62, 0x01, 0x80, 0x08, 0x00, 0x0b, 0x80
	};
	uint8_t encoded[9] = { 0 };
	dnssec_nsec_bitmap_write(bitmap, encoded);

	ok(memcmp(encoded, expected, 9) == 0, "valid bitmap");

	dnssec_nsec_bitmap_clear(bitmap);
	ok(dnssec_nsec_bitmap_size(bitmap) == 0, "bitmap clear");

	dnssec_nsec_bitmap_free(bitmap);

	return 0;
}
