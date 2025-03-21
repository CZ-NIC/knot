/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <tap/basic.h>

#include "libknot/wire.h"

#define write_test(size, value, ...) { \
	const uint8_t expect[] = { __VA_ARGS__ }; \
	uint8_t wdata[sizeof(expect)] = { 0x00 }; \
	knot_wire_write_u ## size(wdata, value); \
	ok(memcmp(wdata, expect, sizeof(expect)) == 0, "%d-bit write", size); \
}

int main(int argc, char *argv[])
{
	plan(8);

	const uint8_t rdata[] = { 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };

	is_hex(            0x8899, knot_wire_read_u16(rdata), "16-bit read");
	is_hex(        0x8899aabb, knot_wire_read_u32(rdata), "32-bit read");
	is_hex(    0x8899aabbccdd, knot_wire_read_u48(rdata), "48-bit read");
	is_hex(0x8899aabbccddeeff, knot_wire_read_u64(rdata), "64-bit read");

	write_test(16, 0x1122,             0x11, 0x22);
	write_test(32, 0x66778899,         0x66, 0x77, 0x88, 0x99);
	write_test(48, 0xbbccdd778899,     0xbb, 0xcc, 0xdd, 0x77, 0x88, 0x99);
	write_test(64, 0xbbccddee66778899, 0xbb, 0xcc, 0xdd, 0xee,
	                                   0x66, 0x77, 0x88, 0x99);

	return 0;
}
