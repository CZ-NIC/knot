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
