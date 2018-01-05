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

#include <tap/basic.h>

#include "binary.h"
#include "binary_wire.h"
#include "bignum.h"

int main(void)
{
	plan_lazy();

	wire_ctx_t wire = { 0 };

	dnssec_binary_t buffer = { .size = 20, .data = (uint8_t []) {
		0xc8, 0x25, 0x19, 0x3c, 0x96, 0xe6, 0x59, 0xf7, 0x2b, 0x94,
		0x83, 0xb3, 0x3e, 0x6f, 0xb9, 0x01, 0xe2, 0x91, 0xa8, 0xa9,
	}};

	wire = wire_init(buffer.data + 10, 10);
	ok(wire_read_u8(&wire) == 0x83, "wire_init()");

	wire = binary_init(&buffer);
	ok(wire_read_u8(&wire) == 0xc8, "binary_init()");

	// read operations

	wire_seek(&wire, 5);
	ok(wire_read_u8(&wire) == 0xe6, "wire_seek() forward");
	wire_seek(&wire, 3);
	ok(wire_read_u8(&wire) == 0x3c, "wire_seek() backward");

	wire_seek(&wire, 10);
	ok(wire_read_u8(&wire) == 0x83, "wire_read_u8()");
	ok(wire_read_u16(&wire) == 45886, "wire_read_u16()");
	ok(wire_tell(&wire) == 13, "wire_tell()");
	ok(wire_available(&wire) == 7, "wire_available()");

	dnssec_binary_t ref = { 0 };
	binary_available(&wire, &ref);
	ok(ref.data == buffer.data + 13 && ref.size == 7, "binary_available()");

	uint8_t in[6] = { 0 };
	wire_seek(&wire, 4);
	wire_read(&wire, in, 6);
	ok(memcmp(in, buffer.data + 4, 6) == 0 && wire_tell(&wire) == 10,
	   "wire_read()");

	// write operations

	wire_seek(&wire, 0);

	wire_write_u8(&wire, 0x42);
	ok(buffer.data[0] == 0x42 && wire_tell(&wire) == 1,
	   "wire_write_u8()");
	wire_write_u16(&wire, 44513);
	ok(memcmp(buffer.data + 1, "\xad\xe1", 2) == 0 && wire_tell(&wire) == 3,
	   "wire_write_u16()");

	wire_seek(&wire, 12);
	const uint8_t out[7] = { 0xc0, 0x1d, 0xca, 0xfe, 0xde, 0xad, 0xbe };
	wire_write(&wire, out, 7);
	ok(memcmp(buffer.data + 12, out, 7) == 0 && wire_tell(&wire) == 19,
	   "wire_write()");

	dnssec_binary_t bignum = { .data = (uint8_t *)out, .size = 4 };
	const uint8_t expect[8] = { 0x00, 0x00, 0x00, 0x00, 0xc0, 0x1d, 0xca, 0xfe };
	wire_seek(&wire, 2);
	bignum_write(&wire, 8, &bignum);
	ok(memcmp(buffer.data + 2, expect, 8) == 0 && wire_tell(&wire) == 10,
	   "wire_write_ralign()");

	return 0;
}
