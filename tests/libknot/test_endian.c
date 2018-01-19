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

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <tap/basic.h>

#include "libknot/endian.h"

int main(int argc, char *argv[])
{
	plan(12);

	typedef union {
		uint16_t value;
		uint8_t  array[2];
	} trafo16_t;

	const uint16_t host16 = 0x0102;
	const trafo16_t be16 = { .array = { 0x01, 0x02 } };
	const trafo16_t le16 = { .array = { 0x02, 0x01 } };
	ok(htobe16(host16) == be16.value, "htobe16");
	ok(htole16(host16) == le16.value, "htole16");
	ok(be16toh(be16.value) == host16, "be16toh");
	ok(le16toh(le16.value) == host16, "le16toh");

	typedef union {
		uint32_t value;
		uint8_t  array[4];
	} trafo32_t;

	const uint32_t host32 = 0x01020304;
	const trafo32_t be32 = { .array = { 0x01, 0x02, 0x03, 0x04 } };
	const trafo32_t le32 = { .array = { 0x04, 0x03, 0x02, 0x01 } };
	ok(htobe32(host32) == be32.value, "htobe32");
	ok(htole32(host32) == le32.value, "htole32");
	ok(be32toh(be32.value) == host32, "be32toh");
	ok(le32toh(le32.value) == host32, "le32toh");

	typedef union {
		uint64_t value;
		uint8_t  array[8];
	} trafo64_t;

	const uint64_t host64 = 0x0102030405060708;
	const trafo64_t be64 = { .array = { 0x01, 0x02, 0x03, 0x04,
	                                    0x05, 0x06, 0x07, 0x08 } };
	const trafo64_t le64 = { .array = { 0x08, 0x07, 0x06, 0x05,
	                                    0x04, 0x03, 0x02, 0x01 } };
	ok(htobe64(host64) == be64.value, "htobe64");
	ok(htole64(host64) == le64.value, "htole64");
	ok(be64toh(be64.value) == host64, "be64toh");
	ok(le64toh(le64.value) == host64, "le64toh");

	return 0;
}
