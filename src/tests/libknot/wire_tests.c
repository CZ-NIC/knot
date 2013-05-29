/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <config.h>
#include "tests/libknot/wire_tests.h"
#include "libknot/util/utils.h"

static int wire_tests_count(int argc, char *argv[]);
static int wire_tests_run(int argc, char *argv[]);

unit_api wire_tests_api = {
	"Wire",
	&wire_tests_count,
	&wire_tests_run
};

static int wire_tests_count(int argc, char *argv[])
{
	return 8;
}

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	#define ENDIAN_MATCH(expression, match_little, match_big) \
		((expression) == (match_little))
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	#define ENDIAN_MATCH(expression, match_little, match_big) \
		((expression) == (match_big))
#else
	#error Unsupported byte order.
#endif

static int wire_tests_run(int argc, char *argv[])
{
	// 1. - 16-bit read
	{
		uint16_t data = 0xAABB;
		ok(ENDIAN_MATCH(knot_wire_read_u16((uint8_t *)&data),
		   0xBBAA, 0xAABB), "16-bit read");
	}

	// 2. - 16-bit read
	{
		uint16_t data_in = 0xAABB;
		uint64_t data_out = 0xFF0000;
		knot_wire_write_u16((uint8_t *)&data_out, data_in);
		ok(ENDIAN_MATCH(data_out,
		   0xFFBBAA, 0xFFAABB), "16-bit write");
	}

	// 3. - 32-bit read
	{
		uint32_t data = 0xAABBCCDD;
		ok(ENDIAN_MATCH(knot_wire_read_u32((uint8_t *)&data),
		   0xDDCCBBAA, 0xAABBCCDD), "32-bit read");
	}

	// 4. - 32-bit write
	{
		uint32_t data_in = 0xAABBCCDD;
		uint64_t data_out = 0xFF00000000;
		knot_wire_write_u32((uint8_t *)&data_out, data_in);
		ok(ENDIAN_MATCH(data_out,
		   0xFFDDCCBBAA, 0xFFAABBCCDD), "32-bit write");

	}

	// 5. - 48-bit read
	{
		uint64_t data = 0x81AABBCCDDEEFF;
		ok(ENDIAN_MATCH(knot_wire_read_u48((uint8_t *)&data),
		   0xFFEEDDCCBBAA, 0xAABBCCDDEEFF), "48-bit read");
	}

	// 6. - 48-bit write
	{
		uint64_t data_in = 0x81AABBCCDDEEFF;
		uint64_t data_out = 0xDD000000000000;
		knot_wire_write_u48((uint8_t *)&data_out, data_in);
		ok(ENDIAN_MATCH(data_out,
		   0xDDFFEEDDCCBBAA, 0xDDAABBCCDDEEFF), "48-bit write");
	}

	// 7. - 64-bit read
	{
		uint64_t data = 0x8899AABBCCDDEEFF;
		ok(ENDIAN_MATCH(knot_wire_read_u64((uint8_t *)&data),
		   0xFFEEDDCCBBAA9988, 0x8899AABBCCDDEEFF), "64-bit read");
	}

	// 8. - 64-bit write
	{
		uint64_t data_in = 0x8899AABBCCDDEEFF;
		uint64_t data_out = 0x0;
		knot_wire_write_u64((uint8_t *)&data_out, data_in);
		ok(ENDIAN_MATCH(data_out,
		   0xFFEEDDCCBBAA9988, 0x8899AABBCCDDEEFF), "64-bit write");
	}

	return 0;
}
