/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <netinet/in.h>
#include <stdio.h>

#include "libknot/internal/errcode.h"
#include "contrib/wire_ctx.h"

#define OK(wire) { \
	is_int(KNOT_EOK, (wire)->error, "check for no error"); \
}

#define NOK(wire, code) { \
	is_int(code, (wire)->error, "check for error"); \
}

void ok_offset(wire_ctx_t *wire, size_t max, size_t i)
{
	wire_ctx_set_offset(wire, i);
	OK(wire);
	is_int(max - i, wire_ctx_available(wire), "get available %zu", max - i);
	OK(wire);
	is_int(i, wire_ctx_offset(wire), "get start position %zu", i);
	OK(wire);
}

void nok_offset(wire_ctx_t *wire, size_t max)
{
	wire_ctx_set_offset(wire, max);
	OK(wire);
	wire_ctx_set_offset(wire, max + 1);
	NOK(wire, KNOT_ERANGE);
	is_int(0, wire_ctx_available(wire), "get available %i", 0);
	NOK(wire, KNOT_ERANGE);
	is_int(max, wire_ctx_offset(wire), "get last start position %zu", max);
	NOK(wire, KNOT_ERANGE);
}

void offset_test(void)
{
	diag("offset operation");

	const size_t LEN = 3;
	uint8_t data[LEN];

	wire_ctx_t wire = wire_ctx_init(data, sizeof(data));

	// First free byte.
	ok_offset(&wire, LEN, 0);
	// Last free byte.
	ok_offset(&wire, LEN, 2);
	// First non-free byte.
	ok_offset(&wire, LEN, 3);
	// Invalid offset.
	nok_offset(&wire, LEN);
}

void skip_test(void)
{
	diag("skip operation");

	uint8_t data[3];

	// Forward skips.

	wire_ctx_t wire = wire_ctx_init(data, sizeof(data));

	wire_ctx_skip(&wire, 2);
	OK(&wire);
	is_int(2, wire_ctx_offset(&wire), "skip by offset %i", 2);

	wire_ctx_skip(&wire, 1);
	OK(&wire);
	is_int(3, wire_ctx_offset(&wire), "skip by offset %i", 1);

	// Out-of-bounds skip.
	wire_ctx_skip(&wire, 1);
	NOK(&wire, KNOT_ERANGE);
	is_int(3, wire_ctx_offset(&wire), "out-of-bounds skip by %i", 1);

	// Backward skips.

	wire = wire_ctx_init(data, sizeof(data));

	wire_ctx_set_offset(&wire, 3);
	OK(&wire);

	wire_ctx_skip(&wire, -2);
	OK(&wire);
	is_int(1, wire_ctx_offset(&wire), "skip by offset %i", -2);

	wire_ctx_skip(&wire, -1);
	OK(&wire);
	is_int(0, wire_ctx_offset(&wire), "skip by offset %i", -1);

	// Out-of-bounds skip.
	wire_ctx_skip(&wire, -1);
	NOK(&wire, KNOT_ERANGE);
	is_int(0, wire_ctx_offset(&wire), "out-of-bounds skip by %i", -1);
}

void clear_test(void)
{
	diag("clear operation");

	uint8_t data[] = { 1, 2, 3 };

	wire_ctx_t wire = wire_ctx_init(data, sizeof(data));

	wire_ctx_clear(&wire);
	OK(&wire);
	is_int(0, wire_ctx_offset(&wire), "no position change after clear");
	for (int i = 0; i < sizeof(data); i++) {
		is_int(0, data[i], "wire position %i is zero", i);
	}

	data[0] = 1;
	wire_ctx_set_offset(&wire, 4);
	NOK(&wire, KNOT_ERANGE);
	wire_ctx_clear(&wire);
	NOK(&wire, KNOT_ERANGE);
	is_int(1, data[0], "no data change after clear after error");
}

#define check_rw(size, value, ...) { \
	const uint8_t expect[] = { __VA_ARGS__ }; \
	uint8_t data[sizeof(expect)] = { 0 }; \
	\
	wire_ctx_t wire = wire_ctx_init(data, sizeof(data)); \
	\
	wire_ctx_write_u ## size(&wire, value); \
	OK(&wire); \
	ok(memcmp(data, expect, sizeof(expect)) == 0, "write %i value", size); \
	is_int(size/8, wire_ctx_offset(&wire), "write %i offset", size); \
	\
	wire_ctx_set_offset(&wire, 0); \
	OK(&wire); \
	\
	uint64_t num = wire_ctx_read_u ## size(&wire); \
	OK(&wire); \
	is_int(value, num, "read %i value", size); \
	is_int(size/8, wire_ctx_offset(&wire), "read %i offset", size); \
}

#define check_general_rw(...) { \
	const uint8_t expect[] = { __VA_ARGS__ }; \
	uint8_t data[sizeof(expect)] = { 0 }; \
	\
	wire_ctx_t wire = wire_ctx_init(data, sizeof(data)); \
	\
	wire_ctx_write(&wire, expect, sizeof(expect)); \
	OK(&wire); \
	ok(memcmp(data, expect, sizeof(expect)) == 0, "write value"); \
	is_int(sizeof(expect), wire_ctx_offset(&wire), "write offset"); \
	\
	wire_ctx_set_offset(&wire, 0); \
	OK(&wire); \
	\
	uint8_t d[sizeof(expect)] = { 0 }; \
	wire_ctx_read(&wire, d, sizeof(expect)); \
	OK(&wire); \
	ok(memcmp(d, expect, sizeof(expect)) == 0, "read value"); \
	is_int(sizeof(expect), wire_ctx_offset(&wire), "read offset"); \
}

void read_write_test(void)
{
	diag("read and write operation");

	check_rw( 8, 0x11,               0x11);
	check_rw(16, 0x1122,             0x11, 0x22);
	check_rw(32, 0x11223344,         0x11, 0x22, 0x33, 0x44);
	check_rw(48, 0x112233445566,     0x11, 0x22, 0x33, 0x44, 0x55, 0x66);
	check_rw(64, 0x1122334455667788, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88);

	check_general_rw(0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x10);
}

#define check_rw_over(size) { \
	uint8_t data[1] = { 0 }; \
	\
	wire_ctx_t wire = wire_ctx_init(data, sizeof(data)); \
	wire_ctx_set_offset(&wire, 1); \
	OK(&wire); \
	\
	wire_ctx_write_u ## size(&wire, 0); \
	NOK(&wire, KNOT_ESPACE); \
	is_int(1, wire_ctx_offset(&wire), "err write %i offset", size); \
	\
	wire = wire_ctx_init(data, sizeof(data)); \
	wire_ctx_set_offset(&wire, 1); \
	OK(&wire); \
	\
	uint64_t num = wire_ctx_read_u ## size(&wire); \
	NOK(&wire, KNOT_EFEWDATA); \
	is_int(0, num, "err read %i value", size); \
	is_int(1, wire_ctx_offset(&wire), "err read %i offset", size); \
}

#define check_general_rw_over(void) { \
	uint8_t data[1] = { 0 }; \
	uint8_t d[2] = { 0 }; \
	\
	wire_ctx_t wire = wire_ctx_init(data, sizeof(data)); \
	wire_ctx_write(&wire, d, sizeof(d)); \
	NOK(&wire, KNOT_ESPACE); \
	is_int(0, wire_ctx_offset(&wire), "err write offset"); \
	\
	wire = wire_ctx_init(data, sizeof(data)); \
	wire_ctx_read(&wire, d, sizeof(d)); \
	NOK(&wire, KNOT_EFEWDATA); \
	is_int(0, wire_ctx_offset(&wire), "err read offset"); \
}

void read_write_overflow_test(void)
{
	diag("overflow read and write operation");

	check_rw_over(8);
	check_rw_over(16);
	check_rw_over(32);
	check_rw_over(48);
	check_rw_over(64);

	check_general_rw_over();
}

#define check_ro(size) { \
	uint8_t data[8] = { 0 }; \
	\
	wire_ctx_t wire = wire_ctx_init_const(data, sizeof(data)); \
	\
	wire_ctx_write_u ## size(&wire, 0); \
	NOK(&wire, KNOT_EACCES); \
	is_int(0, wire_ctx_offset(&wire), "err write %i offset", size); \
}

#define check_general_ro(void) { \
	uint8_t data[8] = { 0 }; \
	uint8_t d[2] = { 0 }; \
	\
	wire_ctx_t wire = wire_ctx_init_const(data, sizeof(data)); \
	\
	wire_ctx_write(&wire, d, sizeof(d)); \
	NOK(&wire, KNOT_EACCES); \
	is_int(0, wire_ctx_offset(&wire), "err write offset"); \
}

void write_readonly_test(void)
{
	diag("readonly write operation");

	check_ro(8);
	check_ro(16);
	check_ro(32);
	check_ro(48);
	check_ro(64);

	check_general_ro();
}

int main(void)
{
	plan_lazy();

	offset_test();
	skip_test();
	clear_test();
	read_write_test();
	read_write_overflow_test();
	write_readonly_test();

	return 0;
}
