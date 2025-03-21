/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <tap/basic.h>
#include <string.h>

#include "bignum.c"
#include "binary.h"

#define bin_init(array) { .data = array, .size = sizeof(array) }

#define test_size(value, usize, ssize, msg) \
	dnssec_binary_t __bin = bin_init(value); \
	is_int(usize, bignum_size_u(&__bin), "bignum_size_u, " msg); \
	is_int(ssize, bignum_size_s(&__bin), "bignum_size_s, " msg)

#define test_write(num, expect, msg) \
	uint8_t __buffer[sizeof(expect)]; \
	memset(__buffer, 0xaa, sizeof(__buffer)); \
	wire_ctx_t __ctx = wire_ctx_init(__buffer, sizeof(expect)); \
	dnssec_binary_t __num = bin_init(num); \
	dnssec_binary_t __exp = bin_init(expect); \
	bignum_write(&__ctx, sizeof(expect), &__num); \
	dnssec_binary_t __dst = bin_init(__buffer); \
	ok(dnssec_binary_cmp(&__dst, &__exp) == 0, "bignum_write, " msg)

int main(int argc, char *argv[])
{
	plan_lazy();

	{
	uint8_t num[] = { };
	test_size(num, 1, 1, "empty string");
	}

	{
	uint8_t num[] = { 0x00 };
	test_size(num, 1, 1, "zero");
	}

	{
	uint8_t num[] = { 0x00, 0x00, 0x00 };
	test_size(num, 1, 1, "long zero");
	}

	{
	uint8_t num[] = { 0x01, 0x02, 0x03 };
	test_size(num, 3, 3, "no MSB");
	}

	{
	uint8_t num[] = { 0x7f, 0xff, 0x00, 0x00, 0x00 };
	test_size(num, 5, 5, "no MSB but all other bits");
	}

	{
	uint8_t num[] = { 0x84, 0x42 };
	test_size(num, 2, 3, "MSB");
	}

	{
	uint8_t num[] = { 0x00, 0x84, 0x42 };
	test_size(num, 2, 3, "MSB and leading zero");
	}

	{
	uint8_t num[] = { 0x00, 0x00, 0x00, 0x00, 0xfc, 0xe1, 0xda };
	test_size(num, 3, 4, "MSB, many leading zeroes");
	}

	{
	uint8_t num[] = { 0x00, 0x00, 0x00, 0x01 };
	test_size(num, 1, 1, "no MSB, many leading zeroes");
	}

	// test writing

	{
	uint8_t num[] = { };
	uint8_t exp[] = { 0x00 };
	test_write(num, exp, "empty string");
	}

	{
	uint8_t num[] = { 0x00 };
	uint8_t exp[] = { 0x00 };
	test_write(num, exp, "zero");
	}

	{
	uint8_t num[] = { 0x11, 0x22, 0x33 };
	uint8_t exp[] = { 0x00, 0x00, 0x00, 0x11, 0x22, 0x33 };
	test_write(num, exp, "no MSB, right-aligned");
	}

	{
	uint8_t num[] = { 0xff, 0xee, 0xdd };
	uint8_t exp[] = { 0x00, 0x00, 0x00, 0xff, 0xee, 0xdd };
	test_write(num, exp, "MSB, right-aligned");
	}

	{
	uint8_t num[] = { 0x11, 0x22, 0x33 };
	uint8_t exp[] = { 0x11, 0x22, 0x33 };
	test_write(num, exp, "no MSB, fitting exactly");
	}

	{
	uint8_t num[] = { 0xff, 0xee, 0xdd };
	uint8_t exp[] = { 0xff, 0xee, 0xdd };
	test_write(num, exp, "MSB, fitting exactly");
	}

	return 0;
}
