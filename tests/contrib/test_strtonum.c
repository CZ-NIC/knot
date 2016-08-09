/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <stdio.h>
#include <stdlib.h>
#include <tap/basic.h>

#include "contrib/strtonum.h"
#include "dnssec/error.h"

static void test_u8(const char *in, uint8_t expected, int errcode)
{
	uint8_t out = 0x11;
	assert(expected != out);

	ok(str_to_u8(in, &out) == errcode &&
	   (errcode != KNOT_EOK || out == expected),
	   "str_to_u8 %s on \"%s\"",
	   (errcode == KNOT_EOK ? "succeeds" : "fails"), in);
}

static void test_u16(const char *in, uint16_t expected, int errcode)
{
	uint16_t out = 0x0101;
	assert(expected != out);

	ok(str_to_u16(in, &out) == errcode &&
	   (errcode != KNOT_EOK || out == expected),
	   "str_to_u16 %s on \"%s\"",
	   (errcode == KNOT_EOK ? "succeeds" : "fails"), in);
}

static void test_u32(const char *in, uint32_t expected, int errcode)
{
	uint32_t out = 0x010101;
	assert(expected != out);

	ok(str_to_u32(in, &out) == errcode &&
	   (errcode != KNOT_EOK || out == expected),
	   "str_to_u32 %s on \"%s\"",
	   (errcode == KNOT_EOK ? "succeeds" : "fails"), in);
}

static void test_int(const char *in, int expected, int errcode)
{
	int out = 12345;
	assert(expected != out);

	ok(str_to_int(in, &out) == errcode &&
	   (errcode != KNOT_EOK || out == expected),
	   "str_to_int %s on \"%s\"",
	   (errcode == KNOT_EOK ? "succeeds" : "fails"), in);
}

// mute warn_unused_result
#define asprintf(args, ...) do { \
	int r = (asprintf)(args, ##__VA_ARGS__); assert(r >= 0); (void)r; \
} while (0);

int main(int argc, char *argv[])
{
	plan_lazy();

	test_u8("-1",          0,          KNOT_EINVAL);
	test_u8("256",         0,          KNOT_ERANGE);
	test_u8("0x1",         0,          KNOT_EINVAL);
	test_u8(" 1",          0,          KNOT_EINVAL);
	test_u8("1 ",          0,          KNOT_EINVAL);
	test_u8("0",           0,          KNOT_EOK);
	test_u8("42",          42,         KNOT_EOK);
	test_u8("+84",         84,         KNOT_EOK);
	test_u8("255",         UINT8_MAX,  KNOT_EOK);

	test_u16("-1",         0,          KNOT_EINVAL);
	test_u16("65536",      0,          KNOT_ERANGE);
	test_u16("0x1",        0,          KNOT_EINVAL);
	test_u16(" 1",         0,          KNOT_EINVAL);
	test_u16("1 ",         0,          KNOT_EINVAL);
	test_u16("0",          0,          KNOT_EOK);
	test_u16("65280",      65280,      KNOT_EOK);
	test_u16("+256",       256,        KNOT_EOK);
	test_u16("65535",      UINT16_MAX, KNOT_EOK);

	test_u32("-1",         0,          KNOT_EINVAL);
	test_u32("4294967296", 0,          KNOT_ERANGE);
	test_u32("0x1",        0,          KNOT_EINVAL);
	test_u32(" 1",         0,          KNOT_EINVAL);
	test_u32("1 ",         0,          KNOT_EINVAL);
	test_u32("0",          0,          KNOT_EOK);
	test_u32("65280",      65280,      KNOT_EOK);
	test_u32("+256",       256,        KNOT_EOK);
	test_u32("4294967295", UINT32_MAX, KNOT_EOK);

	char *int_under = NULL;
	asprintf(&int_under, "%lld", (long long)INT_MIN - 1);
	char *int_min = NULL;
	asprintf(&int_min,   "%lld", (long long)INT_MIN);
	char *int_max = NULL;
	asprintf(&int_max,   "%lld", (long long)INT_MAX);
	char *int_over = NULL;
	asprintf(&int_over,  "%lld", (long long)INT_MAX + 1);

	test_int(int_under,      0,           KNOT_ERANGE);
	test_int(int_over,       0,           KNOT_ERANGE);
	test_int("0x1",          0,           KNOT_EINVAL);
	test_int(" 1",           0,           KNOT_EINVAL);
	test_int("1 ",           0,           KNOT_EINVAL);
	test_int(int_min,        INT_MIN,     KNOT_EOK);
	test_int("0",            0,           KNOT_EOK);
	test_int("268435459",    268435459,   KNOT_EOK);
	test_int("+1073741827",  1073741827,  KNOT_EOK);
	test_int(int_max,        INT_MAX,     KNOT_EOK);

	free(int_under);
	free(int_min);
	free(int_max);
	free(int_over);

	return 0;
}
