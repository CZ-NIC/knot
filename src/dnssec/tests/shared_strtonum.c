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

#include <assert.h>
#include <stdio.h>
#include <tap/basic.h>
#include <assert.h>
#include <inttypes.h>

#include "dnssec/error.h"
#include "strtonum.h"

static void test_u8(const char *in, uint8_t expected, int errcode)
{
	uint8_t out = 0x11;
	assert(expected != out);

	ok(str_to_u8(in, &out) == errcode &&
	   (errcode != DNSSEC_EOK || out == expected),
	   "str_to_u8 %s on \"%s\"",
	   (errcode == DNSSEC_EOK ? "succeeds" : "fails"), in);
}

static void test_u16(const char *in, uint16_t expected, int errcode)
{
	uint16_t out = 0x0101;
	assert(expected != out);

	ok(str_to_u16(in, &out) == errcode &&
	   (errcode != DNSSEC_EOK || out == expected),
	   "str_to_u16 %s on \"%s\"",
	   (errcode == DNSSEC_EOK ? "succeeds" : "fails"), in);
}

static void test_int(const char *in, int expected, int errcode)
{
	int out = 12345;
	assert(expected != out);

	ok(str_to_int(in, &out) == errcode &&
	   (errcode != DNSSEC_EOK || out == expected),
	   "str_to_int %s on \"%s\"",
	   (errcode == DNSSEC_EOK ? "succeeds" : "fails"), in);
}

// mute warn_unused_result
#define asprintf(args, ...) do { \
	int r = (asprintf)(args, ##__VA_ARGS__); assert(r >= 0); \
} while (0);

int main(int argc, char *argv[])
{
	plan_lazy();

	test_u8("-1",      0,      DNSSEC_OUT_OF_RANGE);
	test_u8("256",     0,      DNSSEC_OUT_OF_RANGE);
	test_u8("0x1",     0,      DNSSEC_MALFORMED_DATA);
	test_u8(" 1",      0,      DNSSEC_MALFORMED_DATA);
	test_u8("1 ",      0,      DNSSEC_MALFORMED_DATA);
	test_u8("0",       0,      DNSSEC_EOK);
	test_u8("42",      42,     DNSSEC_EOK);
	test_u8("+84",     84,     DNSSEC_EOK);
	test_u8("255",     0xff,   DNSSEC_EOK);

	test_u16("-1",     0,      DNSSEC_OUT_OF_RANGE);
	test_u16("65536",  0,      DNSSEC_OUT_OF_RANGE);
	test_u16("0x1",    0,      DNSSEC_MALFORMED_DATA);
	test_u16(" 1",     0,      DNSSEC_MALFORMED_DATA);
	test_u16("1 ",     0,      DNSSEC_MALFORMED_DATA);
	test_u16("0",      0,      DNSSEC_EOK);
	test_u16("65280",  65280,  DNSSEC_EOK);
	test_u16("+256",   256,    DNSSEC_EOK);
	test_u16("65535",  65535,  DNSSEC_EOK);

	char *int_under = NULL;
	asprintf(&int_under, "%lld", (long long)INT_MIN - 1);
	char *int_min = NULL;
	asprintf(&int_min,   "%lld", (long long)INT_MIN);
	char *int_max = NULL;
	asprintf(&int_max,   "%lld", (long long)INT_MAX);
	char *int_over = NULL;
	asprintf(&int_over,  "%lld", (long long)INT_MAX + 1);

	test_int(int_under,      0,           DNSSEC_OUT_OF_RANGE);
	test_int(int_over,       0,           DNSSEC_OUT_OF_RANGE);
	test_int("0x1",          0,           DNSSEC_MALFORMED_DATA);
	test_int(" 1",           0,           DNSSEC_MALFORMED_DATA);
	test_int("1 ",           0,           DNSSEC_MALFORMED_DATA);
	test_int(int_min,        INT_MIN,     DNSSEC_EOK);
	test_int("0",            0,           DNSSEC_EOK);
	test_int("268435459",    268435459,   DNSSEC_EOK);
	test_int("+1073741827",  1073741827,  DNSSEC_EOK);
	test_int(int_max,        INT_MAX,     DNSSEC_EOK);

	free(int_under);
	free(int_min);
	free(int_max);
	free(int_over);

	return 0;
}
