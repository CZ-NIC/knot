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
#include <tap/basic.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>

#include "contrib/sockaddr.h"
#include "libknot/errcode.h"
#include "libknot/rrtype/opt.h"

#define GARBAGE_BYTE 0xdb

static void test_size(void)
{
	struct test {
		const char *msg;
		size_t expected;
		knot_edns_client_subnet_t ecs;
	};

	static struct test const TESTS[] = {
		// invalid
		{ "zero family",             0, { 0 } },
		{ "zero family & source",    0, { 0,  1 } },
		{ "unknown family",          0, { 42, 0 } },
		{ "unknown family & source", 0, { 42, 1 } },
		// IPv4 bit ops
		{ "IPv4, zero source",         4, { 1 } },
		{ "IPv4, 7 bits in last byte", 7, { 1, 23 } },
		{ "IPv4, 8 bits in last byte", 7, { 1, 24 } },
		{ "IPv4, 1 bit in last byte",  8, { 1, 25 } },
		// IPv6 bit ops
		{ "IPv6, zero source",         4,  { 2 } },
		{ "IPv6, 7 bits in last byte", 19, { 2, 113 } },
		{ "IPv6, 8 bits in last byte", 19, { 2, 120 } },
		{ "IPv6, 1 bit in last byte",  20, { 2, 121 } },
		// sources
		{ "IPv4, source < max", 8, { 1, 31 } },
		{ "IPv4, source = max", 8, { 1, 32 } },
		{ "IPv4, source > max", 0, { 1, 33 } },
		// scopes
		{ "IPv6, scope < source", 12, { 2, 64, 48 } },
		{ "IPv6, scope = source", 12, { 2, 64, 64 } },
		{ "IPv6, scope > source", 0,  { 2, 64, 65 } },
		{ NULL }
	};

	is_int(0, knot_edns_client_subnet_size(NULL), "%s: null", __func__);

	for (struct test const *t = TESTS; t->msg != NULL; t++) {
		int r = knot_edns_client_subnet_size(&t->ecs);
		is_int(t->expected, r, "%s: %s", __func__, t->msg);
	}
}

struct test_io {
	const char *msg;
	int expected;
	size_t option_len;
	const char *option;
	knot_edns_client_subnet_t ecs;
};

static void test_write(void)
{
	static struct test_io const TESTS[] = {
		// invalid
		{ "unset family",   KNOT_EINVAL, 0, NULL, { 0 } },
		{ "invalid family", KNOT_EINVAL, 0, NULL, { 3 } },
		{ "small buffer",   KNOT_ESPACE, 4, NULL, { 1, 1 } },
		// IPv4 prefix
		{ "IPv4, zero source",   KNOT_EOK,    4, "\x00\x01\x00\x00",                 { 1 } },
		{ "IPv4, 7 bits in LSB", KNOT_EOK,    6, "\x00\x01\x0f\x00\xff\xfe",         { 1, 15,  0, "\xff\xff\xff\xff" } },
		{ "IPv4, 8 bits in LSB", KNOT_EOK,    6, "\x00\x01\x10\x00\xff\xff",         { 1, 16,  0, "\xff\xff\xff\xff" } },
		{ "IPv4, 1 bit in LSB",  KNOT_EOK,    7, "\x00\x01\x11\x00\xff\xff\x80",     { 1, 17,  0, "\xff\xff\xff\xff" } },
		{ "IPv4, source = max",  KNOT_EOK,    8, "\x00\x01\x20\x00\xaa\xbb\xcc\xdd", { 1, 32,  0, "\xaa\xbb\xcc\xdd" } },
		{ "IPv4, source > max",  KNOT_EINVAL, 0, NULL,                               { 2, 129 } },
		// IPv6 scope
		{ "IPv6, scope < source", KNOT_EOK,    6, "\x00\x02\x10\x0e\xff\xff", { 2, 16, 14, "\xff\xff\xff\xff" } },
		{ "IPv6, scope = source", KNOT_EOK,    6, "\x00\x02\x08\x08\xff",     { 2, 8,  8,  "\xff\xff\xff\xff" } },
		{ "IPv6, scope > source", KNOT_EINVAL, 0, NULL,                       { 1, 8,  9 } },
		// other
		{ "larger buffer", KNOT_EOK, 7, "\x00\x01\x10\x0e\xff\xff\x00", { 1, 16, 14, "\xff\xff\xff\xff" } },
		{ NULL }
	};

	for (struct test_io const *t = TESTS; t->msg != NULL; t++) {
		uint8_t option[64];
		assert(sizeof(option) >= t->option_len);
		memset(option, GARBAGE_BYTE, sizeof(option));

		int r = knot_edns_client_subnet_write(option, t->option_len, &t->ecs);
		ok(r == t->expected &&
		   (t->expected != KNOT_EOK || memcmp(option, t->option, t->option_len) == 0),
		   "%s: %s", __func__, t->msg);
	}
}

static void test_parse(void)
{
	static struct test_io const TESTS[] = {
		// invalid
		{ "null",              KNOT_EINVAL, 0, NULL },
		{ "empty buffer",      KNOT_EMALF,  0, "" },
		{ "incomplete header", KNOT_EMALF,  3, "\x00\x01\x00" },
		{ "incomplete source", KNOT_EMALF,  5, "\x00\x0a\x00\x00\xff\xff" },
		{ "zero family",       KNOT_EMALF,  4, "\x00\x00\x00\x00" },
		{ "unknown family",    KNOT_EMALF,  4, "\x00\x03\x00\x00" },
		// IPv4 prefix
		{ "IPv4, zero source",   KNOT_EOK,   4, "\x00\x01\x00\x00",                 { 1 } },
		{ "IPv4, 7 bits in LSB", KNOT_EOK,   6, "\x00\x01\x0f\x00\xff\xfe",         { 1, 15, 0, "\xff\xfe" } },
		{ "IPv4, 9 bits in LSB", KNOT_EOK,   6, "\x00\x01\x10\x00\xff\xff",         { 1, 16, 0, "\xff\xff" } },
		{ "IPv4, 1 bit in LSB",  KNOT_EOK,   7, "\x00\x01\x11\x00\xff\xff\x80",     { 1, 17, 0, "\xff\xff\x80" } },
		{ "IPv4, source = max",  KNOT_EOK,   8, "\x00\x01\x20\x00\xaa\xbb\xcc\xdd", { 1, 32, 0, "\xaa\xbb\xcc\xdd" } },
		{ "IPv4, dirty source",  KNOT_EOK,   8, "\x00\x01\x0b\x00\xff\xff\xff\xff", { 1, 11, 0, "\xff\xe0" } },
		{ "IPv4, source > max",  KNOT_EMALF, 9, "\x00\x01\x21\x00\xaa\xbb\xcc\xdd\xee" },
		// IPv6 scope
		{ "IPv6 scope < source", KNOT_EOK,   5, "\x00\x02\x07\x05\xff", { 2, 7, 5, "\xfe" } },
		{ "IPv6 scope = source", KNOT_EOK,   5, "\x00\x02\x06\x06\xff", { 2, 6, 6, "\xfc" } },
		{ "IPv6 scope > source", KNOT_EMALF, 5, "\x00\x02\x06\x07\xff" },
		// extra buffer size
		{ "extra space", KNOT_EOK, 6, "\x00\x01\x00\x00\xff\x00", { 1 } },
		{ "extra space", KNOT_EOK, 6, "\x00\x01\x01\x00\xff\x00", { 1, 1, 0, "\x80" } },
		{ NULL }
	};

	for (struct test_io const *t = TESTS; t->msg != NULL; t++) {
		knot_edns_client_subnet_t ecs = { 0 };
		memset(&ecs, GARBAGE_BYTE, sizeof(ecs));

		int r = knot_edns_client_subnet_parse(&ecs, (uint8_t *)t->option, t->option_len);
		ok(r == t->expected &&
		   (t->expected != KNOT_EOK || memcmp(&ecs, &t->ecs, sizeof(ecs)) == 0),
		   "%s: %s", __func__, t->msg);
	}
}

static struct sockaddr_storage addr_init(const char *addr)
{
	struct sockaddr_storage sa = { 0 };

	struct addrinfo hints = { .ai_flags = AI_NUMERICHOST };
	struct addrinfo *info = NULL;
	int r = getaddrinfo(addr, NULL, &hints, &info);
	(void)r;
	assert(r == 0);
	memcpy(&sa, info->ai_addr, info->ai_addrlen);
	freeaddrinfo(info);

	return sa;
}

static void test_set_address(void)
{
	int r;
	knot_edns_client_subnet_t ecs = { 0 };
	struct sockaddr_storage ss = { 0 };

	r = knot_edns_client_subnet_set_addr(NULL, &ss);
	is_int(KNOT_EINVAL, r, "%s: missing ECS", __func__);

	r = knot_edns_client_subnet_set_addr(&ecs, NULL);
	is_int(KNOT_EINVAL, r, "%s: missing address", __func__);

	memset(&ecs, GARBAGE_BYTE, sizeof(ecs));
	ss = addr_init("198.51.100.42");
	assert(ss.ss_family == AF_INET);
	const uint8_t raw4[4] = { 198, 51, 100, 42 };

	r = knot_edns_client_subnet_set_addr(&ecs, &ss);
	ok(r == KNOT_EOK &&
	   ecs.family == 1 && ecs.source_len == 32 && ecs.scope_len == 0 &&
	   memcmp(ecs.address, raw4, sizeof(raw4)) == 0,
	   "%s: IPv4", __func__);

	memset(&ecs, GARBAGE_BYTE, sizeof(ecs));
	ss = addr_init("2001:db8::dead:beef");
	assert(ss.ss_family == AF_INET6);
	const uint8_t raw6[16] = "\x20\x01\x0d\xb8\x00\x00\x00\x00"
	                         "\x00\x00\x00\x00\xde\xad\xbe\xef";
	r = knot_edns_client_subnet_set_addr(&ecs, &ss);
	ok(r == KNOT_EOK &&
	   ecs.family == 2 && ecs.source_len == 128 && ecs.scope_len == 0 &&
	   memcmp(ecs.address, raw6, sizeof(raw6)) == 0,
	   "%s: IPv6", __func__);

	const struct sockaddr_storage ss_unix = { .ss_family = AF_UNIX };
	r = knot_edns_client_subnet_set_addr(&ecs, &ss_unix);
	is_int(KNOT_ENOTSUP, r, "%s: UNIX not supported", __func__);
}

static bool sockaddr_eq(const struct sockaddr_storage *a, const struct sockaddr_storage *b)
{
	return sockaddr_cmp((struct sockaddr *)a, (struct sockaddr *)b) == 0;
}

static void test_get_address(void)
{
	struct test {
		const char *msg;
		int expected;
		const char *addr_str;
		knot_edns_client_subnet_t ecs;
	};

	static struct test const TESTS[] = {
		// invalid
		{ "unset family",   KNOT_ENOTSUP, NULL, { 0 } },
		{ "unknown family", KNOT_ENOTSUP, NULL, { 3 } },
		// zero source
		{ "IPv4, any", KNOT_EOK, "0.0.0.0", { 1 } },
		{ "IPv6, any", KNOT_EOK, "::0"    , { 2 } },
		// IPv4
		{ "IPv4, 7 bits in LSB", KNOT_EOK, "198.50.0.0",   { 1, 15, 0, "\xc6\x33\xff\xff" } },
		{ "IPv4, 8 bits in LSB", KNOT_EOK, "198.51.0.0",   { 1, 16, 0, "\xc6\x33\xff\xff" } },
		{ "IPv4, 1 bit in LSB",  KNOT_EOK, "198.51.128.0", { 1, 17, 0, "\xc6\x33\xff\xff" } },
		{ "IPv4, source = max",  KNOT_EOK, "198.51.128.1", { 1, 32, 0, "\xc6\x33\x80\x01" } },
		// IPv6
		{ "IPv6, 7 bits in LSB", KNOT_EOK, "2001:db8:200::", { 2, 39,  0, "\x20\x01\x0d\xb8\x03\xff" } },
		{ "IPv6, 8 bits in LSB", KNOT_EOK, "2001:db8:100::", { 2, 40,  0, "\x20\x01\x0d\xb8\x01\xff" } },
		{ "IPv6, 1 bit in LSB",  KNOT_EOK, "2001:db8:180::", { 2, 41,  0, "\x20\x01\x0d\xb8\x01\xff" } },
		{ "IPv6, source = max",  KNOT_EOK, "2001:db8::1",    { 2, 128, 0, "\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01" } },
		{ NULL }
	};

	for (struct test const *t = TESTS; t->msg != NULL; t++) {
		struct sockaddr_storage result = { 0 };
		int r = knot_edns_client_subnet_get_addr(&result, &t->ecs);
		bool valid = false;

		if (t->expected == KNOT_EOK) {
			struct sockaddr_storage addr = addr_init(t->addr_str);
			assert(addr.ss_family != AF_UNSPEC);
			valid = (r == t->expected && sockaddr_eq(&result, &addr));
		} else {
			valid = (r == t->expected);
		}

		ok(valid, "%s: %s", __func__, t->msg);
	}
}

int main(int argc, char *argv[])
{
	plan_lazy();

	test_size();
	test_write();
	test_parse();
	test_set_address();
	test_get_address();

	return 0;
}
