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
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <tap/basic.h>

#include "contrib/sockaddr.h"
#include "libknot/errcode.h"

struct sockaddr *SA(struct sockaddr_storage *ss)
{
	return (struct sockaddr *)ss;
}

static void test_sockaddr_is_any(void)
{
	struct sockaddr_storage invalid = { 0 };
	ok(!sockaddr_is_any(SA(&invalid)), "sockaddr_is_any: invalid");

	struct sockaddr_storage path = { 0 };
	path.ss_family = AF_UNIX;
	ok(!sockaddr_is_any(SA(&path)), "sockaddr_is_any: unix");

	struct sockaddr_storage ipv4_local = { 0 };
	sockaddr_set(&ipv4_local, AF_INET, "127.0.0.1", 0);
	ok(!sockaddr_is_any(SA(&ipv4_local)), "sockaddr_is_any: IPv4 local");

	struct sockaddr_storage ipv4_any = { 0 };
	sockaddr_set(&ipv4_any, AF_INET, "0.0.0.0", 0);
	ok(sockaddr_is_any(SA(&ipv4_any)), "sockaddr_is_any: IPv4 any");

	struct sockaddr_storage ipv6_local = { 0 };
	sockaddr_set(&ipv6_local, AF_INET6, "::1", 0);
	ok(!sockaddr_is_any(SA(&ipv6_local)), "sockaddr_is_any: IPv6 local");

	struct sockaddr_storage ipv6_any = { 0 };
	sockaddr_set(&ipv6_any, AF_INET6, "::", 0);
	ok(sockaddr_is_any(SA(&ipv6_any)), "sockaddr_is_any: IPv6 any");
}

static void check_sockaddr_set(struct sockaddr_storage *ss, int family,
                               const char *straddr, int port)
{
	int ret = sockaddr_set(ss, family, straddr, port);
	is_int(KNOT_EOK, ret, "set address '%s'", straddr);
}

static void test_net_match(void)
{
	int ret;
	struct sockaddr_storage t = { 0 };

	// 127 dec ~ 01111111 bin
	// 170 dec ~ 10101010 bin
	struct sockaddr_storage ref4 = { 0 };
	check_sockaddr_set(&ref4, AF_INET, "127.170.170.127", 0);

	// 7F hex ~ 01111111 bin
	// AA hex ~ 10101010 bin
	struct sockaddr_storage ref6 = { 0 };
	check_sockaddr_set(&ref6, AF_INET6, "7FAA::AA7F", 0);

	ret = sockaddr_net_match(SA(&ref4), SA(&ref6), 32);
	ok(ret == false, "match: family mismatch");

	ret = sockaddr_net_match(NULL, SA(&ref4), 32);
	ok(ret == false, "match: NULL first parameter");
	ret = sockaddr_net_match(SA(&ref4), NULL, 32);
	ok(ret == false, "match: NULL second parameter");

	ret = sockaddr_net_match(SA(&ref4), SA(&ref4), -1);
	ok(ret == true, "match: ipv4 - identity, auto full prefix");
	ret = sockaddr_net_match(SA(&ref4), SA(&ref4), 31);
	ok(ret == true, "match: ipv4 - identity, subnet");
	ret = sockaddr_net_match(SA(&ref4), SA(&ref4), 32);
	ok(ret == true, "match: ipv4 - identity, full prefix");
	ret = sockaddr_net_match(SA(&ref4), SA(&ref4), 33);
	ok(ret == true, "match: ipv4 - identity, prefix overflow");

	ret = sockaddr_net_match(SA(&ref6), SA(&ref6), -1);
	ok(ret == true, "match: ipv6 - identity, auto full prefix");
	ret = sockaddr_net_match(SA(&ref6), SA(&ref6), 127);
	ok(ret == true, "match: ipv6 - identity, subnet");
	ret = sockaddr_net_match(SA(&ref6), SA(&ref6), 128);
	ok(ret == true, "match: ipv6 - identity, full prefix");
	ret = sockaddr_net_match(SA(&ref6), SA(&ref6), 129);
	ok(ret == true, "match: ipv6 - identity, prefix overflow");

	// 124 dec ~ 01111100 bin
	check_sockaddr_set(&t, AF_INET, "124.0.0.0", 0);
	ret = sockaddr_net_match(SA(&t), SA(&ref4), 5);
	ok(ret == true, "match: ipv4 - first byte, shorter prefix");
	ret = sockaddr_net_match(SA(&t), SA(&ref4), 6);
	ok(ret == true, "match: ipv4 - first byte, precise prefix");
	ret = sockaddr_net_match(SA(&t), SA(&ref4), 7);
	ok(ret == false, "match: ipv4 - first byte, not match");

	check_sockaddr_set(&t, AF_INET, "127.170.170.124", 0);
	ret = sockaddr_net_match(SA(&t), SA(&ref4), 29);
	ok(ret == true, "match: ipv4 - last byte, shorter prefix");
	ret = sockaddr_net_match(SA(&t), SA(&ref4), 30);
	ok(ret == true, "match: ipv4 - last byte, precise prefix");
	ret = sockaddr_net_match(SA(&t), SA(&ref4), 31);
	ok(ret == false, "match: ipv4 - last byte, not match");

	// 7C hex ~ 01111100 bin
	check_sockaddr_set(&t, AF_INET6, "7CAA::", 0);
	ret = sockaddr_net_match(SA(&t), SA(&ref6), 5);
	ok(ret == true, "match: ipv6 - first byte, shorter prefix");
	ret = sockaddr_net_match(SA(&t), SA(&ref6), 6);
	ok(ret == true, "match: ipv6 - first byte, precise prefix");
	ret = sockaddr_net_match(SA(&t), SA(&ref6), 7);
	ok(ret == false, "match: ipv6 - first byte, not match");

	check_sockaddr_set(&t, AF_INET6, "7FAA::AA7C", 0);
	ret = sockaddr_net_match(SA(&t), SA(&ref6), 125);
	ok(ret == true, "match: ipv6 - last byte, shorter prefix");
	ret = sockaddr_net_match(SA(&t), SA(&ref6), 126);
	ok(ret == true, "match: ipv6 - last byte, precise prefix");
	ret = sockaddr_net_match(SA(&t), SA(&ref6), 127);
	ok(ret == false, "match: ipv6 - last byte, not match");
}

static void test_range_match(void)
{
	bool ret;
	struct sockaddr_storage t = { 0 };
	struct sockaddr_storage min = { 0 };
	struct sockaddr_storage max = { 0 };

	// IPv4 tests.

	check_sockaddr_set(&min, AF_INET, "0.0.0.0", 0);
	check_sockaddr_set(&max, AF_INET, "255.255.255.255", 0);

	check_sockaddr_set(&t, AF_INET, "0.0.0.0", 0);
	ret = sockaddr_range_match(SA(&t), SA(&min), SA(&max));
	ok(ret == true, "match: ipv4 max range - minimum");
	check_sockaddr_set(&t, AF_INET, "255.255.255.255", 0);
	ret = sockaddr_range_match(SA(&t), SA(&min), SA(&max));
	ok(ret == true, "match: ipv4 max range - maximum");

	check_sockaddr_set(&min, AF_INET, "1.13.113.213", 0);
	check_sockaddr_set(&max, AF_INET, "2.24.124.224", 0);

	check_sockaddr_set(&t, AF_INET, "1.12.113.213", 0);
	ret = sockaddr_range_match(SA(&t), SA(&min), SA(&max));
	ok(ret == false, "match: ipv4 middle range - negative far min");
	check_sockaddr_set(&t, AF_INET, "1.13.113.212", 0);
	ret = sockaddr_range_match(SA(&t), SA(&min), SA(&max));
	ok(ret == false, "match: ipv4 middle range - negative close min");
	check_sockaddr_set(&t, AF_INET, "1.13.113.213", 0);
	ret = sockaddr_range_match(SA(&t), SA(&min), SA(&max));
	ok(ret == true, "match: ipv4 middle range - minimum");
	check_sockaddr_set(&t, AF_INET, "1.13.213.213", 0);
	ret = sockaddr_range_match(SA(&t), SA(&min), SA(&max));
	ok(ret == true, "match: ipv4 middle range - middle");
	check_sockaddr_set(&t, AF_INET, "2.24.124.224", 0);
	ret = sockaddr_range_match(SA(&t), SA(&min), SA(&max));
	ok(ret == true, "match: ipv4 middle range - max");
	check_sockaddr_set(&t, AF_INET, "2.24.124.225", 0);
	ret = sockaddr_range_match(SA(&t), SA(&min), SA(&max));
	ok(ret == false, "match: ipv4 middle range - negative close max");
	check_sockaddr_set(&t, AF_INET, "2.25.124.225", 0);
	ret = sockaddr_range_match(SA(&t), SA(&min), SA(&max));
	ok(ret == false, "match: ipv4 middle range - negative far max");

	// IPv6 tests.

	check_sockaddr_set(&min, AF_INET6, "::0", 0);
	check_sockaddr_set(&max, AF_INET6,
	                   "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF", 0);

	check_sockaddr_set(&t, AF_INET6, "::0", 0);
	ret = sockaddr_range_match(SA(&t), SA(&min), SA(&max));
	ok(ret == true, "match: ipv6 max range - minimum");
	check_sockaddr_set(&t, AF_INET6,
	                   "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF", 0);
	ret = sockaddr_range_match(SA(&t), SA(&min), SA(&max));
	ok(ret == true, "match: ipv6 max range - maximum");

	check_sockaddr_set(&min, AF_INET6, "1:13::ABCD:200B", 0);
	check_sockaddr_set(&max, AF_INET6, "2:A24::124:224", 0);

	check_sockaddr_set(&t, AF_INET6, "1:12::BCD:2000", 0);
	ret = sockaddr_range_match(SA(&t), SA(&min), SA(&max));
	ok(ret == false, "match: ipv6 middle range - negative far min");
	check_sockaddr_set(&t, AF_INET6, "1:13::ABCD:200A", 0);
	ret = sockaddr_range_match(SA(&t), SA(&min), SA(&max));
	ok(ret == false, "match: ipv6 middle range - negative close min");
	check_sockaddr_set(&t, AF_INET6, "1:13::ABCD:200B", 0);
	ret = sockaddr_range_match(SA(&t), SA(&min), SA(&max));
	ok(ret == true, "match: ipv6 middle range - minimum");
	check_sockaddr_set(&t, AF_INET6, "1:13:0:12:34:0:ABCD:200B", 0);
	ret = sockaddr_range_match(SA(&t), SA(&min), SA(&max));
	ok(ret == true, "match: ipv6 middle range - middle");
	check_sockaddr_set(&t, AF_INET6, "2:A24::124:224", 0);
	ret = sockaddr_range_match(SA(&t), SA(&min), SA(&max));
	ok(ret == true, "match: ipv6 middle range - max");
	check_sockaddr_set(&t, AF_INET6, "2:A24::124:225", 0);
	ret = sockaddr_range_match(SA(&t), SA(&min), SA(&max));
	ok(ret == false, "match: ipv6 middle range - negative close max");
	check_sockaddr_set(&t, AF_INET6, "2:FA24::4:24", 0);
	ret = sockaddr_range_match(SA(&t), SA(&min), SA(&max));
	ok(ret == false, "match: ipv6 middle range - negative far max");
}

int main(int argc, char *argv[])
{
	plan_lazy();

	diag("sockaddr_is_any");
	test_sockaddr_is_any();

	diag("sockaddr_net_match");
	test_net_match();

	diag("sockaddr_range_match");
	test_range_match();

	return 0;
}
