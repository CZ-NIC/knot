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

#include <tap/basic.h>

#include "contrib/sockaddr.h"

static void test_sockaddr_is_any(void)
{
	struct sockaddr_storage invalid = { 0 };
	ok(!sockaddr_is_any(&invalid), "sockaddr_is_any: invalid");

	struct sockaddr_storage path = { 0 };
	path.ss_family = AF_UNIX;
	ok(!sockaddr_is_any(&path), "sockaddr_is_any: unix");

	struct sockaddr_storage ipv4_local = { 0 };
	sockaddr_set(&ipv4_local, AF_INET, "127.0.0.1", 0);
	ok(!sockaddr_is_any(&ipv4_local), "sockaddr_is_any: IPv4 local");

	struct sockaddr_storage ipv4_any = { 0 };
	sockaddr_set(&ipv4_any, AF_INET, "0.0.0.0", 0);
	ok(sockaddr_is_any(&ipv4_any), "sockaddr_is_any: IPv4 any");

	struct sockaddr_storage ipv6_local = { 0 };
	sockaddr_set(&ipv6_local, AF_INET6, "::1", 0);
	ok(!sockaddr_is_any(&ipv6_local), "sockaddr_is_any: IPv6 local");

	struct sockaddr_storage ipv6_any = { 0 };
	sockaddr_set(&ipv6_any, AF_INET6, "::", 0);
	ok(sockaddr_is_any(&ipv6_any), "sockaddr_is_any: IPv6 any");
}

int main(int argc, char *argv[])
{
	plan_lazy();

	test_sockaddr_is_any();

	return 0;
}
