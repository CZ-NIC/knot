/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <tap/basic.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>

#include "contrib/musl/inet_ntop.h"

uint8_t bin[sizeof(struct in6_addr)];
const socklen_t len = INET6_ADDRSTRLEN;
char buf[INET6_ADDRSTRLEN];
const char *txt;

#define CHECK4(addr) \
	ok(inet_pton(AF_INET, addr, bin) == 1, "inet_pton(%s)", addr); \
	ok((txt = knot_inet_ntop(AF_INET, bin, buf, len)) != NULL, "knot_inet_ntop(%s)", addr); \
	ok(strcmp(txt, addr) == 0, "match %s", addr);

#define CHECK6(addr, ref) \
	ok(inet_pton(AF_INET6, addr, bin) == 1, "inet_pton(%s)", addr); \
	ok((txt = knot_inet_ntop(AF_INET6, bin, buf, len)) != NULL, "knot_inet_ntop(%s)", addr); \
	ok(strcmp(txt, ref) == 0, "match %s %s", txt, ref);

int main(int argc, char *argv[])
{
	plan_lazy();

	diag("IPv4 addresses");
	CHECK4("0.0.0.0");
	CHECK4("1.2.3.4");
	CHECK4("11.12.13.14");
	CHECK4("255.255.255.255");

	diag("IPv6 addresses");
	CHECK6("::0",    "::");
	CHECK6("::00",   "::");
	CHECK6("::000",  "::");
	CHECK6("::0000", "::");

	CHECK6("::1",    "::1");
	CHECK6("::01",   "::1");
	CHECK6("::001",  "::1");
	CHECK6("::0001", "::1");

	CHECK6("::10",   "::10");
	CHECK6("::100",  "::100");
	CHECK6("::1000", "::1000");

	CHECK6("::1:0",           "::1:0");
	CHECK6("::1:0:0",         "::1:0:0");
	CHECK6("::1:0:0:0",       "::1:0:0:0");
	CHECK6("::1:0:0:0:0",     "0:0:0:1::");
	CHECK6("::1:0:0:0:0:0",   "0:0:1::");
	CHECK6("::1:0:0:0:0:0:0", "0:1::");
	CHECK6("1:0:0:0:0:0:0:0", "1::");

	// IPv4-Compatible IPv6 Addresses (not supported).
	CHECK6("::0:1:1",     "::1:1");
	CHECK6("::0:1.2.3.4", "::102:304");

	// IPv4-Mapped IPv6 Addresses.
	CHECK6("::ffff:1:1",     "::ffff:0.1.0.1");
	CHECK6("::ffff:1.2.3.4", "::ffff:1.2.3.4");

	CHECK6("1::1", "1::1");
	CHECK6("1000::1", "1000::1");
	CHECK6("1:20:300:4000:0005:006:07:8", "1:20:300:4000:5:6:7:8");

	return 0;
}
