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

#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <tap/basic.h>

#include "libknot/libknot.h"
#include "libknot/internal/sockaddr.h"
#include "knot/updates/acl.h"
#include "knot/conf/conf.h"

int main(int argc, char *argv[])
{
	plan_lazy();

	int ret;
	struct sockaddr_storage t;

	// 127 dec ~ 01111111 bin
	// 170 dec ~ 10101010 bin
	struct sockaddr_storage ref4;
	assert(sockaddr_set(&ref4, AF_INET, "127.170.170.127", 0) == KNOT_EOK);

	// 7F hex ~ 01111111 bin
	// AA hex ~ 10101010 bin
	struct sockaddr_storage ref6;
	assert(sockaddr_set(&ref6, AF_INET6, "7FAA::AA7F", 0) == KNOT_EOK);

	ret = netblock_match(&ref4, &ref6, 32);
	ok(ret == false, "match: family mismatch");

	ret = netblock_match(NULL, &ref4, 32);
	ok(ret == false, "match: NULL first parameter");
	ret = netblock_match(&ref4, NULL, 32);
	ok(ret == false, "match: NULL second parameter");

	ret = netblock_match(&ref4, &ref4, 31);
	ok(ret == true, "match: ipv4 - identity, subnet");
	ret = netblock_match(&ref4, &ref4, 32);
	ok(ret == true, "match: ipv4 - identity, full prefix");
	ret = netblock_match(&ref4, &ref4, 33);
	ok(ret == true, "match: ipv4 - identity, prefix overflow");

	ret = netblock_match(&ref6, &ref6, 127);
	ok(ret == true, "match: ipv6 - identity, subnet");
	ret = netblock_match(&ref6, &ref6, 128);
	ok(ret == true, "match: ipv6 - identity, full prefix");
	ret = netblock_match(&ref6, &ref6, 129);
	ok(ret == true, "match: ipv6 - identity, prefix overflow");

	// 124 dec ~ 01111100 bin
	assert(sockaddr_set(&t, AF_INET, "124.0.0.0", 0) == KNOT_EOK);
	ret = netblock_match(&t, &ref4, 5);
	ok(ret == true, "match: ipv4 - first byte, shorter prefix");
	ret = netblock_match(&t, &ref4, 6);
	ok(ret == true, "match: ipv4 - first byte, precise prefix");
	ret = netblock_match(&t, &ref4, 7);
	ok(ret == false, "match: ipv4 - first byte, not match");

	assert(sockaddr_set(&t, AF_INET, "127.170.170.124", 0) == KNOT_EOK);
	ret = netblock_match(&t, &ref4, 29);
	ok(ret == true, "match: ipv4 - last byte, shorter prefix");
	ret = netblock_match(&t, &ref4, 30);
	ok(ret == true, "match: ipv4 - last byte, precise prefix");
	ret = netblock_match(&t, &ref4, 31);
	ok(ret == false, "match: ipv4 - last byte, not match");

	// 7C hex ~ 01111100 bin
	assert(sockaddr_set(&t, AF_INET6, "7CAA::", 0) == KNOT_EOK);
	ret = netblock_match(&t, &ref6, 5);
	ok(ret == true, "match: ipv6 - first byte, shorter prefix");
	ret = netblock_match(&t, &ref6, 6);
	ok(ret == true, "match: ipv6 - first byte, precise prefix");
	ret = netblock_match(&t, &ref6, 7);
	ok(ret == false, "match: ipv6 - first byte, not match");

	assert(sockaddr_set(&t, AF_INET6, "7FAA::AA7C", 0) == KNOT_EOK);
	ret = netblock_match(&t, &ref6, 125);
	ok(ret == true, "match: ipv6 - last byte, shorter prefix");
	ret = netblock_match(&t, &ref6, 126);
	ok(ret == true, "match: ipv6 - last byte, precise prefix");
	ret = netblock_match(&t, &ref6, 127);
	ok(ret == false, "match: ipv6 - last byte, not match");

	return 0;
}
