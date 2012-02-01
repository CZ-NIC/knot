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

#include <sys/types.h>
#include <sys/socket.h>

#include "tests/common/acl_tests.h"
#include "common/sockaddr.h"
#include "common/acl.h"

static int acl_tests_count(int argc, char *argv[]);
static int acl_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api acl_tests_api = {
	"ACL",             //! Unit name
	&acl_tests_count,  //! Count scheduled tests
	&acl_tests_run     //! Run scheduled tests
};

static int acl_tests_count(int argc, char *argv[])
{
	return 13;
}

static int acl_tests_run(int argc, char *argv[])
{
	// 1. Create an ACL
	acl_t *acl = acl_new(ACL_DENY, "simple ACL");
	ok(acl != 0, "acl: new");

	// 2. Create IPv4 address
	sockaddr_t test_v4;
	int ret = sockaddr_set(&test_v4, AF_INET, "127.0.0.1", 12345);
	ok(ret > 0, "acl: new IPv4 address");

	// 3. Create IPv6 address
	sockaddr_t test_v6;
	ret = sockaddr_set(&test_v6, AF_INET6, "::1", 54321);
	ok(ret > 0, "acl: new IPv6 address");

	// 4. Create simple IPv4 rule
	ret = acl_create(acl, &test_v4, ACL_ACCEPT, 0);
	ok(ret == ACL_ACCEPT, "acl: inserted IPv4 rule");

	// 5. Create simple IPv6 rule
	ret = acl_create(acl, &test_v6, ACL_ACCEPT, 0);
	ok(ret == ACL_ACCEPT, "acl: inserted IPv6 rule");

	// 6. Create simple IPv4 'any port' rule
	sockaddr_t test_v4a;
	sockaddr_set(&test_v4a, AF_INET, "20.20.20.20", 0);
	ret = acl_create(acl, &test_v4a, ACL_ACCEPT, 0);
	ok(ret == ACL_ACCEPT, "acl: inserted IPv4 'any port' rule");

	// 7. Attempt to match unmatching address
	sockaddr_t unmatch_v4;
	sockaddr_set(&unmatch_v4, AF_INET, "10.10.10.10", 24424);
	ret = acl_match(acl, &unmatch_v4, 0);
	ok(ret == ACL_DENY, "acl: matching non-existing address");

	// 8. Attempt to match unmatching IPv6 address
	sockaddr_t unmatch_v6;
	sockaddr_set(&unmatch_v6, AF_INET6, "2001:db8::1428:57ab", 24424);
	ret = acl_match(acl, &unmatch_v6, 0);
	ok(ret == ACL_DENY, "acl: matching non-existing IPv6 address");

	// 9. Attempt to match matching address
	ret = acl_match(acl, &test_v4, 0);
	ok(ret == ACL_ACCEPT, "acl: matching existing address");

	// 10. Attempt to match matching address
	ret = acl_match(acl, &test_v6, 0);
	ok(ret == ACL_ACCEPT, "acl: matching existing IPv6 address");

	// 11. Attempt to match matching 'any port' address
	sockaddr_t match_v4a;
	sockaddr_set(&match_v4a, AF_INET, "20.20.20.20", 24424);
	ret = acl_match(acl, &match_v4a, 0);
	ok(ret == ACL_ACCEPT, "acl: matching existing IPv4 'any port' address");

	// 12. Attempt to match matching address without matching port
	sockaddr_set(&unmatch_v4, AF_INET, "127.0.0.1", 54321);
	ret = acl_match(acl, &unmatch_v4, 0);
	ok(ret == ACL_DENY, "acl: matching address without matching port");

	// 13. Invalid parameters
	lives_ok({
		acl_delete(0);
		acl_create(0, 0, ACL_ERROR, 0);
		acl_match(0, 0, 0);
		acl_truncate(0);
		acl_name(0);
	}, "acl: won't crash with NULL parameters");

	// Return
	return 0;
}
