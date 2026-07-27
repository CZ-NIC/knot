/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <tap/basic.h>

#include "knot/common/unreachable.h"

#include "contrib/sockaddr.h"

#define UR_TEST_ADDRS 32
struct sockaddr_storage ur_test_addrs[UR_TEST_ADDRS] = { { 0 } };
struct sockaddr_storage ur_test_via[2] = { { 0 } };

int main(int argc, char *argv[])
{
	plan_lazy();

	global_unreachables = knot_unreachables_init(10);
	ok(global_unreachables != NULL, "unreachables: init");

	// ur_test_via[0] left empty - AF_UNSPEC
	sockaddr_set(&ur_test_via[1], AF_INET6, "::1", 0);

	for (int i = 0; i < UR_TEST_ADDRS; i++) {
		struct sockaddr_storage *s = &ur_test_addrs[i];
		sockaddr_set(s, AF_INET6, "::2", i + 1);
		struct sockaddr_storage *via = &ur_test_via[i % 2];
		struct sockaddr_storage *not_via = &ur_test_via[1 - i % 2];

		ok(!knot_unreachable_is(global_unreachables, s, via, NULL), "unreachables: pre[%d]", i);
		knot_unreachable_add(global_unreachables, s, via, NULL);
		ok(knot_unreachable_is(global_unreachables, s, via, NULL), "unreachables: post[%d]", i);
		ok(!knot_unreachable_is(global_unreachables, s, not_via, NULL), "unreachables: via[%d]", i);

		usleep(1000);
		if (i >= 10) {
			ok(!knot_unreachable_is(global_unreachables, &ur_test_addrs[i - 10], via, NULL),
			   "unreachables: expired[%d]", i - 10);
		}
	}

	// Device keying: same address/via with a different (or no) device must
	// be tracked independently, not collapsed into one another.
	struct sockaddr_storage dev_addr = { 0 };
	sockaddr_set(&dev_addr, AF_INET6, "::99", 53);
	struct sockaddr_storage dev_via = { 0 };
	sockaddr_set(&dev_via, AF_INET6, "::1", 0);

	ok(!knot_unreachable_is(global_unreachables, &dev_addr, &dev_via, "eth0"),
	   "unreachables: dev pre[eth0]");
	knot_unreachable_add(global_unreachables, &dev_addr, &dev_via, "eth0");
	ok(knot_unreachable_is(global_unreachables, &dev_addr, &dev_via, "eth0"),
	   "unreachables: dev post[eth0]");
	ok(!knot_unreachable_is(global_unreachables, &dev_addr, &dev_via, "eth1"),
	   "unreachables: dev[eth1] unaffected by dev[eth0] entry");
	ok(!knot_unreachable_is(global_unreachables, &dev_addr, &dev_via, NULL),
	   "unreachables: no-device unaffected by dev[eth0] entry");

	knot_unreachables_deinit(&global_unreachables);
	ok(global_unreachables == NULL, "unreachables: deinit");

	return 0;
}
