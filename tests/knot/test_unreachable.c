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

		ok(!knot_unreachable_is(global_unreachables, s, via), "unreachables: pre[%d]", i);
		knot_unreachable_add(global_unreachables, s, via);
		ok(knot_unreachable_is(global_unreachables, s, via), "unreachables: post[%d]", i);
		ok(!knot_unreachable_is(global_unreachables, s, not_via), "unreachables: via[%d]", i);

		usleep(1000);
		if (i >= 10) {
			ok(!knot_unreachable_is(global_unreachables, &ur_test_addrs[i - 10], via),
			   "unreachables: expired[%d]", i - 10);
		}
	}

	knot_unreachables_deinit(&global_unreachables);
	ok(global_unreachables == NULL, "unreachables: deinit");

	return 0;
}
