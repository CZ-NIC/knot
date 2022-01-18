/*  Copyright (C) 2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
