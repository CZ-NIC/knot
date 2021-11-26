/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "knot/common/unreachable.h"

#include <tap/basic.h>

#define UR_TEST_ADDRS 32
struct sockaddr_storage ur_test_addrs[UR_TEST_ADDRS] = { 0 };

int main(int argc, char *argv[])
{
	plan_lazy();

	global_unreachables = knot_unreachables_init(1000);
	ok(global_unreachables != NULL, "unreachables: init");

	for (int i = 0; i < UR_TEST_ADDRS; i++) {
		struct sockaddr_storage *s = &ur_test_addrs[i];
		struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)s;
		s6->sin6_family = AF_INET6;
		s6->sin6_port = i + 1;

		ok(!knot_unreachable_is(global_unreachables, s), "unreachables: pre[%d]", i);
		knot_unreachable_add(global_unreachables, s);
		ok(knot_unreachable_is(global_unreachables, s), "unreachables: post[%d]", i);

		usleep(100);
		if (i >= 10) {
			ok(!knot_unreachable_is(global_unreachables, &ur_test_addrs[i - 10]), "unreachables: expired[%d]", i - 10);
		}
	}
	usleep(1000);

	for (int i = 0; i < UR_TEST_ADDRS; i++) {
		knot_unreachable_add(global_unreachables, &ur_test_addrs[i]);

		usleep(10);
		if (i >= KNOT_UNREACHABLE_COUNT) {
			ok(!knot_unreachable_is(global_unreachables, &ur_test_addrs[i - KNOT_UNREACHABLE_COUNT]), "unreachables: overfill[%d]", i - 10);
		}
	}

	knot_unreachables_deinit(&global_unreachables);
	ok(global_unreachables == NULL, "unreachables: deinit");
	return 0;
}
