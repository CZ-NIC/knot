/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include "knot/server/server.h"
#include "test_conf.h"

// Signal handler
static void interrupt_handle(int s)
{
}

/*! API: run tests. */
int main(int argc, char *argv[])
{
	plan(2);

	server_t server;
	int ret = 0;

	/* Some random configuration just to apply the default conf schema */
	ret = test_conf("", NULL);
	assert(ret == KNOT_EOK);

	/* Register service and signal handler */
	struct sigaction sa;
	sa.sa_handler = interrupt_handle;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGALRM, &sa, NULL); // Interrupt

	/* Test server for correct initialization */
	ret = server_init(&server, 1);
	is_int(KNOT_EOK, ret, "server: initialized");
	if (ret != KNOT_EOK) {
		return 1;
	}

	/* Test server startup */
	ret = server_start(&server, false);
	is_int(KNOT_EOK, ret, "server: started ok");
	if (ret != KNOT_EOK) {
	        return 1;
	}

	server_stop(&server);

	/* Wait for server to finish. */
	server_wait(&server);

	/* Wait for server to finish. */
	server_deinit(&server);

	return 0;
}
