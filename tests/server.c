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

#include <config.h>
#include <tap/basic.h>
#include "knot/server/server.h"

/*! Test: create server. */
server_t *test_server_create()
{
	return server_create();
}

/*! Test: start server. */
int test_server_start(server_t *s)
{
	return server_start(s) == 0;
}

/*! Test: finish server. */
int test_server_finish(server_t *s)
{
	return server_wait(s) == 0;
}

/*! Test: stop server. */
int test_server_destroy(server_t *s)
{
	server_destroy(&s);
	return s == 0;
}

// Signal handler
static void interrupt_handle(int s)
{
}

/*! API: run tests. */
int main(int argc, char *argv[])
{
	plan(4);

	server_t *server = 0;
	int ret = 0;

	// Register service and signal handler
	struct sigaction sa;
	sa.sa_handler = interrupt_handle;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGALRM, &sa, NULL); // Interrupt

	//! Test server for correct initialization
	server = test_server_create();
	ok(server != 0, "server: initialized");

	//! Test server startup
	ret = test_server_start(server);
	ok(ret, "server: started ok");

	if (!ret) {
	        skip_block(2, "server crashed, skipping deinit and destroy tests");
	} else {
		server_stop(server);

		//! Test server waiting for finish
		ok(test_server_finish(server), "server: waiting for finish");

		//! Test server for correct deinitialization
		ok(test_server_destroy(server), "server: deinit");
	}

	return 0;
}
