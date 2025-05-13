/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <signal.h>
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
	ret = server_start(&server);
	is_int(KNOT_EOK, ret, "server: started ok");
	if (ret != KNOT_EOK) {
	        return 1;
	}

	server_stop(&server);

	/* Wait for server to finish. */
	server_wait(&server);

	/* Destroy the server structure. */
	server_deinit(&server);

	/* Remove the configuration. */
        conf_free(conf());

	return 0;
}
