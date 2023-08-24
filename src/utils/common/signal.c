/*  Copyright (C) 2023 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <signal.h>
#include <stdio.h>

#include "utils/common/signal.h"

#include "contrib/color.h"
#include "knot/conf/base.h"

extern signal_ctx_t signal_ctx; // It must be defined as global in each utility.
int SIGNAL_REPEAT = 1;

static void signal_handler(int signum)
{
	// Allow a repeated signal during the handler run (in case
	// the handler gets stuck).
	sigset_t set;
	(void)sigaddset(&set, signum);
	(void)sigprocmask(SIG_UNBLOCK, &set, NULL);

	if (--SIGNAL_REPEAT < 0) {
		abort();
	}

	(void)printf("%s%s\n", COL_RST(signal_ctx.color),
	             signum == SIGINT ? "" : strsignal(signum));

	conf_t *config = conf();
	if (config != NULL && config->api != NULL) {
		config->api->deinit(config->db);
	}

	if (signal_ctx.close_db != NULL) {
		knot_lmdb_close(signal_ctx.close_db);
	}

	exit(EXIT_FAILURE);
}

void signal_init_std(void)
{
	struct sigaction sigact = { .sa_handler = signal_handler };

	sigaction(SIGHUP, &sigact, NULL);
	sigaction(SIGINT, &sigact, NULL);
	sigaction(SIGPIPE, &sigact, NULL);
	sigaction(SIGALRM, &sigact, NULL);
	sigaction(SIGTERM, &sigact, NULL);
	sigaction(SIGUSR1, &sigact, NULL);
	sigaction(SIGUSR2, &sigact, NULL);
}
