/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
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
