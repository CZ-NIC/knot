/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <signal.h>
#include <stdlib.h>

#include "knot/server/signals.h"

volatile bool signals_req_stop = false;
volatile bool signals_req_reload = false;
volatile bool signals_req_zones_reload = false;

struct signal {
	int signum;
	bool handle;
};

static const struct signal SIGNALS[] = {
	{ SIGHUP,  true  },  /* Reload server. */
	{ SIGUSR1, true  },  /* Reload zones. */
	{ SIGINT,  true  },  /* Terminate server. */
	{ SIGTERM, true  },  /* Terminate server. */
	{ SIGALRM, false },  /* Internal thread synchronization. */
	{ SIGPIPE, false },  /* Ignored. Some I/O errors. */
	{ 0 }
};

static void handle_signal(int signum)
{
	switch (signum) {
	case SIGHUP:
		signals_req_reload = true;
		break;
	case SIGUSR1:
		signals_req_zones_reload = true;
		break;
	case SIGINT:
	case SIGTERM:
		if (signals_req_stop) {
			exit(EXIT_FAILURE);
		}
		signals_req_stop = true;
		break;
	default:
		/* ignore */
		break;
	}
}

void signals_setup(void)
{
	/* Block all signals. */
	static sigset_t all;
	sigfillset(&all);
	sigdelset(&all, SIGPROF);
	sigdelset(&all, SIGQUIT);
	sigdelset(&all, SIGILL);
	sigdelset(&all, SIGABRT);
	sigdelset(&all, SIGBUS);
	sigdelset(&all, SIGFPE);
	sigdelset(&all, SIGSEGV);

	/* Setup handlers. */
	struct sigaction action = { .sa_handler = handle_signal };
	for (const struct signal *s = SIGNALS; s->signum > 0; s++) {
		sigaction(s->signum, &action, NULL);
	}

	pthread_sigmask(SIG_SETMASK, &all, NULL);
}

void signals_enable(void)
{
	sigset_t mask;
	sigemptyset(&mask);

	for (const struct signal *s = SIGNALS; s->signum > 0; s++) {
		if (s->handle) {
			sigaddset(&mask, s->signum);
		}
	}

	pthread_sigmask(SIG_UNBLOCK, &mask, NULL);
}
