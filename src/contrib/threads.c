/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include "threads.h"

#include <signal.h>

int thread_create_nosignal(pthread_t *thr, void *(*cb)(void*), void *ctx)
{
	sigset_t tmp, orig;
	sigfillset(&tmp);
	sigdelset(&tmp, SIGBUS);
	sigdelset(&tmp, SIGFPE);
	sigdelset(&tmp, SIGILL);
	sigdelset(&tmp, SIGSEGV);
	pthread_sigmask(SIG_SETMASK, &tmp, &orig);

	int ret = pthread_create(thr, NULL, cb, ctx);

	pthread_sigmask(SIG_SETMASK, &orig, NULL);

	return ret;
}
