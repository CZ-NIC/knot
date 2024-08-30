/*  Copyright (C) 2024 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "contrib/threads.h"

typedef struct {
	const struct sigaction *sa;
	const sigset_t *sm;
	void *(*routine)(void *);
	void *arg;
	const int *signals;
	int nsignals;
} sigsafe_arg_t;

static void *thread_create_sigsafe__impl(void *arg)
{
	sigsafe_arg_t *sarg = arg;

	// first set handlers, then unblock - order matters!
	for (int i = 0; i < sarg->nsignals; ++i) {
		sigaction(sarg->signals[i], sarg->sa, NULL);
	}
	pthread_sigmask(SIG_SETMASK, sarg->sm, NULL);

	return sarg->routine(sarg->arg);
}

int thread_create_sigsafe(pthread_t *restrict thr,
			  const pthread_attr_t *restrict attr,
			  const struct sigaction *sa,
			  const sigset_t *sm,
			  const int *signals,
			  int nsignals,
			  void *(*routine)(void *),
			  void *restrict arg)
{
	sigset_t mask;
	sigset_t oldmask;
	sigfillset(&mask);
	sigdelset(&mask, SIGBUS);
	sigdelset(&mask, SIGFPE);
	sigdelset(&mask, SIGILL);
	sigdelset(&mask, SIGSEGV);

	// block all blockable signals
	pthread_sigmask(SIG_SETMASK, &mask, &oldmask);

	// set desired sigmask and signal handler inside the thread through a wrapper function
	sigsafe_arg_t sarg = { sa, sm, routine, arg, signals, nsignals };
	int ret = pthread_create(thr, attr, thread_create_sigsafe__impl, &sarg);

	// restore original sigmask
	pthread_sigmask(SIG_SETMASK, &oldmask, NULL);

	return ret;
}
