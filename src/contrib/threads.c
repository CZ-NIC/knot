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
