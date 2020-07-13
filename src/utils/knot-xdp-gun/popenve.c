/*  Copyright (C) 2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include "utils/knot-xdp-gun/popenve.h"

#ifdef ENABLE_CAP_NG
#include <cap-ng.h>

static void drop_capabilities(void)
{
	/* Drop all capabilities. */
	if (capng_have_capability(CAPNG_EFFECTIVE, CAP_SETPCAP)) {
		capng_clear(CAPNG_SELECT_BOTH);
		capng_apply(CAPNG_SELECT_BOTH);
	}
}
#else /* ENABLE_CAP_NG */
static void drop_capabilities(void) {  }
#endif

int kpopenvef(const char *binfile, char *const args[], char *const env[], bool drop_cap)
{
	int pipefds[2];
	if (pipe(pipefds) < 0) {
		return -errno;
	}
	if (fcntl(pipefds[0], F_SETFD, FD_CLOEXEC) < 0) {
		int fcntlerrno = errno;
		close(pipefds[0]);
		close(pipefds[1]);
		return -fcntlerrno;
	}

	pid_t forkpid = fork();
	if (forkpid < 0) {
		int forkerrno = errno;
		close(pipefds[0]);
		close(pipefds[1]);
		return -forkerrno;
	}

	if (forkpid == 0) {
dup_stdout:
		if (dup2(pipefds[1], STDOUT_FILENO) < 0) {
			if (errno == EINTR) {
				goto dup_stdout;
			}
			perror("dup_stdout");
			close(pipefds[0]);
			close(pipefds[1]);
			exit(EXIT_FAILURE);
		}
		close(pipefds[1]);

		if (drop_cap) {
			drop_capabilities();
		}

		execve(binfile, args, env);
		perror("execve");
		exit(EXIT_FAILURE);
	}

	close(pipefds[1]);
	return pipefds[0];
}

FILE *kpopenve(const char *binfile, char *const args[], char *const env[], bool drop_cap)
{
	int p = kpopenvef(binfile, args, env, drop_cap);
	if (p < 0) {
		errno = -p;
		return NULL;
	}

	FILE *res = fdopen(p, "r");
	if (res == NULL) {
		int fdoerrno = errno;
		close(p);
		errno = fdoerrno;
	}
	return res;
}
