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

#include <stdlib.h>
#include <stdint.h>
#include <sys/time.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <tap/basic.h>
#include <time.h>

#include "knot/common/fdset.h"

#define WRITE_PATTERN ((char) 0xde)
#define WRITE_PATTERN_LEN sizeof(char)

/* Subtract the `struct timeval' values X and Y,
   storing the result in RESULT.
   Return 1 if the difference is negative, otherwise 0.
   Copyright http://www.delorie.com/gnu/docs/glibc/libc_428.html
*/
static int timeval_subtract (struct timeval *result, struct timeval *x,  struct timeval* y)
{
  /* Perform the carry for the later subtraction by updating y. */
  if (x->tv_usec < y->tv_usec) {
    int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
    y->tv_usec -= 1000000 * nsec;
    y->tv_sec += nsec;
  }
  if (x->tv_usec - y->tv_usec > 1000000) {
    int nsec = (x->tv_usec - y->tv_usec) / 1000000;
    y->tv_usec += 1000000 * nsec;
    y->tv_sec -= nsec;
  }

  /* Compute the time remaining to wait.
     tv_usec is certainly positive. */
  result->tv_sec = x->tv_sec - y->tv_sec;
  result->tv_usec = x->tv_usec - y->tv_usec;

  /* Return 1 if result is negative. */
  return x->tv_sec < y->tv_sec;
}

static size_t timeval_diff(struct timeval *from, struct timeval *to) {
	struct timeval res;
	timeval_subtract(&res, to, from);
	return res.tv_sec*1000 + res.tv_usec/1000;
}

void* thr_action(void *arg)
{
	int *fd = (int *)arg;

	/* Sleep for 100ms. */
	struct timespec ts = { .tv_nsec = 1e8 };
	nanosleep(&ts, NULL);

	/* Write pattern. */
	char pattern = WRITE_PATTERN;
	if (write(*fd, &pattern, WRITE_PATTERN_LEN) == -1) {
		// Error.
	}

	return NULL;
}

int main(int argc, char *argv[])
{
	plan(12);

	/* 1. Create fdset. */
	fdset_t set;
	int ret = fdset_init(&set, 32);
	is_int(0, ret, "fdset: init");

	/* 2. Create pipe. */
	int fds[2], tmpfds[2];
	ret = pipe(fds);
	ok(ret >= 0, "fdset: pipe() works");
	ret = pipe(tmpfds);
	ok(ret >= 0, "fdset: 2nd pipe() works");

	/* 3. Add fd to set. */
	ret = fdset_add(&set, fds[0], POLLIN, NULL);
	is_int(0, ret, "fdset: add to set works");
	fdset_add(&set, tmpfds[0], POLLIN, NULL);

	/* Schedule write. */
	struct timeval ts, te;
	gettimeofday(&ts, 0);
	pthread_t t;
	pthread_create(&t, 0, thr_action, &fds[1]);

	/* 4. Watch fdset. */
	int nfds = poll(set.pfd, set.n, 60 * 1000);
	gettimeofday(&te, 0);
	size_t diff = timeval_diff(&ts, &te);

	ok(nfds > 0, "fdset: poll returned %d events in %zu ms", nfds, diff);

	/* 5. Prepare event set. */
	ok(set.pfd[0].revents & POLLIN, "fdset: pipe is active");

	/* 6. Receive data. */
	char buf = 0x00;
	ret = read(set.pfd[0].fd, &buf, WRITE_PATTERN_LEN);
	ok(ret >= 0 && buf == WRITE_PATTERN, "fdset: contains valid data");

	/* 7-9. Remove from event set. */
	ret = fdset_remove(&set, 0);
	is_int(0, ret, "fdset: remove from fdset works");
	close(fds[0]);
	close(fds[1]);
	ret = fdset_remove(&set, 0);
	close(tmpfds[1]);
	close(tmpfds[1]);
	is_int(0, ret, "fdset: remove from fdset works (2)");
	ret = fdset_remove(&set, 0);
	ok(ret != 0, "fdset: removing nonexistent item");

	/* 10. Crash test. */
	fdset_init(0, 0);
	fdset_add(0, 1, 1, 0);
	fdset_add(0, 0, 1, 0);
	fdset_remove(0, 1);
	fdset_remove(0, 0);
	ok(1, "fdset: crash test successful");

	/* 11. Destroy fdset. */
	ret = fdset_clear(&set);
	is_int(0, ret, "fdset: destroyed");

	/* Cleanup. */
	pthread_join(t, 0);

	return 0;
}
