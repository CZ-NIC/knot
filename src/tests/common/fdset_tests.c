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

#include "tests/common/fdset_tests.h"
#include "common/fdset.h"

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

static int fdset_tests_count(int argc, char *argv[]);
static int fdset_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api fdset_tests_api = {
	"Native fdset poll wrapper",   //! Unit name
	&fdset_tests_count,  //! Count scheduled tests
	&fdset_tests_run     //! Run scheduled tests
};

void* thr_action(void *arg)
{
	int *fd = (int *)arg;

	/* Sleep for 100ms. */
	struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = 100 * 1000; // 100ms
	select(0, 0, 0, 0, &tv);

	/* Write pattern. */
	char pattern = WRITE_PATTERN;
	(void)write(*fd, &pattern, WRITE_PATTERN_LEN);

	return NULL;
}

static int fdset_tests_count(int argc, char *argv[])
{
	return 11;
}

static int fdset_tests_run(int argc, char *argv[])
{
	diag("fdset: implements '%s'", fdset_method());

	/* 1. Create fdset. */
	fdset_t *set = fdset_new();
	ok(set != 0, "fdset: new");

	/* 2. Create pipe. */
	int fds[2], tmpfds[2];
	int ret = pipe(fds);
	ok(ret >= 0, "fdset: pipe() works");
	ret = pipe(tmpfds);

	/* 3. Add fd to set. */
	ret = fdset_add(set, fds[0], OS_EV_READ);
	ok(ret == 0, "fdset: add to set works");
	fdset_add(set, tmpfds[0], OS_EV_READ);

	/* Schedule write. */
	struct timeval ts, te;
	gettimeofday(&ts, 0);
	pthread_t t;
	pthread_create(&t, 0, thr_action, &fds[1]);

	/* 4. Watch fdset. */
	ret = fdset_wait(set, OS_EV_FOREVER);
	gettimeofday(&te, 0);
	size_t diff = timeval_diff(&ts, &te);

	ok(ret > 0 && diff > 99 && diff < 10000,
	   "fdset: poll returned events in %zu ms", diff);

	/* 5. Prepare event set. */
	fdset_it_t it;
	ret = fdset_begin(set, &it);
	ok(ret == 0 && it.fd == fds[0], "fdset: begin is valid, ret=%d", ret);

	/* 6. Receive data. */
	char buf = 0x00;
	ret = read(it.fd, &buf, WRITE_PATTERN_LEN);
	ok(ret >= 0 && buf == WRITE_PATTERN, "fdset: contains valid data, fd=%d", it.fd);

	/* 7. Iterate event set. */
	ret = fdset_next(set, &it);
	ok(ret < 0, "fdset: boundary check works");

	/* 8. Remove from event set. */
	ret = fdset_remove(set, fds[0]);
	ok(ret == 0, "fdset: remove from fdset works");
	close(fds[0]);
	close(fds[1]);
	ret = fdset_remove(set, tmpfds[0]);
	close(tmpfds[1]);
	close(tmpfds[1]);

	/* 9. Poll empty fdset. */
	ret = fdset_wait(set, OS_EV_FOREVER);
	ok(ret <= 0, "fdset: polling empty fdset returns -1 (ret=%d)", ret);

	/* 10. Crash test. */
	lives_ok({
		 fdset_destroy(0);
		 fdset_add(0, -1, 0);
		 fdset_remove(0, -1);
		 fdset_wait(0, OS_EV_NOWAIT);
		 fdset_begin(0, 0);
		 fdset_end(0, 0);
		 fdset_next(0, 0);
		 fdset_method();
	}, "fdset: crash test successful");

	/* 11. Destroy fdset. */
	ret = fdset_destroy(set);
	ok(ret == 0, "fdset: destroyed");

	/* Cleanup. */
	pthread_join(t, 0);

	return 0;
}
