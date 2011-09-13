#include <stdlib.h>
#include <stdint.h>
#include <sys/time.h>
#include <pthread.h>

#include "tests/common/os_fdset_tests.h"
#include "common/os_fdset.h"

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

static int os_fdset_tests_count(int argc, char *argv[]);
static int os_fdset_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api os_fdset_tests_api = {
	"Native fdset poll wrapper",   //! Unit name
	&os_fdset_tests_count,  //! Count scheduled tests
	&os_fdset_tests_run     //! Run scheduled tests
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
	int ret = write(*fd, &pattern, WRITE_PATTERN_LEN);
	ret = 0; /* Use variable. */

	return 0;
}

static int os_fdset_tests_count(int argc, char *argv[])
{
	return 11;
}

static int os_fdset_tests_run(int argc, char *argv[])
{
	diag("os_fdset: implements '%s'", os_fdset_method());

	/* 1. Create fdset. */
	os_fdset_t *set = os_fdset_new();
	ok(set != 0, "os_fdset: new");

	/* 2. Create pipe. */
	int fds[2], tmpfds[2];
	int ret = pipe(fds);
	ok(ret >= 0, "os_fdset: pipe() works");
	ret = pipe(tmpfds);

	/* 3. Add fd to set. */
	ret = os_fdset_add(set, fds[0], OS_EV_READ);
	ok(ret == 0, "os_fdset: add to set works");
	os_fdset_add(set, tmpfds[0], OS_EV_READ);

	/* Schedule write. */
	struct timeval ts, te;
	gettimeofday(&ts, 0);
	pthread_t t;
	pthread_create(&t, 0, thr_action, &fds[1]);

	/* 4. Watch fdset. */
	ret = os_fdset_poll(set);
	gettimeofday(&te, 0);
	size_t diff = timeval_diff(&ts, &te);

	ok(ret > 0 && diff > 99 && diff < 10000,
	   "os_fdset: poll returned events in %zu ms", diff);

	/* 5. Prepare event set. */
	os_fdset_it it;
	ret = os_fdset_begin(set, &it);
	ok(ret == 0 && it.fd == fds[0], "os_fdset: begin is valid, ret=%d", ret);

	/* 6. Receive data. */
	char buf = 0x00;
	ret = read(it.fd, &buf, WRITE_PATTERN_LEN);
	ok(ret >= 0 && buf == WRITE_PATTERN, "os_fdset: contains valid data, fd=%d", it.fd);

	/* 7. Iterate event set. */
	ret = os_fdset_next(set, &it);
	ok(ret < 0, "os_fdset: boundary check works");

	/* 8. Remove from event set. */
	ret = os_fdset_remove(set, fds[0]);
	ok(ret == 0, "os_fdset: remove from fdset works");
	close(fds[0]);
	close(fds[1]);
	ret = os_fdset_remove(set, tmpfds[0]);
	close(tmpfds[1]);
	close(tmpfds[1]);

	/* 9. Poll empty fdset. */
	ret = os_fdset_poll(set);
	ok(ret <= 0, "os_fdset: polling empty fdset returns -1 (ret=%d)", ret);

	/* 10. Crash test. */
	lives_ok({
		 os_fdset_destroy(0);
		 os_fdset_add(0, -1, 0);
		 os_fdset_remove(0, -1);
		 os_fdset_poll(0);
		 os_fdset_begin(0, 0);
		 os_fdset_end(0, 0);
		 os_fdset_next(0, 0);
		 os_fdset_method();
	}, "os_fdset: crash test successful");

	/* 11. Destroy fdset. */
	ret = os_fdset_destroy(set);
	ok(ret == 0, "os_fdset: destroyed");

	/* Cleanup. */
	pthread_join(t, 0);

	return 0;
}
