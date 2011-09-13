#include <stdlib.h>
#include <stdint.h>

#include "tests/common/os_fdset_tests.h"
#include "common/os_fdset.h"

static int os_fdset_tests_count(int argc, char *argv[]);
static int os_fdset_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api os_fdset_tests_api = {
	"Native fdset poll wrapper",   //! Unit name
	&os_fdset_tests_count,  //! Count scheduled tests
	&os_fdset_tests_run     //! Run scheduled tests
};

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
	int fds[2];
	int ret = pipe(fds);
	ok(ret >= 0, "os_fdset: pipe() works");

	/* 3. Add fd to set. */
	ret = os_fdset_add(set, fds[0], OS_EV_READ);
	ok(ret == 0, "os_fdset: add to set works");

	/* 4. Watch fdset. */
	const char pattern = 0xde;
	ret = write(fds[1], &pattern, 1);
	ret = os_fdset_poll(set);
	ok(ret > 0, "os_fdset: poll returned events");

	/* 5. Prepare event set. */
	os_fdset_it it;
	ret = os_fdset_begin(set, &it);
	ok(ret == 0, "os_fdset: begin is valid");

	/* 6. Receive data. */
	char buf;
	ret = read(it.fd, &buf, 1);
	ok(ret >= 0 && buf == pattern, "os_fdset: contains valid data");

	/* 7. Iterate event set. */
	ret = os_fdset_next(set, &it);
	ok(ret < 0, "os_fdset: boundary check works");

	/* 8. Remove from event set. */
	ret = os_fdset_remove(set, fds[0]);
	ok(ret == 0, "os_fdset: remove from fdset works");
	close(fds[0]);
	close(fds[1]);

	/* 9. Poll empty fdset. */
	ret = os_fdset_poll(set);
	ok(ret <= 0, "os_fdset: polling empty fdset returns");

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

	return 0;
}
