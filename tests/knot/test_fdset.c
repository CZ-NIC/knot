/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <pthread.h>
#include <tap/basic.h>
#include <unistd.h>

#include "knot/common/fdset.h"
#include "libknot/attribute.h"
#include "contrib/time.h"

#define PATTERN1		"0x45"
#define PATTERN2		"0xED"

void *thr_action1(void *arg)
{
	usleep(10000);
	_unused_ int ret = write(*((int *)arg), &PATTERN1, 1);
	return NULL;
}

void *thr_action2(void *arg)
{
	usleep(20000);
	_unused_ int ret = write(*((int *)arg), &PATTERN2, 1);
	return NULL;
}

int main(int argc, char *argv[])
{
	plan_lazy();

	fdset_t fdset;
	int ret = fdset_init(&fdset, 32);
	ok(ret == KNOT_EOK, "fdset_init");

	int fds0[2], fds1[2], fds2[2];

	ret = pipe(fds0);
	ok(ret >= 0, "create pipe 0");
	ret = fdset_add(&fdset, fds0[0], FDSET_POLLIN, NULL);
	ok(ret >= 0, "add pipe 0 to fdset");

	ret = pipe(fds1);
	ok(ret >= 0, "create pipe 1");
	ret = fdset_add(&fdset, fds1[0], FDSET_POLLIN, NULL);
	ok(ret >= 0, "add pipe 1 to fdset");

	ret = pipe(fds2);
	ok(ret >= 0, "create pipe 2");
	ret = fdset_add(&fdset, fds2[0], FDSET_POLLIN, NULL);
	ok(ret >= 0, "add pipe 2 to fdset");

	ok(fdset_get_length(&fdset) == 3, "fdset size full");

	struct timespec time0 = time_now();

	pthread_t t1, t2;
	ret = pthread_create(&t1, 0, thr_action1, &fds1[1]);
	ok(ret == 0, "create thread 1");
	ret = pthread_create(&t2, 0, thr_action2, &fds2[1]);
	ok(ret == 0, "create thread 2");

	fdset_it_t it;
	ret = fdset_poll(&fdset, &it, 0, 100);
	struct timespec time1 = time_now();
	double diff1 = time_diff_ms(&time0, &time1);
	ok(ret == 1, "fdset_poll return 1");
	ok(diff1 > 5 && diff1 < 100, "fdset_poll timeout 1");
	for(; !fdset_it_is_done(&it); fdset_it_next(&it)) {
		ok(!fdset_it_is_error(&it), "fdset no error");
		ok(fdset_it_is_pollin(&it), "fdset can read");

		int fd = fdset_it_get_fd(&it);
		ok(fd == fds1[0], "fdset_it fd check");

		char buf = 0x00;
		ret = read(fd, &buf, sizeof(buf));
		ok(ret == 1 && buf == PATTERN1[0], "fdset_it value check");

		fdset_it_remove(&it);
	}
	fdset_it_commit(&it);
	ok(fdset_get_length(&fdset) == 2, "fdset size 2");
	close(fds1[1]);

	int fd2_dup = dup(fds2[0]);
	ok(fd2_dup >= 0, "duplicate fd");

	ret = fdset_poll(&fdset, &it, 0, 100);
	struct timespec time2 = time_now();
	double diff2 = time_diff_ms(&time0, &time2);
	ok(ret == 1, "fdset_poll return 2");
	ok(diff2 > 15 && diff2 < 100, "fdset_poll timeout 2");
	for(; !fdset_it_is_done(&it); fdset_it_next(&it)) {
		ok(!fdset_it_is_error(&it), "fdset no error");
		ok(fdset_it_is_pollin(&it), "fdset can read");

		int fd = fdset_it_get_fd(&it);
		ok(fd == fds2[0], "fdset_it fd check");

		char buf = 0x00;
		ret = read(fd, &buf, sizeof(buf));
		ok(ret == 1 && buf == PATTERN2[0], "fdset_it value check");

		fdset_it_remove(&it);
	}
	fdset_it_commit(&it);
	ok(fdset_get_length(&fdset) == 1, "fdset size 1");

	pthread_join(t1, 0);
	pthread_join(t2, 0);

	ret = fdset_remove(&fdset, 0);
	ok(ret == KNOT_EOK, "fdset remove");
	close(fds0[1]);
	ok(fdset_get_length(&fdset) == 0, "fdset size 0");

	ret = write(fds2[1], &PATTERN2, 1);
	ok(ret == 1, "write to removed fd");
	ret = fdset_poll(&fdset, &it, 0, 100);
	ok(ret == 0, "fdset_poll return 3");


	close(fds2[1]);
	if (fd2_dup >= 0) {
		close(fd2_dup);
	}
	fdset_clear(&fdset);

	return 0;
}
