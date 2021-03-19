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
#include "contrib/time.h"

#define WRITE_PATTERN		((char)0xde)
#define WRITE_PATTERN_LEN	(sizeof(char))

void *thr_action(void *arg)
{
	int *fd = arg;

	usleep(10000);

	char pattern = WRITE_PATTERN;
	(void)write(*fd, &pattern, sizeof(pattern));

	return NULL;
}

int main(int argc, char *argv[])
{
	plan_lazy();

	fdset_t fdset;
	int ret = fdset_init(&fdset, 32);
	is_int(0, ret, "fdset_init");

	int empty_fds[2], fds[2];
	ret = pipe(empty_fds);
	ok(ret >= 0, "create pipe 1");
	ret = pipe(fds);
	ok(ret >= 0, "create pipe 2");

	ret = fdset_add(&fdset, empty_fds[0], FDSET_POLLIN, NULL);
	ok(ret == 0, "fdset_add 1");
	ret = fdset_add(&fdset, fds[0], FDSET_POLLIN, NULL);
	ok(ret == 1, "fdset_add 2");

	struct timespec time0 = time_now();

	pthread_t t;
	ret = pthread_create(&t, 0, thr_action, &fds[1]);
	ok(ret == 0, "create thread");

	fdset_it_t it;
	int nfds = fdset_poll(&fdset, &it, 0, 20);
	struct timespec time1 = time_now();
	double diff = time_diff_ms(&time0, &time1);
	ok(nfds == 1, "fdset_poll return");
	ok(diff > 5 && diff < 20, "fdset_poll timeout");

	ok(fdset_it_is_pollin(&it), "fdset_it is POLLIN");
	ok(fdset_it_get_idx(&it) == 1, "fdset_it index");

	char buf = 0x00;
	ret = read(fdset_it_get_fd(&it), &buf, sizeof(buf));
	ok(ret == 1 && buf == WRITE_PATTERN, "fdset_it access");

	fdset_clear(&fdset);

	pthread_join(t, 0);

	close(empty_fds[0]); close(empty_fds[1]);
	close(fds[0]); close(fds[1]);

	return 0;
}
