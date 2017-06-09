/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <tap/basic.h>

#include "contrib/time.h"

static void test_now(void)
{
	struct timespec t = time_now();
	ok(t.tv_sec != 0, "time_now() returns something");
}

static void test_diff(void)
{
	struct timespec t1 = { 10, 1000 };
	struct timespec t2 = { 50, 1500 };
	struct timespec t3 = { 70, 500 };

	struct timespec res;

	res = time_diff(&t1, &t2);
	ok(res.tv_sec == 40 && res.tv_nsec == 500, "time_diff()");

	res = time_diff(&t2, &t3);
	ok(res.tv_sec == 19 && res.tv_nsec == 999999000, "time_diff() ns overflow");

	res = time_diff(&t3, &t1);
	ok(res.tv_sec == -60 && res.tv_nsec == 500, "time_diff() negative");

	res = time_diff(&t2, &t1);
	ok(res.tv_sec == -41 && res.tv_nsec == 999999500, "time_diff() negative");
}

static void test_diff_ms(void)
{
	struct timespec t1 = { 10, 1000 };
	struct timespec t2 = { 50, 500 };

	float ms = 0.0;

	ms = time_diff_ms(&t1, &t2);
	ok(39990.0 < ms && ms < 40010.0, "time_diff_ms()");

	ms = time_diff_ms(&t2, &t1);
	ok(-40010.0 < ms && ms < -39990.0, "time_diff_ms() negative");
}

static void test_knot_time(void)
{
	knot_time_t a = knot_time();
	knot_time_t inf = 0;
	knot_time_t c;
	knot_timediff_t d;
	int ret;

	ok(a != 0, "knot time not zero");

	ret = knot_time_cmp(a, a);
	ok(ret == 0, "compare same times");

	ret = knot_time_cmp(a - 1, a + 1);
	ok(ret == -1, "compare smaller time");

	ret = knot_time_cmp(a + 10, a - 10);
	ok(ret == 1, "compare bigger time");

	ret = knot_time_cmp(inf, inf);
	ok(ret == 0, "compare two infinities");

	ret = knot_time_cmp(a, inf);
	ok(ret == -1, "compare time and infty");

	ret = knot_time_cmp(inf, a);
	ok(ret == 1, "compare infty and time");

	c = knot_time_min(a, a);
	ok(c == a, "take same time");

	c = knot_time_min(a, a + 1);
	ok(c == a, "take first smaller");

	c = knot_time_min(a + 1, a);
	ok(c == a, "take second smaller");

	c = knot_time_min(inf, inf);
	ok(c == inf, "take same infty");

	c = knot_time_min(a, inf);
	ok(c == a, "take first finite");

	c = knot_time_min(inf, a);
	ok(c == a, "take second finite");

	d = knot_time_diff(a + 1, a);
	ok(d == 1, "positive diff");

	d = knot_time_diff(a, a + 1);
	ok(d == -1, "negative diff");

	d = knot_time_diff(inf, inf);
	ok(d == KNOT_TIMEDIFF_MAX, "positive double infty diff");

	d = knot_time_diff(inf, a);
	ok(d == KNOT_TIMEDIFF_MAX, "positive infty diff");

	d = knot_time_diff(a, inf);
	ok(d == KNOT_TIMEDIFF_MIN, "negative infty diff");
}

int main(int argc, char *argv[])
{
	plan_lazy();

	test_now();
	test_diff();
	test_diff_ms();
	test_knot_time();

	return 0;
}
