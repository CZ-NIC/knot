/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <tap/basic.h>
#include <stdlib.h>
#include <time.h>

#include "knot/zone/serial.h"
#include "knot/conf/schema.h"
#include "contrib/strtonum.h"

enum serials {
	S_LOWEST = 0,			// lowest value
	S_2LOWEST = 1,			// second lowest value
	S_BELOW_MIDDLE = 0x7fffffff,	// one below middle
	S_ABOVE_MIDDLE = 0x80000000,	// one above middle
	S_2HIGHEST = 0xffffffff - 1,	// second highest value
	S_HIGHEST = 0xffffffff		// highest value
};

static uint32_t random_serial(void)
{
	uint32_t s = rand() & 0xff;
	s |= (rand() & 0xff) << 8;
	s |= (rand() & 0xff) << 16;
	s |= (rand() & 0xff) << 24;

	return s;
}

static void check_unixtime(uint32_t current, uint32_t increment, uint32_t expected, const char *msg)
{
	uint32_t next = serial_next(current, SERIAL_POLICY_UNIXTIME, increment);
	ok(next == expected, "unixtime: %s", msg);
}

/* Test will wrongly fail if the next second starts while running;
 * this is unlikely, so not taking any action */
static void test_unixtime(void)
{
	time_t serial0 = time(NULL);

	check_unixtime(1000000000, 1, serial0, "from old second or policy");
	check_unixtime(serial0, 0, serial0, "reuse current second");
	check_unixtime(serial0, 1, serial0 + 1, "this second's first increment");
	check_unixtime(serial0 + 1, 1, serial0 + 2, "this second's second increment");
	check_unixtime(3000000000, 1, 3000000001, "from future second");
	check_unixtime(3000000000, 0, 3000000000, "at future second");
}

static void check_dateserial(uint32_t current, uint32_t increment, uint32_t expected, const char *msg)
{
	uint32_t next = serial_next(current, SERIAL_POLICY_DATESERIAL, increment);
	ok(next == expected, "dateserial: %s", msg);
}

/* Test will wrongly fail if the next day starts while running;
 * this is EXTREMELY unlikely, so definitely not taking any action */
static void test_dateserial(void)
{
	time_t now = time(NULL);

	struct tm *gm_ret = gmtime(&now);

	char str[32];
	int ret1 = strftime(str, sizeof(str), "%Y%m%d00", gm_ret);

	uint32_t serial0 = 0;
	int ret2 = str_to_u32(str, &serial0);

	ok(gm_ret != NULL && ret1 > 0 && ret2 == KNOT_EOK,
	   "dateserial: prepare current value");

	check_dateserial(2000010100, 1, serial0, "from old date or policy");
	check_dateserial(serial0, 1, serial0 + 1, "today's first increment");
	check_dateserial(serial0 + 98, 1, serial0 + 99, "today's last increment");
	check_dateserial(serial0 + 99, 1, serial0 + 100, "wrap from today");
	check_dateserial(2100010100, 1, 2100010101, "from future date");
	check_dateserial(2100010100, 0, 2100010100, "at future date");
}

int main(int argc, char *argv[])
{
	plan_lazy();

	/* Serial compare test. */
	ok(serial_compare(S_LOWEST, S_BELOW_MIDDLE) == SERIAL_LOWER,
	   "serial compare: lowest < below middle");
	ok(serial_compare(S_BELOW_MIDDLE, S_LOWEST) == SERIAL_GREATER,
	   "serial compare: below middle > lowest");

	/* Corner-case: these serials' distance is exactly 2^31. */
	ok(serial_compare(S_LOWEST, S_ABOVE_MIDDLE) == SERIAL_INCOMPARABLE,
	   "serial compare: lowest < above_middle");
	ok(serial_compare(S_ABOVE_MIDDLE, S_LOWEST) == SERIAL_INCOMPARABLE,
	   "serial compare: above_middle < lowest");

	ok(serial_compare(S_LOWEST, S_HIGHEST) == SERIAL_GREATER,
	   "serial compare: lowest > highest");
	ok(serial_compare(S_HIGHEST, S_LOWEST) == SERIAL_LOWER,
	   "serial compare: highest < lowest");

	ok(serial_compare(S_2LOWEST, S_ABOVE_MIDDLE) == SERIAL_LOWER,
	   "serial compare: 2nd lowest < above middle");
	ok(serial_compare(S_ABOVE_MIDDLE, S_2LOWEST) == SERIAL_GREATER,
	   "serial compare: above middle > 2nd lowest");

	/* Corner-case: these serials' distance is exactly 2^31. */
	ok(serial_compare(S_BELOW_MIDDLE, S_HIGHEST) == SERIAL_INCOMPARABLE,
	   "serial compare: below middle < highest");
	ok(serial_compare(S_HIGHEST, S_BELOW_MIDDLE) == SERIAL_INCOMPARABLE,
	   "serial compare: highest < below middle");

	ok(serial_compare(S_BELOW_MIDDLE, S_2HIGHEST) == SERIAL_LOWER,
	   "serial compare: below middle < 2nd highest");
	ok(serial_compare(S_2HIGHEST, S_BELOW_MIDDLE) == SERIAL_GREATER,
	   "serial compare: 2nd highest > below middle");

	ok(serial_compare(S_ABOVE_MIDDLE, S_HIGHEST) == SERIAL_LOWER,
	   "serial compare: above middle < highest");
	ok(serial_compare(S_HIGHEST, S_ABOVE_MIDDLE) == SERIAL_GREATER,
	   "serial compare: highest > above middle");

	ok(serial_compare(S_LOWEST, S_LOWEST) == SERIAL_EQUAL,
	   "serial compare: lowest == lowest");
	ok(serial_compare(S_HIGHEST, S_HIGHEST) == SERIAL_EQUAL,
	   "serial compare: highest == highest");

	ok(serial_compare(S_LOWEST - 1, S_HIGHEST) == SERIAL_EQUAL,
	   "serial compare: lowest - 1 == highest");
	ok(serial_compare(S_LOWEST, S_HIGHEST + 1) == SERIAL_EQUAL,
	   "serial compare: lowest== highest + 1");

	/* Corner-case: these serials' distance is exactly 2^31. */
	uint32_t s1 = random_serial();
	uint32_t s2 = s1 + S_ABOVE_MIDDLE;  // exactly the 'opposite' number
	ok(serial_compare(s1, s2) == SERIAL_INCOMPARABLE,
	   "serial compare: random opposites (s1 < s2)");
	ok(serial_compare(s2, s1) == SERIAL_INCOMPARABLE,
	   "serial compare: random opposites (s2 < s1)");

	test_dateserial();
	test_unixtime();

	return 0;
}
