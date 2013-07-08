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

#include <config.h>
#include "tests/zscanner/zscanner_tests.h"

#include <stdlib.h>

static int zscanner_tests_count(int argc, char *argv[]);
static int zscanner_tests_run(int argc, char *argv[]);

unit_api zscanner_tests_api = {
	"Zone scanner",
	&zscanner_tests_count,
	&zscanner_tests_run
};

static int zscanner_tests_count(int argc, char *argv[])
{
	return 1;
}

static int zscanner_tests_run(int argc, char *argv[])
{
	int  ret;

	ret = system("/bin/sh ../zscanner/test/run_tests.sh test");
	cmp_ok(ret, "==", 0, "zscanner unittests");

	return 0;
}
