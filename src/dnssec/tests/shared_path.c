/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <stdlib.h>
#include <unistd.h>

#include "path.h"

static void test_normalize(const char *input, const char *expected)
{
	char *output = path_normalize(input);

	is_string(expected, output, "path_normalize(\"%s\")", input);
	free(output);
}

int main(int argc, char *argv[])
{
	plan_lazy();

	test_normalize("/", "/");
	test_normalize("/tmp", "/tmp");
	test_normalize("/tmp/", "/tmp");
	test_normalize("/tmp/../tmp/./", "/tmp");
	test_normalize("/tmp/../../..", "/");

	char *cwd = getcwd(NULL, 0);
	test_normalize(".", cwd);
	free(cwd);

	return 0;
}
