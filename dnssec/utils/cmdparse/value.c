/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "cmdparse/value.h"
#include "print.h"

#include <assert.h>
#include <stdbool.h>

static void error_missing_option(const parameter_t *p)
{
	error("Missing value for option '%s'.", p->name);
}

int value_flag(int argc, char *argv[], const parameter_t *p, void *data)
{
	assert(p);
	assert(data);

	bool *flag = data + p->offset;
	*flag = true;

	return 0;
}

int value_string(int argc, char *argv[], const parameter_t *p, void *data)
{
	assert(p);
	assert(data);

	if (argc < 1) {
		error_missing_option(p);
		return -1;
	}

	char **string = data + p->offset;
	*string = argv[0];

	return 1;
}
