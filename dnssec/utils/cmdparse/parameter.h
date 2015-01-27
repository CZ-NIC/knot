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

#pragma once

#include <stdbool.h>
#include <stdlib.h>

struct parameter;
typedef struct parameter parameter_t;

typedef int (*parameter_cb)(int argc, char *argv[],
			    const parameter_t *parameter, void *data);

struct parameter {
	char *name;
	parameter_cb process;

	bool req_full_match;
	char *hint;

	size_t offset;
};

int parse_parameters(const parameter_t *params, int argc, char *argv[], void *data);
