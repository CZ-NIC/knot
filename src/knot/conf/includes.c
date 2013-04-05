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

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "knot/conf/includes.h"

struct conf_includes {
	int free_index;
	int capacity;
	char *names[0];
};

conf_includes_t *conf_includes_init(int capacity)
{
	if (capacity <= 0)
		return NULL;

	size_t size = sizeof(conf_includes_t) + (capacity * sizeof(char *));
	conf_includes_t *result = calloc(1, size);
	if (!result)
		return NULL;

	result->capacity = capacity;
	return result;
}

void conf_includes_free(conf_includes_t *includes)
{
	if (!includes)
		return;

	for (int i = 0; i < includes->free_index; i++)
		free(includes->names[i]);

	free(includes);
}

bool conf_includes_can_push(conf_includes_t *includes)
{
	if (!includes)
		return false;

	return includes->free_index < includes->capacity;
}

bool conf_includes_push(conf_includes_t *includes, const char *filename)
{
	if (!includes || !filename)
		return false;

	if (!conf_includes_can_push(includes))
		return false;

	includes->names[includes->free_index++] = strdup(filename);
	return true;
}

char *conf_includes_top(conf_includes_t *includes)
{
	if (!includes || includes->free_index == 0)
		return NULL;

	return includes->names[includes->free_index - 1];
}

char *conf_includes_pop(conf_includes_t *includes)
{
	char *result = conf_includes_top(includes);
	if (result)
		includes->free_index -= 1;

	return result;
}
