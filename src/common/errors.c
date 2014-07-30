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

#include <stdlib.h>

#include "common/errors.h"

static const error_table_t *lookup_error(const error_table_t *table, int id)
{
	while (table->name != NULL) {
		if (table->id == id) {
			return table;
		}
		table++;
	}

	return NULL;
}

const char *error_to_str(const error_table_t *table, int id)
{
	const error_table_t *msg = lookup_error(table, id);

	if (msg != NULL) {
		return msg->name;
	} else {
		return "Unknown error.";
	}
}
