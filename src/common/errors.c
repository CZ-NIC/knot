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

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "common/errors.h"

/*!
 * \brief Looks up the given id in the lookup table.
 *
 * \param table Lookup table.
 * \param id ID to look up.
 *
 * \return Item in the lookup table with the given id or NULL if no such is
 *         present.
 */
static const error_table_t *error_lookup_by_id(const error_table_t *table,
                                               int id)
{
	while (table->name != 0) {
		if (table->id == id) {
			return table;
		}
		table++;
	}

	return 0;
}

const char *error_to_str(const error_table_t *table, int code)
{
	const error_table_t *msg = error_lookup_by_id(table, code);
	if (msg != 0) {
		return msg->name;
	} else {
		return "Unknown error.";
	}
}

int _map_errno(int fallback_value, int arg0, ...)
{
	/* Iterate all variable-length arguments. */
	va_list ap;
	va_start(ap, arg0);

	/* KNOT_ERROR serves as a sentinel. */
	for (int c = arg0; c != 0; c = va_arg(ap, int)) {

		/* Error code matches with mapped. */
		if (c == errno) {
			/* Return negative value of the code. */
			va_end(ap);
			return -abs(c);
		}
	}
	va_end(ap);

	/* Fallback error code. */
	return fallback_value;
}
