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
/*!
 * \file
 *
 * \brief A general purpose lookup table.
 *
 * \addtogroup libknot
 * @{
 */

#pragma once

#include <string.h>

/*!
 * \brief A general purpose lookup table.
 */
typedef struct knot_lookup {
	int id;
	const char *name;
} knot_lookup_t;

/*!
 * \brief Looks up the given name in the lookup table.
 *
 * \param table Lookup table.
 * \param name Name to look up.
 *
 * \return Item in the lookup table with the given name or NULL if no such is
 *         present.
 */
inline static const knot_lookup_t *knot_lookup_by_name(const knot_lookup_t *table, const char *name)
{
	if (table == NULL || name == NULL) {
		return NULL;
	}

	while (table->name != NULL) {
		if (strcasecmp(name, table->name) == 0) {
			return table;
		}
		table++;
	}

	return NULL;
}

/*!
 * \brief Looks up the given id in the lookup table.
 *
 * \param table Lookup table.
 * \param id ID to look up.
 *
 * \return Item in the lookup table with the given id or NULL if no such is
 *         present.
 */
inline static const knot_lookup_t *knot_lookup_by_id(const knot_lookup_t *table, int id)
{
	if (table == NULL) {
		return NULL;
	}

	while (table->name != NULL) {
		if (table->id == id) {
			return table;
		}
		table++;
	}

	return NULL;
}
