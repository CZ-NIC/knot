/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
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
#include <strings.h>

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

/*! @} */
