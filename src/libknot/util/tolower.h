/*!
 * \file tolower.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Table for converting ASCII characters to lowercase.
 *
 * \addtogroup libknot
 * @{
 */
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

#pragma once

#include <stdint.h>
#include <stdlib.h>

/*! \brief Size of the character conversion table. */
#define KNOT_CHAR_TABLE_SIZE (UINT8_MAX + 1)

/*! \brief Character table mapping uppercase letters to lowercase. */
extern const uint8_t char_table[KNOT_CHAR_TABLE_SIZE];

/*!
 * \brief Converts binary character to lowercase.
 *
 * \param c  Character code.
 *
 * \return \a c converted to lowercase (or \a c if not applicable).
 */
static inline uint8_t knot_tolower(uint8_t c) {
	return char_table[c];
}

/*!
 * \brief Convert binary data to lowercase (if lowercase equivalent exists).
 *
 * \param data  Binary input string.
 * \param size  Size of the input string
 *
 * \return Lowercase representation of the input string.
 */
static inline uint8_t *knot_strtolower(const uint8_t *data, size_t size)
{
	uint8_t *result = (uint8_t *)malloc(size);
	if (!result)
		return NULL;

	for (size_t i = 0; i < size; ++i) {
		result[i] = knot_tolower(data[i]);
	}

	return result;
}

/*! @} */
