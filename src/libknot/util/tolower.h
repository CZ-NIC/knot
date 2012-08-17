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

#ifndef _KNOT_TOLOWER_H_
#define _KNOT_TOLOWER_H_

#include <stdint.h>

/*! \brief Size of the character conversion table. */
#define KNOT_CHAR_TABLE_SIZE 256

enum {
	/*! \brief Size of the character conversion table. */
	CHAR_TABLE_SIZE = KNOT_CHAR_TABLE_SIZE
};

/*! \brief Character table mapping uppercase letters to lowercase. */
extern const uint8_t char_table[CHAR_TABLE_SIZE];

/*!
 * \brief Converts ASCII character to lowercase.
 * 
 * \param c ASCII character code.
 *
 * \return \a c converted to lowercase (or \a c if not applicable).
 */
static inline uint8_t knot_tolower(uint8_t c) {
#if KNOT_CHAR_TABLE_SIZE < 256
	assert(c < CHAR_TABLE_SIZE);
#endif
	return char_table[c];
}

#endif /* _KNOT_TOLOWER_H_ */

/*! @} */
