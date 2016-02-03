/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
 * \brief String manipulations.
 *
 * \addtogroup contrib
 * @{
 */

#pragma once

#include <stdint.h>

/*!
 * \brief Create a copy of a binary buffer.
 *
 * Like \c strdup, but for binary data.
 */
uint8_t *memdup(const uint8_t *data, size_t data_size);

/*!
 * \brief Format string and take care of allocating memory.
 *
 * \note sprintf(3) manual page reference implementation.
 *
 * \param fmt Message format.
 * \return formatted message or NULL.
 */
char *sprintf_alloc(const char *fmt, ...);

/*!
 * \brief Create new string from a concatenation of s1 and s2.
 *
 * \param s1 First string.
 * \param s2 Second string.
 *
 * \retval Newly allocated string on success.
 * \retval NULL on error.
 */
char *strcdup(const char *s1, const char *s2);

/*!
 * \brief Create a copy of a string skipping leading and trailing white spaces.
 *
 * \return Newly allocated string, NULL in case of error.
 */
char *strstrip(const char *str);

/*! @} */
