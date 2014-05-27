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
 * \file errors.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \brief Error codes and function for getting error message.
 *
 * \addtogroup common_lib
 * @{
 */

#ifndef _KNOTD_COMMON_ERROR_H_
#define _KNOTD_COMMON_ERROR_H_

#include <errno.h>

/*! \brief Error lookup table. */
typedef struct error_table_t {
	int id;
	const char *name;
} error_table_t;

/*!
 * \brief Returns error message for the given error code.
 *
 * \param table Table of error messages to use.
 * \param code Error code.
 *
 * \return String containing the error message.
 */
const char *error_to_str(const error_table_t *table, int code);

/*!
 * \brief Safe errno mapper that automatically appends sentinel value.
 *
 * \see _map_errno()
 *
 * \param fallback_value Fallback error value (used if the code could not be
 *                       mapped.
 * \param err POSIX errno.
 * \param ... List of handled codes.
 *
 * \return Mapped error code.
 */
#define map_errno(fallback_value, err...) _map_errno(fallback_value, err, 0)

/*!
 * \brief Returns a mapped POSIX errcode.
 *
 * \warning Last error must be 0, it serves as a sentinel value.
 *          Use map_errno() instead.
 *
 * \param fallback_value Fallback error value (used if the code could not be
 *                       mapped.
 * \param arg0 First mandatory argument.
 * \param ... List of handled codes.
 *
 * \return Mapped error code.
 */
int _map_errno(int fallback_value, int arg0, ...);

#endif /* _KNOTD_COMMON_ERROR_H_ */

/*! @} */
