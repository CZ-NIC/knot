/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <time.h>

/*
 * The ISO 8610 'YYYY-MM-DDThh:mm:ss+zzzz' format is used.
 */

/*!
 * Write time stamp into a string buffer.
 *
 * \param buffer     Buffer to write time stamp into.
 * \param size       Size of the output buffer.
 * \param timestamp  Time stamp value to be written.
 *
 * \return Time stamp was written successfully.
 *
 */
bool timestamp_write(char *buffer, size_t size, time_t timestamp);

/*!
 * Read a time stamp from a string buffer.
 *
 * \param[in]  buffer     Buffer to read time stamp from.
 * \param[out] timestamp  Read time stamp value.
 *
 * \return Time stamp was read successfully.
 */
bool timestamp_read(const char *buffer, time_t *timestamp);
