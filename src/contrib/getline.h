/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
 * \brief Multiplatform getline wrapper.
 */

#pragma once

#include <stdio.h>
#include <sys/types.h>

/*!
 * \brief Reads a line from a stream.
 *
 * This function has the same semantics as POSIX.1-2008 getline().
 * If necessary, the output buffer will be allocated/reallocated.
 *
 * \param lineptr	Output buffer.
 * \param n		Output buffer size.
 * \param stream	Input stream.
 *
 * \retval Number of characters read, including new line delimiter,
 *         not including terminating. -1 on error or EOF.
 */
ssize_t knot_getline(char **lineptr, size_t *n, FILE *stream);
