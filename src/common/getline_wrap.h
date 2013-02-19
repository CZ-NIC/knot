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
 * \file getline_wrap.h
 *
 * \author Daniel Salzman <daniel.salzman@nic.cz>
 *
 * \brief getline wrapper.
 *
 * \addtogroup common_lib
 * @{
 */

#ifndef _KNOTD_COMMON_GETLINE_WRAP_H_
#define _KNOTD_COMMON_GETLINE_WRAP_H_

#include <stdio.h>		// size_t

/*!
 * \brief Reads a line from stream.
 *
 * This wrapper switches between getline (Linux) and fgetln (BSD).
 *
 * \note It is necessary to free buffer after use.
 *
 * \param stream	input stream.
 * \param len		length of output buffer.
 *
 * \retval pointer to a buffer.
 */
char* getline_wrap(FILE *stream, size_t *len);

#endif // _KNOTD_COMMON_GETLINE_WRAP_H_

