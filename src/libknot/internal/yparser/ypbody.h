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
/*!
 * \file
 *
 * Yparser core interface for Ragel source.
 *
 * \addtogroup yparser
 *
 * @{
 */

#pragma once

#include "libknot/internal/yparser/yparser.h"

/*!
 * Gets the initial parser state.
 */
int _start_state(
	void
);

/*!
 * Executes the parser on the current input block.
 *
 * \param[in] parser A parser returned by #yp_create().
 */
int _parse(
	yp_parser_t *parser
);

/*! @} */
