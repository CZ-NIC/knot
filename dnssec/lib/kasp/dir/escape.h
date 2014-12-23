/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

/*!
 * Escape entity name to be safely included into a file name.
 *
 * A-Z letters are converted to lower case.
 *
 * ASCII letters (a-z), numbers (0-9), dot (.), dash (-), and underscore (_)
 * are preserved.
 *
 * Other characters are written as a sequence '\x..', where .. is hex
 * representation of the char.
 *
 * \param[in]  name     Entity name to be encoded.
 * \param[out] escaped  Allocated escaped zone name.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int escape_entity_name(const char *name, char **escaped);

/*!
 * Reverse function of \ref escape_entity_name.
 */
int unescape_entity_name(const char *escaped, char **name);
