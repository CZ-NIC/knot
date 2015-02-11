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
 * Get a file name from a configuration entity name.
 *
 * \param dir   Destination directory.
 * \param type  Entity type.
 * \param name  Entity name.
 *
 * \return File name '<dir>/<type><escaped-name>.json'
 */
char *file_from_entity(const char *dir, const char *type, const char *name);

/*!
 * Get a configuration entity name from a file name.
 *
 * \param type      Entity type.
 * \param basename  Base name of the configuration file.
 *
 * \return Unescaped entity name from a basename.
 */
char *file_to_entity(const char *type, const char *basename);
