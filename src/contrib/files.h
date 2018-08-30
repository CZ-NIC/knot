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
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#pragma once

#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>

/*!
 * \brief Delete file or directory (recursive).
 *
 * \return true on success, false when one or more files failed to be removed.
 */
bool remove_path(const char *path);

/*!
 * Equivalent to mkdir(2), can succeed if the directory already exists.
 */
int make_dir(const char *path, mode_t mode, bool ignore_existing);

/*!
 * Makes a directory part of the path with all parent directories if not exist.
 */
int make_path(const char *path, mode_t mode);

/*!
 * Creates and opens for writing a temporary file based on given path.
 */
int open_tmp_file(const char *path, char **tmp_name, FILE **file, mode_t mode);
