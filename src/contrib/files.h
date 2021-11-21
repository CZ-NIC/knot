/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
 * Gets the absolute path.
 *
 * \note The result must be explicitly deallocated.
 *
 * \param[in] path      Absolute path or a relative path suffix; a string.
 * \param[in] base_dir  Path prefix for a relative string.
 *
 * \return Absolute path string pointer.
 */
char* abs_path(const char *path, const char *base_dir);

/*!
 * Try to compare two paths whether they are identical.
 *
 * \note If any of the two paths doesn't physically exist, their identity can't
 *       be detected in some special corner cases.
 *
 * \param[in] path1     Absolute or a relative path (a file, a directory, etc.)
 * \param[in] path2     Absolute or a relative path (a file, a directory, etc.)
 *
 * \return True if both paths are identical (if they point to the same inode),
 *         false otherwise.
 */
bool same_path(const char *path1, const char *path2);

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

/*!
 * Copies a file, possibly overwriting existing one, as an atomic operation.
 *
 * \return KNOT_EOK on success, KNOT_EFILE if the source file doesn't exist,
 *         \or other KNOT_E* values in case of other errors.
 */
int copy_file(const char *dest, const char *src);
