/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>

#define LMDB_DIR_MODE   0770
#define LMDB_FILE_MODE  0660

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
 * \param[in] path       Absolute path or a relative path suffix; a string.
 * \param[in] keep_apex  If true, don't remove the starting point (apex).
 *
 * \return KNOT_E*
 */
int remove_path(const char *path, bool keep_apex);

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
