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

/*!
 * \brief Create a temporary file.
 *
 * If TMPDIR environment variable is set, the file is created within
 * that directory. If the variable is not set, the file is created
 * within /tmp.
 */
char *test_mktemp(void);

/*!
 * \brief Create a temporary directory.
 *
 * If TMPDIR environment variable is set, the directory is created within
 * that directory. If the variable is not set, the directory is created
 * within /tmp.
 */
char *test_mkdtemp(void);

/*!
 * \brief Delete file or directory (recursive).
 *
 * \return true on success, false when one or more files failed to be removed.
 */
bool test_rm_rf(const char *path);
