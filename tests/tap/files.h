/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
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
