/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
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
