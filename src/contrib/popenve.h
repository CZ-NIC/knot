/*  Copyright (C) 2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <stdio.h>

/*!
 * \brief Hybrid of popen() and execve().
 *
 * This function is a safer altervative to popen(), it is the same to
 * popen() as execve() is to system().
 *
 * \param binfile   Executable file to be executed.
 * \param args      NULL-terminated arguments; first shall be the prog name!
 * \param env       NULL-terminated environment variables "key=value"
 *
 * \retval < 0   Error occured, set to -errno.
 * \return > 0   File descriptor of the pipe reading end.
 */
int kpopenve(const char *binfile, char *const args[], char *const env[]);

/*!
 * \brief Variant of kpopenve() returning FILE*
 *
 * \param binfile   Executable file to be executed.
 * \param args      NULL-terminated arguments; first shall be the prog name!
 * \param env       NULL-terminated environment variables "key=value"
 *
 * \retval NULL   Error occured, see errno.
 * \return Pointer to open file descriptor.
 */
FILE *kpopenve2(const char *binfile, char *const args[], char *const env[]);
