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
 * \brief Functions for POSIX process handling.
 *
 * \addtogroup knot
 * @{
 */

#pragma once

#include <stdbool.h>
#include <unistd.h>

/*!
 * \brief Check if PID file exists and create it if possible.
 *
 * \retval NULL if failed.
 * \retval Created PID file path.
 */
char *pid_check_and_create();

/*!
 * \brief Remove PID file.
 *
 * \warning PID file content won't be checked.
 */
void pid_cleanup();

/*!
 * \brief Return true if the PID is running.
 *
 * \param pid Process ID.
 *
 * \retval 1 if running.
 * \retval 0 if not running (or error).
 */
bool pid_running(pid_t pid);

/*!
 * \brief Update process privileges to new UID/GID.
 *
 * \param uid New user ID.
 * \param gid New group ID.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EACCESS if storage is not writeable.
 */
int proc_update_privileges(int uid, int gid);

/*! @} */
