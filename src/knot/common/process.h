/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
 * \file process.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \brief Functions for POSIX process handling.
 *
 * \addtogroup ctl
 * @{
 */

#pragma once

#include <unistd.h>

/*!
 * \brief Return a filename of the default compiled database file.
 *
 * \retval Filename of the database file.
 * \retval NULL if not exists.
 */
char* pid_filename();

/*!
 * \brief Read PID from given file.
 *
 * \param fn Filename containing PID.
 *
 * \retval PID on success (positive integer).
 * \retval KNOT_EINVAL on null path.
 * \retval KNOT_ENOENT if the filename content cannot be read.
 * \retval KNOT_ERANGE if the stored PID is out of range.
 */
pid_t pid_read(const char* fn);

/*!
 * \brief Write PID to given file.
 *
 * \param fn Filename containing PID.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL on null path.
 * \retval KNOT_ENOENT filename cannot be opened for writing.
 * \retval KNOT_ERROR unspecified error.
 */
int pid_write(const char* fn);

/*!
 * \brief Remove file containing PID.
 *
 * \param fn Filename containing PID.
 *
 * \warning Filename content won't be checked.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL failed to remove filename.
 */
int pid_remove(const char* fn);

/*!
 * \brief Return true if the PID is running.
 *
 * \param pid Process ID.
 *
 * \retval 1 if running.
 * \retval 0 if not running (or error).
 */
int pid_running(pid_t pid);

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

/*!
 * \brief Check if PID file exists and create it if possible.
 * \retval NULL if failed
 * \retval Created PID file path
 */
char *pid_check_and_create();

/*! @} */
