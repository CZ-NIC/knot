/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

/*!
 * \brief Functions for POSIX process handling.
 */

#pragma once

#include <stdbool.h>
#include <unistd.h>

/*!
 * \brief Check if PID file exists and create it if possible.
 *
 * \retval 0 if failed.
 * \retval Current PID.
 */
unsigned long pid_check_and_create(void);

/*!
 * \brief Remove PID file.
 *
 * \warning PID file content won't be checked.
 */
void pid_cleanup(void);

/*!
 * \brief Return true if the PID is running.
 *
 * \param pid Process ID.
 *
 * \retval true if running.
 * \retval false if not running (or error).
 */
bool pid_running(pid_t pid);

/*!
 * \brief Update process privileges to new UID/GID.
 *
 * \param uid New user ID.
 * \param gid New group ID.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_ERROR if UID or GID change failed.
 */
int proc_update_privileges(int uid, int gid);
