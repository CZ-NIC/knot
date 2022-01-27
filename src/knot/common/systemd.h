/*  Copyright (C) 2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

/*!
 * \brief Systemd API wrappers.
 */

#pragma once

/*!
 * \brief Notify systemd about zone loading start.
 */
void systemd_zone_load_timeout_notify(void);

/*!
 * \brief Update systemd service status with information about number
 *        of scheduled tasks.
 * \param tasks  Number of tasks to be done.
 */
void systemd_tasks_status_notify(int tasks);

/*!
 * \brief Notify systemd about service is ready.
 */
void systemd_ready_notify(void);

/*!
 * \brief Notify systemd about service is reloading.
 */
void systemd_reloading_notify(void);

/*!
 * \brief Notify systemd about service is stopping.
 */
void systemd_stopping_notify(void);

#ifdef ENABLE_SYSTEMD
#include <systemd/sd-bus.h>
#else
#define sd_bus void
#endif

/*!
 * \brief Creates unique D-Bus sender reference (common for whole process).
 * \retval KNOT_EOK on successful create of reference.
 * \retval Negative value on error.
 */
int systemd_dbus_open(void);

/*!
 * \brief Closes D-Bus.
 */
void systemd_dbus_close(void);

/*!
 * \brief Emit event signal in specific format.
 * \param zone Zone name.
 * \retval KNOT_EOK on successful send.
 * \retval Negative value on error.
 */
int systemd_dbus_emit_xfr_done(unsigned char *zone);
