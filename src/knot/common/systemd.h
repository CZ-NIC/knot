/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
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
