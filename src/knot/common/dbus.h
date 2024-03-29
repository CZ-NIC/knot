/*  Copyright (C) 2024 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
 * \brief D-Bus API wrappers.
 */

#pragma once

#include "libknot/libknot.h"

#define KNOT_DBUS_NAME "cz.nic.knotd"
#define KNOT_DBUS_PATH "/cz/nic/knotd"

#define KNOT_BUS_EVENT_STARTED       "started"
#define KNOT_BUS_EVENT_STOPPED       "stopped"
#define KNOT_BUS_EVENT_ZONE_UPD      "zone_updated"
#define KNOT_BUS_EVENT_ZONE_KEYS_UPD "keys_updated"
#define KNOT_BUS_EVENT_ZONE_KSK_SUBM "zone_ksk_submission"
#define KNOT_BUS_EVENT_ZONE_INVALID  "zone_dnssec_invalid"

/*!
 * \brief Creates unique D-Bus sender reference (common for whole process).
 *
 * \retval KNOT_EOK on successful create of reference.
 * \retval Negative value on error.
 */
int dbus_open(void);

/*!
 * \brief Closes D-Bus.
 */
void dbus_close(void);

/*!
 * \brief Emit event signal for started daemon.
 *
 * \param up  Indication if the server has been started.
 */
void dbus_emit_running(bool up);

/*!
 * \brief Emit event signal for updated zones.
 *
 * \param zone_name  Zone name.
 * \param serial     Current zone SOA serial.
 */
void dbus_emit_zone_updated(const knot_dname_t *zone_name, uint32_t serial);

/*!
 * \brief Emit event signal for updated DNSSEC key set.
 *
 * \param zone_name   Zone name.
 */
void dbus_emit_keys_updated(const knot_dname_t *zone_name);

/*!
 * \brief Emit event signal for KSK submission.
 *
 * \param zone_name  Zone name.
 * \param keytag     Keytag of the ready key.
 * \param keyid      KASP id of the ready key.
 */
void dbus_emit_zone_submission(const knot_dname_t *zone_name, uint16_t keytag,
                               const char *keyid);

/*!
 * \brief Emit event signal for failed DNSSEC validation.
 *
 * \param zone_name       Zone name.
 * \param remaining_secs  Remaining time until a RRSIG expires.
 */
void dbus_emit_zone_invalid(const knot_dname_t *zone_name, uint32_t remaining_secs);
