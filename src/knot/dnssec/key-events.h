/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "knot/dnssec/context.h"
#include "knot/dnssec/zone-events.h"

/*!
 * \brief Perform correct ZSK and KSK rollover action and plan next one.
 *
 * For given zone, check keys in KASP db and decide what shall be done
 * according to their timers. Perform the action if they shall be done now,
 * and tell the user the next time it shall be called.
 *
 * This function is optimized to be called from KEY_ROLLOVER_EVENT,
 * but also during zone load so that the zone gets loaded already with
 * proper DNSSEC chain.
 *
 * \param ctx         Zone signing context
 * \param flags       Determine if some actions are forced
 * \param reschedule  Out: timestamp of desired next invoke
 *
 * \return KNOT_E*
 */
int knot_dnssec_key_rollover(kdnssec_ctx_t *ctx, zone_sign_roll_flags_t flags,
                             zone_sign_reschedule_t *reschedule);

/*!
 * \brief Set the submitted KSK to active state and the active one to retired
 *
 * \param ctx           Zone signing context.
 * \param retire_delay  Retire event delay.
 *
 * \return KNOT_E*
 */
int knot_dnssec_ksk_sbm_confirm(kdnssec_ctx_t *ctx, uint32_t retire_delay);

/*!
 * \brief Is there a key in submission phase?
 *
 * \param ctx zone signing context
 *
 * \return False if there is no submitted key or if error; True otherwise
 */
bool zone_has_key_sbm(const kdnssec_ctx_t *ctx);
