/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#pragma once

#include <time.h>

#include "knot/dnssec/context.h"
#include "knot/dnssec/zone-events.h"
#include "knot/zone/zone.h"

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
 * \param ctx           zone signing context
 * \param keys_changed  output if KNOT_EOK: were any keys changed ? (if so, please re-sign)
 * \param next_rollover output if KNOT_EOK: tmestamp when next rollover action takes place
 *
 * \return KNOT_E*
 */
int knot_dnssec_key_rollover(kdnssec_ctx_t *ctx, zone_sign_reschedule_t *reschedule);

int knot_dnssec_ksk_submittion_confirm(kdnssec_ctx_t *ctx, uint16_t for_key);

bool zone_has_key_submittion(const kdnssec_ctx_t *ctx);
