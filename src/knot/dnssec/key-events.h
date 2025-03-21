/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
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
 * \brief Get the key that ought to be retired by activating given new key.
 *
 * \param ctx       DNSSEC context.
 * \param newkey    New key being rolled in.
 *
 * \return Old key being rolled out.
 */
knot_kasp_key_t *knot_dnssec_key2retire(kdnssec_ctx_t *ctx, knot_kasp_key_t *newkey);

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
