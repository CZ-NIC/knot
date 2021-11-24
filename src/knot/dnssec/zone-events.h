/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <time.h>

#include "knot/zone/zone.h"
#include "knot/updates/changesets.h"
#include "knot/updates/zone-update.h"
#include "knot/dnssec/context.h"

enum zone_sign_flags {
	ZONE_SIGN_NONE = 0,
	ZONE_SIGN_DROP_SIGNATURES = (1 << 0),
	ZONE_SIGN_KEEP_SERIAL = (1 << 1),
};

typedef enum zone_sign_flags zone_sign_flags_t;

typedef enum {
	KEY_ROLL_ALLOW_KSK_ROLL    = (1 << 0),
	KEY_ROLL_FORCE_KSK_ROLL    = (1 << 1),
	KEY_ROLL_ALLOW_ZSK_ROLL    = (1 << 2),
	KEY_ROLL_FORCE_ZSK_ROLL    = (1 << 3),
	KEY_ROLL_ALLOW_NSEC3RESALT = (1 << 4),
	KEY_ROLL_ALLOW_ALL         = KEY_ROLL_ALLOW_KSK_ROLL |
	                             KEY_ROLL_ALLOW_ZSK_ROLL |
	                             KEY_ROLL_ALLOW_NSEC3RESALT
} zone_sign_roll_flags_t;

typedef struct {
	knot_time_t next_sign;
	knot_time_t next_rollover;
	knot_time_t next_nsec3resalt;
	knot_time_t last_nsec3resalt;
	bool keys_changed;
	bool plan_ds_check;
} zone_sign_reschedule_t;

/*!
 * \brief Generate/rollover keys in keystore as needed.
 *
 * \param kctx       Pointers to the keytore, policy, etc.
 * \param zone_name  Zone name.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_dnssec_sign_process_events(const kdnssec_ctx_t *kctx,
                                    const knot_dname_t *zone_name);

/*!
 * \brief DNSSEC re-sign zone, store new records into changeset. Valid signatures
 *        and NSEC(3) records will not be changed.
 *
 * \param update       Zone Update structure with current zone contents to be updated by signing.
 * \param conf         Knot configuration.
 * \param flags        Zone signing flags.
 * \param roll_flags   Key rollover flags.
 * \param adjust_now   If not zero: adjust "now" to this timestamp.
 * \param reschedule   Signature refresh time of the oldest signature in zone.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_dnssec_zone_sign(zone_update_t *update,
                          conf_t *conf,
                          zone_sign_flags_t flags,
                          zone_sign_roll_flags_t roll_flags,
                          knot_time_t adjust_now,
                          zone_sign_reschedule_t *reschedule);

/*!
 * \brief Sign changeset (inside incremental Zone Update) created by DDNS or so...
 *
 * \param update      Zone Update structure with current zone contents, changes to be signed and to be updated with signatures.
 * \param conf        Knot configuration.
 * \param reschedule  Signature refresh time of the new signatures.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_dnssec_sign_update(zone_update_t *update, conf_t *conf, zone_sign_reschedule_t *reschedule);

/*!
 * \brief Create new NCES3 salt if the old one is too old, and plan next resalt.
 *
 * For given zone, check NSEC3 salt in KASP db and decide if it shall be recreated
 * and tell the user the next time it shall be called.
 *
 * This function is optimized to be called from NSEC3RESALT_EVENT,
 * but also during zone load so that the zone gets loaded already with
 * proper DNSSEC chain.
 *
 * \param ctx           zone signing context
 * \param salt_changed  output if KNOT_EOK: when was the salt last changed? (either ctx->now or 0)
 * \param when_resalt   output: timestamp when next resalt takes place
 *
 * \return KNOT_E*
 */
int knot_dnssec_nsec3resalt(kdnssec_ctx_t *ctx, knot_time_t *salt_changed, knot_time_t *when_resalt);

/*!
 * \brief When DNSSEC signing failed, re-plan on this time.
 *
 * \param ctx    zone signing context
 *
 * \return Timestamp of next signing attempt.
 */
knot_time_t knot_dnssec_failover_delay(const kdnssec_ctx_t *ctx);

/*!
 * \brief Validate zone DNSSEC based on its contents.
 *
 * \param update         Zone update with contents.
 * \param conf           Knot configuration.
 * \param incremental    Try to validate incrementally.
 *
 * \return KNOT_E*
 */
int knot_dnssec_validate_zone(zone_update_t *update, conf_t *conf, bool incremental);
