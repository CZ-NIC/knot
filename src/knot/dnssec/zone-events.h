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

#include "knot/zone/zone.h"
#include "knot/updates/changesets.h"
#include "knot/dnssec/context.h"

enum zone_sign_flags {
	ZONE_SIGN_NONE = 0,
	ZONE_SIGN_DROP_SIGNATURES = (1 << 0),
	ZONE_SIGN_KEEP_SOA_SERIAL = (1 << 1),
};

typedef enum zone_sign_flags zone_sign_flags_t;

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
 * \brief DNSSEC resign zone, store new records into changeset. Valid signatures
 *        and NSEC(3) records will not be changed.
 *
 * \param zone         Zone contents to be signed.
 * \param out_ch       New records will be added to this changeset.
 * \param flags        Zone signing flags.
 * \param refresh_at   Signature refresh time of the oldest signature in zone.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_dnssec_zone_sign(zone_contents_t *zone, changeset_t *out_ch,
                          zone_sign_flags_t flags, uint32_t *refresh_at);

/*!
 * \brief Sign changeset created by DDNS or zone-diff.
 *
 * \param zone            Zone contents to be signed.
 * \param in_ch           Changeset created bvy DDNS or zone-diff
 * \param out_ch          New records will be added to this changeset.
 * \param refresh_at      Signature refresh time of the new signatures.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_dnssec_sign_changeset(const zone_contents_t *zone,
                               const changeset_t *in_ch,
                               changeset_t *out_ch,
                               uint32_t *refresh_at);
