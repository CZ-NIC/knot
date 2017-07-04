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

#include "knot/updates/changesets.h"
#include "knot/updates/zone-update.h"
#include "knot/zone/zone.h"
#include "knot/zone/contents.h"
#include "knot/dnssec/context.h"
#include "knot/dnssec/zone-events.h"
#include "knot/dnssec/zone-keys.h"

/*!
 * \brief Update zone signatures and store performed changes in update.
 *
 * Updates RRSIGs, NSEC(3)s, and DNSKEYs.
 *
 * \param update      Zone Update containing the zone and to be updated with new DNSKEYs and RRSIGs.
 * \param zone_keys   Zone keys.
 * \param dnssec_ctx  DNSSEC context.
 * \param expire_at   Time, when the oldest signature in the zone expires.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_zone_sign(zone_update_t *update,
                   zone_keyset_t *zone_keys,
                   const kdnssec_ctx_t *dnssec_ctx,
                   knot_time_t *expire_at);

/*!
 * \brief Check if zone SOA signatures are expired.
 *
 * \param zone       Zone to be signed.
 * \param zone_keys  Zone keys.
 * \param dnssec_ctx DNSSEC context.
 *
 * \return True if zone SOA signatures need update, false othewise.
 */
bool knot_zone_sign_soa_expired(const zone_contents_t *zone,
                                const zone_keyset_t *zone_keys,
                                const kdnssec_ctx_t *dnssec_ctx);

/*!
 * \brief Sign NSEC/NSEC3 nodes in changeset and update the changeset.
 *
 * \param zone_keys  Zone keys.
 * \param dnssec_ctx DNSSEC context.
 * \param changeset  Changeset to be updated.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_zone_sign_nsecs_in_changeset(const zone_keyset_t *zone_keys,
                                      const kdnssec_ctx_t *dnssec_ctx,
                                      changeset_t *changeset);

/*!
 * \brief Checks whether RRSet in a node has to be signed. Will not return
 *        true for all types that should be signed, do not use this as an
 *        universal function, it is implementation specific.
 *
 * \param node         Node containing the RRSet.
 * \param rrset        RRSet we are checking for.
 *
 * \retval true if should be signed.
 */
bool knot_zone_sign_rr_should_be_signed(const zone_node_t *node,
                                        const knot_rrset_t *rrset);

/*!
 * \brief Checks whether a DS record corresponds to a key.
 *
 * \param key   A DNSSEC key in zone.
 * \param rdata The DS record rdata.
 *
 * \return true if corresponds.
 */
bool knot_match_key_ds(zone_key_t *key,
                       const knot_rdata_t *rdata);

/*!
 * \brief Sign updates of the zone, storing new RRSIGs in this update again.
 *
 * \param update     Zone Update structure.
 * \param zone_keys  Zone keys.
 * \param dnssec_ctx DNSSEC context.
 * \param expire_at  Time, when the oldest signature in the update expires.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_zone_sign_update(zone_update_t *update,
                          zone_keyset_t *zone_keys,
                          const kdnssec_ctx_t *dnssec_ctx,
                          knot_time_t *expire_at);

/*!
 * \brief Sign the new SOA record in the Zone Update.
 *
 * The reason for having this separate is: not updating
 * SOA if everything else is unchanged. So, the procedure is
 * [refresh_DNSKEY_records]->[recreate_nsec]->[sign_zone]->
 * ->[check_unchanged]->[update_soa]->[sign_soa]
 *
 * \param update     Zone Update with new SOA and to be updated with SOA RRSIG.
 * \param zone_keys  Zone keys.
 * \param dnssec_ctx DNSSEC context.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_zone_sign_soa(zone_update_t *update,
                       const zone_keyset_t *zone_keys,
                       const kdnssec_ctx_t *dnssec_ctx);
