/*  Copyright (C) 2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "knot/updates/changesets.h"
#include "knot/updates/zone-update.h"
#include "knot/zone/contents.h"
#include "knot/dnssec/context.h"
#include "knot/dnssec/zone-keys.h"

int rrset_add_zone_key(knot_rrset_t *rrset, zone_key_t *zone_key);

bool rrsig_covers_type(const knot_rrset_t *rrsig, uint16_t type);

/*!
 * \brief Prepare DNSKEYs, CDNSKEYs and CDSs to be added to the zone into rrsets.
 *
 * \param zone_keys     Zone keyset.
 * \param dnssec_ctx    KASP context.
 * \param add_r         RRSets to be added.
 *
 * \return KNOT_E*
 */
int knot_zone_sign_add_dnskeys(zone_keyset_t *zone_keys, const kdnssec_ctx_t *dnssec_ctx,
			       key_records_t *add_r);

/*!
 * \brief Adds/removes DNSKEY (and CDNSKEY, CDS) records to zone according to zone keyset.
 *
 * \param update     Structure holding zone contents and to be updated with changes.
 * \param zone_keys  Keyset with private keys.
 * \param dnssec_ctx KASP context.
 *
 * \return KNOT_E*
 */
int knot_zone_sign_update_dnskeys(zone_update_t *update,
                                  zone_keyset_t *zone_keys,
                                  kdnssec_ctx_t *dnssec_ctx,
                                  knot_time_t *next_resign);

/*!
 * \brief Check if key can be used to sign given RR.
 *
 * \param key      Zone key.
 * \param covered  RR to be checked.
 *
 * \return The RR should be signed.
 */
bool knot_zone_sign_use_key(const zone_key_t *key, const knot_rrset_t *covered);

/*!
 * \brief Return those keys for whose the CDNSKEY/CDS records shall be created.
 *
 * \param ctx        DNSSEC context.
 * \param zone_keys  Zone keyset, including ZSKs.
 *
 * \return Dynarray containing pointers on some KSKs in keyset.
 */
keyptr_dynarray_t knot_zone_sign_get_cdnskeys(const kdnssec_ctx_t *ctx,
					      zone_keyset_t *zone_keys);

/*!
 * \brief Check that at least one correct signature exists to at least one DNSKEY and that none incorrect exists.
 *
 * \param covered        RRSet bein validated.
 * \param rrsigs         RRSIG with signatures.
 * \param sign_ctx       Signing context (with keys == NULL)
 * \param skip_crypto    Crypto operations might be skipped as they had been successful earlier.
 *
 * \return KNOT_E*
 */
int knot_validate_rrsigs(const knot_rrset_t *covered,
                         const knot_rrset_t *rrsigs,
                         zone_sign_ctx_t *sign_ctx,
                         bool skip_crypto);

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
                                      zone_update_t *update);

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
 * \brief Force re-sign of a RRSet in zone apex.
 *
 * \param update        Zone update to be updated.
 * \param rrtype        Type of the apex RR.
 * \param zone_keys     Zone keyset.
 * \param dnssec_ctx    DNSSEC context.
 *
 * \return KNOT_E*
 */
int knot_zone_sign_apex_rr(zone_update_t *update, uint16_t rrtype,
                           const zone_keyset_t *zone_keys,
                           const kdnssec_ctx_t *dnssec_ctx);
