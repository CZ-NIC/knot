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

#include <stdbool.h>

#include "knot/dnssec/context.h"
#include "knot/dnssec/zone-keys.h"
#include "knot/updates/zone-update.h"
#include "knot/zone/contents.h"

/*!
 * Check if NSEC3 is enabled for the given zone.
 *
 * \param zone  Zone to be checked.
 *
 * \return NSEC3 is enabled.
 */
inline static bool knot_is_nsec3_enabled(const zone_contents_t *zone)
{
	return zone != NULL && zone->nsec3_params.algorithm != 0;
}

inline static size_t zone_nsec3_hash_len(const zone_contents_t *zone)
{
	return knot_is_nsec3_enabled(zone) ? dnssec_nsec3_hash_length(zone->nsec3_params.algorithm) : 0;
}

inline static size_t zone_nsec3_name_len(const zone_contents_t *zone)
{
	return 1 + ((zone_nsec3_hash_len(zone) + 4) / 5) * 8 + knot_dname_size(zone->apex->owner);
}

/*!
 * \brief Create NSEC3 owner name from hash and zone apex.
 *
 * \param out        Output buffer.
 * \param out_size   Size of the output buffer.
 * \param hash       Raw hash.
 * \param hash_size  Size of the hash.
 * \param zone_apex  Zone apex.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_nsec3_hash_to_dname(uint8_t *out, size_t out_size, const uint8_t *hash,
                             size_t hash_size, const knot_dname_t *zone_apex);

/*!
 * \brief Create NSEC3 owner name from regular owner name.
 *
 * \param out        Output buffer.
 * \param out_size   Size of the output buffer.
 * \param owner      Node owner name.
 * \param zone_apex  Zone apex name.
 * \param params     Params for NSEC3 hashing function.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_create_nsec3_owner(uint8_t *out, size_t out_size,
                            const knot_dname_t *owner, const knot_dname_t *zone_apex,
                            const dnssec_nsec3_params_t *params);

/*!
 * \brief Return (and compute of needed) the corresponding NSEC3 node's name.
 *
 * \param node   Normal node.
 * \param zone   Optional: zone contents with NSEC3 params.
 *
 * \return NSEC3 node owner.
 *
 * \note The result is also stored in (node), unless zone == NULL;
 */
knot_dname_t *node_nsec3_hash(zone_node_t *node, const zone_contents_t *zone);

/*!
 * \brief Return (and compute if needed) the corresponding NSEC3 node.
 *
 * \param node   Normal node.
 * \param zone   Optional: zone contents with NSEC3 params and NSEC3 tree.
 *
 * \return NSEC3 node.
 *
 * \note The result is also stored in (node), unless zone == NULL;
 */
zone_node_t *node_nsec3_node(zone_node_t *node, const zone_contents_t *zone);

/*!
 * \brief Update node's NSEC3 pointer (or hash), taking it from bi-node counterpart if possible.
 *
 * \param node   Bi-node with this node to be updated.
 * \param zone   Zone contents the node is in.
 *
 * \return KNOT_EOK :)
 */
int binode_fix_nsec3_pointer(zone_node_t *node, const zone_contents_t *zone);

/*!
 * \brief Check if NSEC3 record in zone is consistent with configured params.
 */
bool knot_nsec3param_uptodate(const zone_contents_t *zone,
                              const dnssec_nsec3_params_t *params);

/*!
 * \brief Update NSEC3PARAM in zone to be consistent with configured params.
 *
 * \param update  Zone to be updated.
 * \param params  NSEC3 params.
 * \param ttl     Desired TTL for NSEC3PARAM.
 *
 * \return KNOT_E*
 */
int knot_nsec3param_update(zone_update_t *update,
                           const dnssec_nsec3_params_t *params,
                           uint32_t ttl);

/*!
 * \brief Create NSEC or NSEC3 chain in the zone.
 *
 * \param update          Zone Update with current zone contents and to be updated with NSEC chain.
 * \param ctx             Signing context.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_zone_create_nsec_chain(zone_update_t *update, const kdnssec_ctx_t *ctx);

/*!
 * \brief Fix NSEC or NSEC3 chain after zone was updated, and sign the changed NSECs.
 *
 * \param update           Zone Update with the update and to be update with NSEC chain.
 * \param zone_keys        Zone keys used for NSEC(3) creation.
 * \param ctx              Signing context.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_zone_fix_nsec_chain(zone_update_t *update,
                             const zone_keyset_t *zone_keys,
                             const kdnssec_ctx_t *ctx);

/*!
 * \brief Validate NSEC or NSEC3 chain in the zone.
 *
 * \param update         Zone update with current/previous contents.
 * \param ctx            Signing context.
 * \param incremental    Validate incremental update.
 *
 * \return KNOT_E*
 */
int knot_zone_check_nsec_chain(zone_update_t *update, const kdnssec_ctx_t *ctx,
                               bool incremental);
