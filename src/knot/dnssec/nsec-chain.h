/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
/*!
 * \file nsec-chain.h
 *
 * \author Jan Vcelak <jan.vcelak@nic.cz> (chain creation)
 *
 * \brief NSEC chain fix and creation.
 *
 * \addtogroup dnssec
 * @{
 */

#pragma once

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>

#include "knot/zone/contents.h"
#include "knot/updates/changesets.h"
#include "dnssec/nsec.h"

/*!
 * \brief Parameters to be used in connect_nsec_nodes callback.
 */
typedef struct {
	uint32_t ttl;			// TTL for NSEC(3) records
	bool cds_in_apex;		// Marks presence of CDS&CDNSKEY records in apex.
	changeset_t *changeset;		// Changeset for NSEC(3) changes
	const zone_contents_t *zone;	// Updated zone
} nsec_chain_iterate_data_t;

/*!
 * \brief Used to control changeset iteration functions.
 */
enum {
	NSEC_NODE_SKIP = 1,
};

/*!
 * \brief Callback used when creating NSEC chains.
 */
typedef int (*chain_iterate_create_cb)(zone_node_t *, zone_node_t *,
                                       nsec_chain_iterate_data_t *);

/*!
 * \brief Add all RR types from a node into the bitmap.
 */
inline static void bitmap_add_node_rrsets(dnssec_nsec_bitmap_t *bitmap,
                                          enum knot_rr_type nsec_type,
                                          const zone_node_t *node)
{
	bool deleg = node->flags & NODE_FLAGS_DELEG;
	bool apex = node->parent == NULL;
	for (int i = 0; i < node->rrset_count; i++) {
		knot_rrset_t rr = node_rrset_at(node, i);
		if (deleg && (rr.type != KNOT_RRTYPE_NS && rr.type != KNOT_RRTYPE_DS)) {
			continue;
		}
		if (rr.type == KNOT_RRTYPE_NSEC || rr.type == KNOT_RRTYPE_RRSIG) {
			continue;
		}
		// NSEC3PARAM in zone apex is maintained automatically
		if (apex && rr.type == KNOT_RRTYPE_NSEC3PARAM && nsec_type != KNOT_RRTYPE_NSEC3) {
			continue;
		}

		dnssec_nsec_bitmap_add(bitmap, rr.type);
	}
}

/*!
 * \brief Call a function for each piece of the chain formed by sorted nodes.
 *
 * \note If the callback function returns anything other than KNOT_EOK, the
 *       iteration is terminated and the error code is propagated.
 *
 * \param nodes     Zone nodes.
 * \param callback  Callback function.
 * \param data      Custom data supplied to the callback function.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_nsec_chain_iterate_create(zone_tree_t *nodes,
                                   chain_iterate_create_cb callback,
                                   nsec_chain_iterate_data_t *data);

/*!
 * \brief Add entry for removed NSEC(3) and its RRSIG to the changeset.
 *
 * \param n          Node to extract NSEC(3) from.
 * \param changeset  Changeset to add the old RR into.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_nsec_changeset_remove(const zone_node_t *n,
                               changeset_t *changeset);

/*!
 * \brief Checks whether the node is empty or eventually contains only NSEC and
 *        RRSIGs.
 *
 * \param n Node to check.
 *
 * \retval true if the node is empty or contains only NSEC and RRSIGs.
 * \retval false otherwise.
 */
bool knot_nsec_empty_nsec_and_rrsigs_in_node(const zone_node_t *n);

/*!
 * \brief Create new NSEC chain, add differences from current into a changeset.
 *
 * \param zone       Zone.
 * \param ttl        TTL for created NSEC records.
 * \param cds_in_apexHint to guess apex node type bitmap: false=just DNSKEY, true=DNSKEY,CDS,CDNSKEY.
 * \param changeset  Changeset the differences will be put into.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_nsec_create_chain(const zone_contents_t *zone, uint32_t ttl, bool cds_in_apex,
                           changeset_t *changeset);
