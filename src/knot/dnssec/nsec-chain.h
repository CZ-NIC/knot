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

#ifndef _KNOT_DNSSEC_NSEC_CHAIN_FIX_H_
#define _KNOT_DNSSEC_NSEC_CHAIN_FIX_H_

#include <stdbool.h>
#include <stdint.h>

#include "knot/zone/zone-contents.h"
#include "knot/updates/changesets.h"
#include "libknot/dnssec/bitmap.h"

/*!
 * \brief Parameters to be used in connect_nsec_nodes callback.
 */
typedef struct {
	uint32_t ttl;                      // TTL for NSEC(3) records
	knot_changeset_t *changeset;       // Changeset for NSEC(3) changes
	const knot_zone_contents_t *zone;  // Updated zone
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
typedef int (*chain_iterate_create_cb)(knot_node_t *, knot_node_t *,
                                       nsec_chain_iterate_data_t *);


/*!
 * \brief Add all RR types from a node into the bitmap.
 */
inline static void bitmap_add_node_rrsets(bitmap_t *bitmap,
                                          const knot_node_t *node)
{
	knot_rrset_t **node_rrsets = knot_node_create_rrsets(node);
	for (int i = 0; i < node->rrset_count; i++) {
		const knot_rrset_t *rr = node_rrsets[i];
		if (rr->type != KNOT_RRTYPE_NSEC &&
		    rr->type != KNOT_RRTYPE_RRSIG) {
			bitmap_add_type(bitmap, rr->type);
		}
	}
	knot_node_free_created_rrsets(node, node_rrsets);
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
int knot_nsec_chain_iterate_create(knot_zone_tree_t *nodes,
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
int knot_nsec_changeset_remove(const knot_node_t *n,
                               knot_changeset_t *changeset);

/*!
 * \brief Checks whether the node is empty or eventually contains only NSEC and
 *        RRSIGs.
 *
 * \param n Node to check.
 *
 * \retval true if the node is empty or contains only NSEC and RRSIGs.
 * \retval false otherwise.
 */
bool knot_nsec_empty_nsec_and_rrsigs_in_node(const knot_node_t *n);

/*!
 * \brief Create new NSEC chain, add differences from current into a changeset.
 *
 * \param zone       Zone.
 * \param ttl        TTL for created NSEC records.
 * \param changeset  Changeset the differences will be put into.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_nsec_create_chain(const knot_zone_contents_t *zone, uint32_t ttl,
                           knot_changeset_t *changeset);

#endif // _KNOT_DNSSEC_NSEC_CHAIN_FIX_H_
