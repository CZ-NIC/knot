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
 * \author Jan Kadlec <jan.kadlec@nic.cz> (chain fix)
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

/*!
 * \brief Parameters to be used when fixing NSEC(3) chain.
 */
typedef struct chain_fix_data {
	const knot_zone_contents_t *zone;     // Zone to fix
	knot_changeset_t *out_ch;             // Outgoing changes
	const knot_dname_t *chain_start;      // Possible new starting node
	bool old_connected;                   // Marks old start connection
	const knot_dname_t *last_used_dname;  // Last dname used in chain
	const knot_node_t *last_used_node;    // Last covered node used in chain
	knot_dname_t *next_dname;             // Used to reconnect broken chain
	const hattrie_t *sorted_changes;      // Iterated trie
	uint32_t ttl;                         // TTL for NSEC(3) records
} chain_fix_data_t;

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
	NSEC_NODE_RESET = 2
};
/*!
 * \brief Callback used when fixing NSEC chains.
 */
typedef int (*chain_iterate_fix_cb)(knot_dname_t *, knot_dname_t *,
                                    knot_dname_t *, knot_dname_t *,
                                    chain_fix_data_t *);
/*!
 * \brief Callback used when finalizing NSEC chains.
 */
typedef int (*chain_finalize_cb)(chain_fix_data_t *);

/*!
 * \brief Callback used when creating NSEC chains.
 */
typedef int (*chain_iterate_create_cb)(knot_node_t *, knot_node_t *,
                                       nsec_chain_iterate_data_t *);

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
 * \brief Iterates sorted changeset and calls callback function - works for
 *        NSEC and NSEC3 chain.
 *
 * \note If the callback function returns anything other than KNOT_EOK, the
 *       iteration is terminated and the error code is propagated.
 *
 * \param  nodes     Tree to fix.
 * \param  callback  Callback to call.
 * \param  finalize  Finalization callback.
 * \param  data      Data needed for fixing.
 *
 * \return KNOT_E*
 */
int knot_nsec_chain_iterate_fix(hattrie_t *nodes,
                                chain_iterate_fix_cb callback,
                                chain_finalize_cb finalize,
                                chain_fix_data_t *data);

/*!
 * \brief Add entry for removed NSEC to the changeset.
 *
 * \param oldrr      Old NSEC RR set to be removed (including RRSIG).
 * \param changeset  Changeset to add the old RR into.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_nsec_changeset_remove(const knot_rrset_t *oldrr,
                               knot_changeset_t *changeset);

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

/*!
 * \brief Fixes NSEC chain after DDNS/reload
 *
 * \param sorted_changes  Sorted changes created by changeset sign function.
 * \param fix_data        Chain fix data.
 *
 * \return KNOT_E*
 */
int knot_nsec_fix_chain(hattrie_t *sorted_changes,
                        chain_fix_data_t *fix_data);


#endif // _KNOT_DNSSEC_NSEC_CHAIN_FIX_H_
