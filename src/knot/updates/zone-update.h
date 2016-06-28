/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
 * \file
 *
 * \brief API for quering zone that is being updated.
 *
 * \addtogroup ddns
 * @{
 */

#pragma once

#include "knot/updates/apply.h"
#include "knot/conf/conf.h"
#include "knot/updates/changesets.h"
#include "knot/zone/contents.h"
#include "knot/zone/zone.h"
#include "libknot/mm_ctx.h"

/*! \brief Structure for zone contents updating / querying. */
typedef struct {
	zone_t *zone;                /*!< Zone being updated. */
	zone_contents_t *new_cont;   /*!< New zone contents for full updates. */
	changeset_t change;          /*!< Changes we want to apply. */
	apply_ctx_t a_ctx;           /*!< Context for applying changesets. */
	uint32_t flags;              /*!< Zone update flags. */
	knot_mm_t mm;                /*!< Memory context used for intermediate nodes. */
} zone_update_t;

typedef struct {
	zone_update_t *update;          /*!< The update we're iterating over. */
	hattrie_iter_t *base_it;        /*!< Iterator for the original zone in the case of INCREMENTAL update or the new zone in case of FULL update. */
	hattrie_iter_t *add_it;         /*!< Iterator for the added nodes in the changeset. Available in the INCREMENTAL update only. */
	const zone_node_t *base_node;   /*!< The original node (INCREMENTAL update) or new node (FULL update). */
	const zone_node_t *add_node;    /*!< The additions to that node (INCREMENTAL update only). */
	const zone_node_t *next_node;   /*!< The smaller of t_node and ch_node (INCREMENTAL update) or next new node (FULL update). */
	bool nsec3;                     /*!< Set when we're using the NSEC3 node tree. */
} zone_update_iter_t;

typedef enum {
	UPDATE_FULL           = 1 << 0, /*!< Replace the old zone by a complete new one. */
	UPDATE_INCREMENTAL    = 1 << 1, /*!< Apply changes to the old zone. */
	UPDATE_SIGN           = 1 << 2, /*!< Sign the resulting zone. */
	UPDATE_DIFF           = 1 << 3, /*!< In the case of full update, create a diff for journal. */
} zone_update_flags_t;

/*!
 * \brief Inits given zone update structure, new memory context is created.
 *
 * \param update  Zone update structure to init.
 * \param zone    Init with this zone.
 * \param flags   Flags to control the behavior of the update.
 *
 * \return KNOT_E*
 */
int zone_update_init(zone_update_t *update, zone_t *zone, zone_update_flags_t flags);

/*!
 * \brief Returns node that would be in the zone after updating it.
 *
 * \note Returned node is either zone original or synthesized, do *not* free
 *       or modify. Returned node is allocated on local mempool.
 *
 * \param update  Zone update.
 * \param dname   Dname to search for.
 *
 * \return   Node after zone update.
 */
const zone_node_t *zone_update_get_node(zone_update_t *update,
                                        const knot_dname_t *dname);

/*!
 * \brief Returns updated zone apex.
 *
 * \note Returned node is either zone original or synthesized, do *not* free
 *       or modify.
 *
 * \param update  Zone update.
 *
 * \return   Returns apex after update.
 */
const zone_node_t *zone_update_get_apex(zone_update_t *update);

/*!
 * \brief Returns the serial from the current apex.
 *
 * \param update  Zone update.
 *
 * \return   0 if no apex was found, its serial otherwise.
 */
uint32_t zone_update_current_serial(zone_update_t *update);

/*!
 * \brief Returns the SOA rdataset we're updating from.
 *
 * \param update  Zone update.
 *
 * \return   The original SOA rdataset.
 */
const knot_rdataset_t *zone_update_from(zone_update_t *update);

/*!
 * \brief Returns the SOA rdataset we're updating to.
 *
 * \param update  Zone update.
 *
 * \return   NULL if no new SOA has been added, new SOA otherwise.
 */
const knot_rdataset_t *zone_update_to(zone_update_t *update);

/*!
 * \brief Clear data allocated by given zone update structure.
 *
 * \param  update Zone update to clear.
 */
void zone_update_clear(zone_update_t *update);

/*!
 * \brief Adds an RRSet to the zone.
 *
 * \warning Do not edit the zone_update when any iterator is active. Any
 *          zone_update modifications will invalidate the trie iterators
 *          in the zone_update iterator(s).
 *
 * \param update  Zone update.
 *
 * \return KNOT_E*
 */
int zone_update_add(zone_update_t *update, const knot_rrset_t *rrset);

/*!
 * \brief Removes an RRSet from the zone.
 *
 * \warning Do not edit the zone_update when any iterator is active. Any
 *          zone_update modifications will invalidate the trie iterators
 *          in the zone_update iterator(s).
 *
 * \param update  Zone update.
 *
 * \return KNOT_E*
 */
int zone_update_remove(zone_update_t *update, const knot_rrset_t *rrset);

/*!
 * \brief Commits all changes to the zone, signs it, saves changes to journal.
 *
 * \param conf          Configuration.
 * \param update        Zone update.
 *
 * \return KNOT_E*
 */
int zone_update_commit(conf_t *conf, zone_update_t *update);

/*!
 * \brief Setup a zone_update iterator for both FULL and INCREMENTAL updates.
 *
 * \warning Do not init or use iterators when the zone is edited. Any
 *          zone_update modifications will invalidate the trie iterators
 *          in the zone_update iterator.
 *
 * \param it       Iterator.
 * \param update   Zone update.
 *
 * \return KNOT_E*
 */
int zone_update_iter(zone_update_iter_t *it, zone_update_t *update);

/*!
 * \brief Setup a zone_update iterator for both FULL and INCREMENTAL updates.
 *        Version for iterating over nsec3 nodes.
 *
 * \warning Do not init or use iterators when the zone is edited. Any
 *          zone_update modifications will invalidate the trie iterators
 *          in the zone_update iterator.
 *
 *
 * \param it       Iterator.
 * \param update   Zone update.
 *
 * \return KNOT_E*
 */
int zone_update_iter_nsec3(zone_update_iter_t *it, zone_update_t *update);

/*!
 * \brief Move the iterator to the next item.
 *
 * \param it  Iterator.
 *
 * \return KNOT_E*
 */
int zone_update_iter_next(zone_update_iter_t *it);

/*!
 * \brief Get the value of the iterator.
 *
 * \param it  Iterator.
 *
 * \return A (synthesized or added) node with all its current data.
 */
const zone_node_t *zone_update_iter_val(zone_update_iter_t *it);

/*!
 * \brief Finish the iterator and clean it up.
 *
 * \param it  Iterator.
 *
 * \return KNOT_E*
 */
int zone_update_iter_finish(zone_update_iter_t *it);

/*!
 * \brief Returns bool whether there are any changes at all.
 *
 * \param update  Zone update.
 */
bool zone_update_no_change(zone_update_t *up);

/*! @} */
