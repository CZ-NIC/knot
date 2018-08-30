/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "knot/updates/apply.h"
#include "knot/conf/conf.h"
#include "knot/updates/changesets.h"
#include "knot/zone/contents.h"
#include "knot/zone/zone.h"
#include "libknot/mm_ctx.h"

/*! \brief Structure for zone contents updating / querying. */
typedef struct zone_update {
	zone_t *zone;                /*!< Zone being updated. */
	zone_contents_t *new_cont;   /*!< New zone contents for full updates. */
	bool new_cont_deep_copy;     /*!< On update_clear, perform deep free instead of shallow. */
	changeset_t change;          /*!< Changes we want to apply. */
	apply_ctx_t *a_ctx;          /*!< Context for applying changesets. */
	uint32_t flags;              /*!< Zone update flags. */
	knot_mm_t mm;                /*!< Memory context used for intermediate nodes. */
} zone_update_t;

typedef struct {
	zone_update_t *update;          /*!< The update we're iterating over. */
	trie_it_t *tree_it;             /*!< Iterator for the new zone. */
	const zone_node_t *cur_node;    /*!< Current node in the new zone. */
	bool nsec3;                     /*!< Set when we're using the NSEC3 node tree. */
} zone_update_iter_t;

typedef enum {
	UPDATE_FULL           = 1 << 0, /*!< Replace the old zone by a complete new one. */
	UPDATE_INCREMENTAL    = 1 << 1, /*!< Apply changes to the old zone. */
	UPDATE_SIGN           = 1 << 2, /*!< Sign the resulting zone. */
	UPDATE_JOURNAL        = 1 << 3, /*!< Using zone-in-journal for a diff update. */
	UPDATE_STRICT         = 1 << 4, /*!< Apply changes strictly, i.e. fail when removing nonexistent RR. */
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
 * \brief Inits update structure, the update is built like IXFR from differences.
 *
 * The existing zone with its own contents is taken as a base,
 * the new candidate zone contents are taken as new contents,
 * the diff is calculated, so that this update is INCREMENTAL.
 *
 * \param update   Zone update structure to init.
 * \param zone     Init with this zone.
 * \param old_cont The current zone contents the diff will be against. Probably zone->contents.
 * \param new_cont New zone contents. Will be taken over (and later freed) by zone update.
 * \param flags    Flags for update. Must be UPDATE_INCREMENTAL.
 *
 * \return KNOT_E*
 */
int zone_update_from_differences(zone_update_t *update, zone_t *zone, zone_contents_t *old_cont,
                                 zone_contents_t *new_cont, zone_update_flags_t flags, bool ignore_dnssec);

/*!
 * \brief Inits a zone update based on new zone contents.
 *
 * \param update                 Zone update structure to init.
 * \param zone_without_contents  Init with this zone. Its contents may be NULL.
 * \param new_cont               New zone contents. Will be taken over (and later freed) by zone update.
 * \param flags                  Flags for update.
 *
 * \return KNOT_E*
 */
int zone_update_from_contents(zone_update_t *update, zone_t *zone_without_contents,
                              zone_contents_t *new_cont, zone_update_flags_t flags);

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
 * \param rrset   RRSet to add.
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
 * \param rrset   RRSet to remove.
 *
 * \return KNOT_E*
 */
int zone_update_remove(zone_update_t *update, const knot_rrset_t *rrset);

/*!
 * \brief Removes a whole RRSet of specified type from the zone.
 *
 * \warning Do not edit the zone_update when any iterator is active. Any
 *          zone_update modifications will invalidate the trie iterators
 *          in the zone_update iterator(s).
 *
 * \param update  Zone update.
 * \param owner   Node name to remove.
 * \param type    RRSet type to remove.
 *
 * \return KNOT_E*
 */
int zone_update_remove_rrset(zone_update_t *update, knot_dname_t *owner, uint16_t type);

/*!
 * \brief Removes a whole node from the zone.
 *
 * \warning Do not edit the zone_update when any iterator is active. Any
 *          zone_update modifications will invalidate the trie iterators
 *          in the zone_update iterator(s).
 *
 * \param update  Zone update.
 * \param owner   Node name to remove.
 *
 * \return KNOT_E*
 */
int zone_update_remove_node(zone_update_t *update, const knot_dname_t *owner);

/*!
 * \brief Adds and removes RRsets to/from the zone according to the changeset.
 *
 * \param update  Zone update.
 * \param changes Changes to be made in zone.
 *
 * \return KNOT_E*
 */
int zone_update_apply_changeset(zone_update_t *update, const changeset_t *changes);

/*!
 * \brief Applies a changeset to zone, the changeset is modified to contain only really added/removed rdata.
 *
 * \param update  Zone update.
 * \param changes In: changes to be made in zone; out: changes really made in zone.
 *
 * \return KNOT_E*
 */
int zone_update_apply_changeset_fix(zone_update_t *update, changeset_t *changes);

/*!
 * \brief Applies the changeset in reverse, rsets from REM section are added and from ADD section removed.
 *
 * \param update   Zone update.
 * \param changes  Changes to be un-done.
 *
 * \return KNOT_E*
 */
int zone_update_apply_changeset_reverse(zone_update_t *update, const changeset_t *changes);

/*!
 * \brief Increment SOA serial (according to cofigured policy) in the update.
 *
 * \param update  Update to be modified.
 * \param conf    Configuration.
 *
 * \return KNOT_E*
 */
int zone_update_increment_soa(zone_update_t *update, conf_t *conf);

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
 */
void zone_update_iter_finish(zone_update_iter_t *it);

/*!
 * \brief Returns bool whether there are any changes at all.
 *
 * \param update  Zone update.
 */
bool zone_update_no_change(zone_update_t *update);
