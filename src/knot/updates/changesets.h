/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <stdio.h>

#include "libknot/rrset.h"
#include "knot/zone/contents.h"
#include "contrib/ucw/lists.h"

/*! \brief Changeset addition/removal flags */
typedef enum {
	CHANGESET_NONE = 0,
	CHANGESET_CHECK = 1 << 0, /*! Perform redundancy check on additions/removals */
	CHANGESET_CHECK_CANCELOUT = 1 << 1, /*! Do the complete cancelout on addition/removal/merge (depends on CHANGESET_CHECK */
} changeset_flag_t;

/*! \brief One zone change, from 'soa_from' to 'soa_to'. */
typedef struct {
	node_t n;                 /*!< List node. */
	knot_rrset_t *soa_from;   /*!< Start SOA. */
	knot_rrset_t *soa_to;     /*!< Destination SOA. */
	zone_contents_t *add;     /*!< Change additions. */
	zone_contents_t *remove;  /*!< Change removals. */
	size_t size;              /*!< Size of serialized changeset. \todo Remove after old_journal removal! */
	uint8_t *data;            /*!< Serialized changeset. */
} changeset_t;

/*! \brief Changeset iteration structure. */
typedef struct {
	list_t iters;             /*!< List of pending zone iterators. */
	zone_tree_t *trees[4];    /*!< Poiters to zone trees to iterate over. */
	size_t n_trees;           /*!< Their count. */
	zone_tree_it_t it;        /*!< Zone tree iterator. */
	const zone_node_t *node;  /*!< Current zone node. */
	uint16_t node_pos;        /*!< Position in node. */
} changeset_iter_t;

/*!
 * \brief Inits changeset structure.
 *
 * \param ch    Changeset to init.
 * \param apex  Zone apex DNAME.
 *
 * \return KNOT_E*
 */
int changeset_init(changeset_t *ch, const knot_dname_t *apex);

/*!
 * \brief Creates new changeset structure and inits it.
 *
 * \param apex  Zone apex DNAME.
 *
 * \return Changeset structure on success, NULL on errors.
 */
changeset_t *changeset_new(const knot_dname_t *apex);

/*!
 * \brief Checks whether changeset is empty, i.e. no change will happen after its application.
 *
 * \param ch  Changeset to be checked.
 *
 * \retval true if changeset is empty.
 * \retval false if changeset is not empty.
 */
bool changeset_empty(const changeset_t *ch);

/*!
 * \brief Get number of changes (additions and removals) in the changeset.
 *
 * \param ch  Changeset to be checked.
 *
 * \return Number of changes in the changeset.
 */
size_t changeset_size(const changeset_t *ch);

/*!
 * \brief Add RRSet to 'add' part of changeset.
 *
 * \param ch     Changeset to add RRSet into.
 * \param rrset  RRSet to be added.
 * \param flags  Changeset flags.
 *
 * \return KNOT_E*
 */
int changeset_add_addition(changeset_t *ch, const knot_rrset_t *rrset, changeset_flag_t flags);

/*!
 * \brief Add RRSet to 'remove' part of changeset.
 *
 * \param ch     Changeset to add RRSet into.
 * \param rrset  RRSet to be added.
 * \param flags  Changeset flags.
 *
 * \return KNOT_E*
 */
int changeset_add_removal(changeset_t *ch, const knot_rrset_t *rrset, changeset_flag_t flags);


/*!
 * \brief Remove an RRSet from the 'add' part of changeset.
 *
 * \param ch                Changeset to add RRSet into.
 * \param rrset             RRSet to be added.
 *
 * \return KNOT_E*
 */
int changeset_remove_addition(changeset_t *ch, const knot_rrset_t *rrset);

/*!
 * \brief Remove an RRSet from the 'remove' part of changeset.
 *
 * \param ch                Changeset to add RRSet into.
 * \param rrset             RRSet to be added.
 *
 * \return KNOT_E*
 */
int changeset_remove_removal(changeset_t *ch, const knot_rrset_t *rrset);

/*!
 * \brief Merges two changesets together.
 *
 * \param ch1  Merge into this changeset.
 * \param ch2  Merge this changeset.
 * \param flags  Flags how to handle rendundancies.
 *
 * \return KNOT_E*
 */
int changeset_merge(changeset_t *ch1, const changeset_t *ch2, int flags);

/*!
 * \brief Get serial "from" of the changeset.
 *
 * \param ch   Changeset in question.
 *
 * \return Its serial "from", or 0 if none.
 */
uint32_t changeset_from(const changeset_t *ch);

/*!
 * \brief Get serial "to" of the changeset.
 *
 * \param ch   Changeset in question.
 *
 * \return Its serial "to", or 0 if none.
 */
uint32_t changeset_to(const changeset_t *ch);

/*!
 * \brief Remove from changeset those rdata which won't be added/removed from zone.
 *
 * \param zone  The zone the changeset is going to be applied on.
 * \param ch    The cheangeset to be fixed.
 *
 * \return KNOT_E*
 */
int changeset_preapply_fix(const zone_contents_t *zone, changeset_t *ch);

/*!
 * \brief Remove from changeset records which are removed and added the same.
 *
 * \param ch  Changeset to be fixed.
 *
 * \return KNOT_E*
 */
int changeset_cancelout(changeset_t *ch);

/*!
 * \brief Check the changes and SOA, ignoring possibly updated SOA serial.
 *
 * \note Also tolerates changed RRSIG of SOA.
 *
 * \param ch  Changeset in question.
 *
 * \retval false  If the changeset changes other records than SOA, or some SOA field
 *                other than serial changed.
 * \retval true   Otherwise.
 */
bool changeset_differs_just_serial(const changeset_t *ch);

/*!
 * \brief Clears changesets in list. Changesets are not free'd. Legacy.
 *
 * \param chgs  Changeset list to clear.
 */
void changesets_clear(list_t *chgs);

/*!
 * \brief Free changesets in list. Legacy.
 *
 * \param chgs  Changeset list to free.
 */
void changesets_free(list_t *chgs);

/*!
 * \brief Clear single changeset.
 *
 * \param ch  Changeset to clear.
 */
void changeset_clear(changeset_t *ch);

/*!
 * \brief Copy changeset to newly allocated space, all rrsigs are copied.
 *
 * \param ch  Changeset to be copied.
 *
 * \return a copy, or NULL if error.
 */
changeset_t *changeset_clone(const changeset_t *ch);

/*!
 * \brief Frees single changeset.
 *
 * \param ch  Changeset to free.
 */
void changeset_free(changeset_t *ch);

/*!
 * \brief Inits changeset iteration structure with changeset additions.
 *
 * \param itt  Iterator to init.
 * \param ch   Changeset to use.
 *
 * \return KNOT_E*
 */
int changeset_iter_add(changeset_iter_t *itt, const changeset_t *ch);

/*!
 * \brief Inits changeset iteration structure with changeset removals.
 *
 * \param itt  Iterator to init.
 * \param ch   Changeset to use.
 *
 * \return KNOT_E*
 */
int changeset_iter_rem(changeset_iter_t *itt, const changeset_t *ch);

/*!
 * \brief Inits changeset iteration structure with changeset additions and removals.
 *
 * \param itt  Iterator to init.
 * \param ch   Changeset to use.
 *
 * \return KNOT_E*
 */
int changeset_iter_all(changeset_iter_t *itt, const changeset_t *ch);

/*!
 * \brief Gets next RRSet from changeset iterator.
 *
 * \param it  Changeset iterator.
 *
 * \return Next RRSet in iterator, empty RRSet if iteration done.
 */
knot_rrset_t changeset_iter_next(changeset_iter_t *it);

/*!
 * \brief Free resources allocated by changeset iterator.
 *
 * \param it  Iterator to clear.
 */
void changeset_iter_clear(changeset_iter_t *it);

/*!
 * \brief A pointer type for callback for changeset_walk() function.
 *
 * \param rrset    An actual removal/addition inside the changeset.
 * \param addition Indicates addition against removal.
 * \param ctx      A context passed to the changeset_walk() function.
 *
 * \retval KNOT_EOK if all ok, iteration will continue
 * \return KNOT_E*  if error, iteration will stop immediately and changeset_walk() returns this error.
 */
typedef int (*changeset_walk_callback)(const knot_rrset_t *rrset, bool addition, void *ctx);

/*!
 * \brief Calls a callback for each removal/addition in the changeset.
 *
 * \param changeset Changeset.
 * \param callback  Callback.
 * \param ctx       Arbitrary context passed to the callback.
 *
 * \return KNOT_E*
 */
int changeset_walk(const changeset_t *changeset, changeset_walk_callback callback, void *ctx);

/*!
 *
 * \brief Dumps the changeset into text file.
 *
 * \param changeset Changeset.
 * \param outfile   File to write into.
 * \param color     Use unix tty color metacharacters.
 */
void changeset_print(const changeset_t *changeset, FILE *outfile, bool color);
