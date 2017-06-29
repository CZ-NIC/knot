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

#include "libknot/rrset.h"
#include "knot/zone/contents.h"
#include "contrib/ucw/lists.h"

/*! \brief Changeset addition/removal flags */
enum {
	CHANGESET_NONE = 0,
	CHANGESET_CHECK = 1 << 0, /*! Perform redundancy check on additions/removals */
};

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
 * \param changeset  Changeset to be checked.
 *
 * \retval true if changeset is empty.
 * \retval false if changeset is not empty.
 */
bool changeset_empty(const changeset_t *ch);

/*!
 * \brief Get number of changes (additions and removals) in the changeset.
 *
 * \param changeset  Changeset to be checked.
 *
 * \return Number of changes in the changeset.
 */
size_t changeset_size(const changeset_t *ch);

/*!
 * \brief Add RRSet to 'add' part of changeset.
 *
 * \param ch                Changeset to add RRSet into.
 * \param rrset             RRSet to be added.
 * \param check_redundancy  Check the added RR for redundancy already in the changeset.
 *
 * \return KNOT_E*
 */
int changeset_add_addition(changeset_t *ch, const knot_rrset_t *rrset, unsigned flags);

/*!
 * \brief Add RRSet to 'remove' part of changeset.
 *
 * \param ch                Changeset to add RRSet into.
 * \param rrset             RRSet to be added.
 * \param check_redundancy  Check the added RR for redundancy already in the changeset.
 *
 * \return KNOT_E*
 */
int changeset_add_removal(changeset_t *ch, const knot_rrset_t *rrset, unsigned flags);


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
 *
 * \return KNOT_E*
 */
int changeset_merge(changeset_t *ch1, const changeset_t *ch2);

/*!
 * \brief Remove from changeset those rdata which won't be added/removed from zone.
 *
 * \param zone    The zone the changeset is going to be applied on.
 * \param change  The cheangeset to be fixed.
 *
 * \return KNOT_E*
 */
int changeset_preapply_fix(const zone_contents_t *zone, changeset_t *change);

/*!
 * \brief Remove from changeset records which are removed and added the same.
 *
 * \param change  Changeset to be fixed.
 *
 * \return KNOT_E*
 */
int changeset_cancelout(changeset_t *change);

/*!
 * \brief Loads zone contents from botstrap changeset.
 *
 * \param ch  Changeset to load from, will be freed!
 *
 * \return Zone contents.
 */
zone_contents_t *changeset_to_contents(changeset_t *ch);

/*!
 * \brief Creates a bootstrap changeset from zone.
 *
 * \param contents  Contents to include, will be freed!
 *
 * \return Changeset, which shall be freed with changeset_from_contents_free()
 */
changeset_t *changeset_from_contents(const zone_contents_t *contents);

/*!
 * \brief Frees single changeset.
 *
 * \param ch  Changeset from changeset_from_contents() to free.
 */
void changeset_from_contents_free(changeset_t *ch);

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
