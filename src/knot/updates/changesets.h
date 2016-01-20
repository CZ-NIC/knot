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
 * \brief Structure for representing zone change and its API.
 *
 * \addtogroup ddns
 * @{
 */

#pragma once

#include "libknot/rrset.h"
#include "knot/zone/contents.h"
#include "contrib/ucw/lists.h"

/*! \brief One zone change, from 'soa_from' to 'soa_to'. */
typedef struct {
	node_t n;                 /*!< List node. */
	knot_rrset_t *soa_from;   /*!< Start SOA. */
	knot_rrset_t *soa_to;     /*!< Destination SOA. */
	zone_contents_t *add;     /*!< Change additions. */
	zone_contents_t *remove;  /*!< Change removals. */
	list_t old_data;          /*!< Old data, to be freed after successful update. */
	list_t new_data;          /*!< New data, to be freed after failed update. */
	size_t size;              /*!< Size of serialized changeset. */
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
 * \param ch     Changeset to add RRSet into.
 * \param rrset  RRSet to be added.
 *
 * \return KNOT_E*
 */
int changeset_add_rrset(changeset_t *ch, const knot_rrset_t *rrset);

/*!
 * \brief Add RRSet to 'remove' part of changeset.
 *
 * \param ch     Changeset to add RRSet into.
 * \param rrset  RRSet to be added.
 *
 * \return KNOT_E*
 */
int changeset_rem_rrset(changeset_t *ch, const knot_rrset_t *rrset);

/*!
 * \brief Merges two changesets together. Legacy, to be removed with new zone API.
 *
 * \param ch1  Merge into this changeset.
 * \param ch2  Merge this changeset.
 *
 * \return KNOT_E*
 */
int changeset_merge(changeset_t *ch1, const changeset_t *ch2);

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
 * \param itt     Iterator to init.
 * \param ch      Changeset to use.
 * \param sorted  Sort the iteration?
 *
 * \return KNOT_E*
 */
int changeset_iter_add(changeset_iter_t *itt, const changeset_t *ch, bool sorted);

/*!
 * \brief Inits changeset iteration structure with changeset removals.
 *
 * \param itt     Iterator to init.
 * \param ch      Changeset to use.
 * \param sorted  Sort the iteration?
 *
 * \return KNOT_E*
 */
int changeset_iter_rem(changeset_iter_t *itt, const changeset_t *ch, bool sorted);

/*!
 * \brief Inits changeset iteration structure with changeset additions and removals.
 *
 * \param itt     Iterator to init.
 * \param ch      Changeset to use.
 * \param sorted  Sort the iteration?
 *
 * \return KNOT_E*
 */
int changeset_iter_all(changeset_iter_t *itt, const changeset_t *ch, bool sorted);

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

/*! @} */
