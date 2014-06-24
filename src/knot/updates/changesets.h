/*!
 * \file changesets.h
 *
 * \author Jan Kadlec <jan.kadlec@nic.cz>
 *
 * \brief Structure for representing IXFR/DDNS changeset and its API.
 *
 * \addtogroup xfr
 * @{
 */
/*  Copyright (C) 2013 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include "common/lists.h"
#include "common/mempattern.h"

/*----------------------------------------------------------------------------*/

/*! \brief One zone change, from 'soa_from' to 'soa_to'. */
typedef struct changeset {
	node_t n; /*!< List node. */
	mm_ctx_t *mm; /*!< Memory context */
	knot_rrset_t *soa_from; /*!< Start SOA. */
	zone_contents_t *add;
	zone_contents_t *remove;
	knot_rrset_t *soa_to; /*!< Destination SOA. */
	uint8_t *data; /*!< Serialized changeset. */
	size_t size; /*!< Size of serialized changeset. */
	list_t old_data; /*!< Old data, to be freed after succesfull update. */
	list_t new_data; /*!< New data, to be freed after failed update. */
} changeset_t;

typedef struct {
	list_t iters;
	const zone_node_t *node;
	int32_t node_pos;
} changeset_iter_t;

/*----------------------------------------------------------------------------*/

typedef enum {
	CHANGESET_ADD, /*!< Put RR into 'add' section. */
	CHANGESET_REMOVE /*!< Put RR into 'remove' section. */
} changeset_part_t;

/*----------------------------------------------------------------------------*/

changeset_t *changeset_new(mm_ctx_t *mm, const knot_dname_t *apex);
void changeset_init(changeset_t *ch, const knot_dname_t *apex, mm_ctx_t *mm);

/*!
 * \brief Add RRSet to changeset. RRSet is either inserted to 'add' or to
 *        'remove' list. Will *not* try to merge with previous RRSets.
 *
 * \param chgs Changeset to add RRSet into.
 * \param rrset RRSet to be added.
 * \param part Add to 'add' or 'remove'?
 *
 * \retval KNOT_EOK on success.
 * \retval Error code on failure.
 */
int changeset_add_rrset(changeset_t *ch, const knot_rrset_t *rrset);
int changeset_rem_rrset(changeset_t *ch, const knot_rrset_t *rrset);

/*!
 * \brief Checks whether changeset is empty.
 *
 * Changeset is considered empty if it has no RRs in REMOVE and ADD sections and
 * final SOA (soa_to) is not set.
 *
 * \param changeset Changeset to be checked.
 *
 * \retval true if changeset is empty.
 * \retval false if changeset is not empty.
 */
bool changeset_empty(const changeset_t *ch);

/*!
 * \brief Get number of changes (additions and removals) in the changeset.
 *
 * \param changeset Changeset to be checked.
 *
 * \return Number of changes in the changeset.
 */
size_t changeset_size(const changeset_t *ch);

/*!
 * \brief Frees the 'changesets' structure, including all its internal data.
 *
 * \param changesets  Double pointer to changesets structure to be freed.
 * \param mm          Memory context used to allocate RRSets.
 */
void changesets_free(list_t *chgs, mm_ctx_t *rr_mm);
void changeset_clear(changeset_t *ch, mm_ctx_t *rr_mm);

int changeset_merge(changeset_t *ch1, changeset_t *ch2);
changeset_iter_t *changeset_iter_add(const changeset_t *ch, bool sorted);
changeset_iter_t *changeset_iter_rem(const changeset_t *ch, bool sorted);
changeset_iter_t *changeset_iter_all(const changeset_t *ch, bool sorted);
knot_rrset_t changeset_iter_next(changeset_iter_t *it);
void changeset_iter_free(changeset_iter_t *it, mm_ctx_t *mm);

/*! @} */
