/*!
 * \file changesets.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Structure for representing IXFR/DDNS changeset and its API.
 *
 * \addtogroup xfr
 * @{
 */
/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#ifndef _KNOT_CHANGESETS_H_
#define _KNOT_CHANGESETS_H_

#include "rrset.h"
#include "zone/node.h"

/*! \todo Changeset must be serializable/deserializable, so
 *        all data and pointers have to be changeset-exclusive,
 *        or more advanced structure serialization scheme has to be
 *        implemented.
 *
 * \todo Preallocation of space for changeset.
 */
typedef struct {
	knot_rrset_t *soa_from;
	knot_rrset_t **remove;
	size_t remove_count;
	size_t remove_allocated;

	knot_rrset_t *soa_to;
	knot_rrset_t **add;
	size_t add_count;
	size_t add_allocated;

	uint8_t *data;
	size_t size;
	size_t allocated;
	uint32_t serial_from;
	uint32_t serial_to;
} knot_changeset_t;

/*----------------------------------------------------------------------------*/

typedef struct {
	/*!
	 * Deleted (without owners and RDATA) after successful update.
	 */
	knot_rrset_t **old_rrsets;
	int old_rrsets_count;
	int old_rrsets_allocated;

	/*!
	 * Deleted after successful update.
	 */
	knot_rdata_t **old_rdata;
	unsigned *old_rdata_types;
	int old_rdata_count;
	int old_rdata_allocated;

	/*!
	 * \brief Copied RRSets (i.e. modified by the update).
	 *
	 * Deleted (without owners and RDATA) after failed update.
	 */
	knot_rrset_t **new_rrsets;
	int new_rrsets_count;
	int new_rrsets_allocated;

	/*!
	 * Deleted after failed update.
	 */
	knot_rdata_t **new_rdata;
	unsigned *new_rdata_types;
	int new_rdata_count;
	int new_rdata_allocated;

	/*!
	 * Deleted (without contents) after successful update.
	 */
	knot_node_t **old_nodes;
	int old_nodes_count;
	int old_nodes_allocated;

	knot_node_t **old_nsec3;
	int old_nsec3_count;
	int old_nsec3_allocated;
} knot_changes_t;

/*----------------------------------------------------------------------------*/

typedef struct {
	knot_changeset_t *sets;
	size_t count;
	size_t allocated;
	knot_rrset_t *first_soa;
	knot_changes_t *changes;
} knot_changesets_t;

/*----------------------------------------------------------------------------*/

typedef enum {
	XFRIN_CHANGESET_ADD,
	XFRIN_CHANGESET_REMOVE
} xfrin_changeset_part_t;

/*----------------------------------------------------------------------------*/

int knot_changeset_allocate(knot_changesets_t **changesets);

int knot_changeset_add_rrset(knot_rrset_t ***rrsets,
                             size_t *count, size_t *allocated,
                             knot_rrset_t *rrset);

int knot_changeset_add_rr(knot_rrset_t ***rrsets, size_t *count,
                          size_t *allocated, knot_rrset_t *rr);

int knot_changeset_add_new_rr(knot_changeset_t *changeset,
                              knot_rrset_t *rrset,
                              xfrin_changeset_part_t part);

void knot_changeset_store_soa(knot_rrset_t **chg_soa,
                              uint32_t *chg_serial, knot_rrset_t *soa);

int knot_changeset_add_soa(knot_changeset_t *changeset, knot_rrset_t *soa,
                           xfrin_changeset_part_t part);

int knot_changesets_check_size(knot_changesets_t *changesets);

void knot_free_changeset(knot_changeset_t **changeset);

void knot_free_changesets(knot_changesets_t **changesets);

#endif /* _KNOT_CHANGESETS_H_ */

/*! @} */
