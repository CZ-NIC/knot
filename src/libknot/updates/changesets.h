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

/*----------------------------------------------------------------------------*/

/*! \brief Changeset flags, stored as first 4 bytes in serialized changeset. */
typedef enum {
	KNOT_CHANGESET_TYPE_IXFR = 1 << 0,
	KNOT_CHANGESET_TYPE_DDNS = 1 << 1
} knot_changeset_flag_t;

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

	uint32_t flags;  /*!< DDNS / IXFR */
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
	uint16_t *old_rdata_types;
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
	uint16_t *new_rdata_types;
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
	uint32_t flags;
	knot_changes_t *changes;
} knot_changesets_t;

/*----------------------------------------------------------------------------*/

typedef enum {
	KNOT_CHANGESET_ADD,
	KNOT_CHANGESET_REMOVE
} knot_changeset_part_t;

/*----------------------------------------------------------------------------*/

int knot_changeset_allocate(knot_changesets_t **changesets,
                            uint32_t flags);

int knot_changeset_add_rrset(knot_rrset_t ***rrsets,
                             size_t *count, size_t *allocated,
                             knot_rrset_t *rrset);

int knot_changeset_add_rr(knot_rrset_t ***rrsets, size_t *count,
                          size_t *allocated, knot_rrset_t *rr);

int knot_changeset_add_new_rr(knot_changeset_t *changeset,
                              knot_rrset_t *rrset,
                              knot_changeset_part_t part);

knot_rrset_t *knot_changeset_remove_rr(knot_rrset_t **rrsets, size_t *count,
                                       int pos);

void knot_changeset_store_soa(knot_rrset_t **chg_soa,
                              uint32_t *chg_serial, knot_rrset_t *soa);

int knot_changeset_add_soa(knot_changeset_t *changeset, knot_rrset_t *soa,
                           knot_changeset_part_t part);

int knot_changesets_check_size(knot_changesets_t *changesets);

void knot_changeset_set_flags(knot_changeset_t *changeset,
                             uint32_t flags);

uint32_t knot_changeset_flags(knot_changeset_t *changeset);

int knot_changeset_is_empty(const knot_changeset_t *changeset);

void knot_free_changeset(knot_changeset_t **changeset);

void knot_free_changesets(knot_changesets_t **changesets);

int knot_changes_rrsets_reserve(knot_rrset_t ***rrsets,
                                int *count, int *allocated, int to_add);

int knot_changes_nodes_reserve(knot_node_t ***nodes,
                               int *count, int *allocated);

int knot_changes_rdata_reserve(knot_rdata_t ***rdatas, uint16_t **types,
                               int count, int *allocated, int to_add);

void knot_changes_add_rdata(knot_rdata_t **rdatas, uint16_t *types,
                            int *count, knot_rdata_t *rdata, uint16_t type);

/*!
 * \note Also processes RRSIGs. May be switched by a parameter later, if needed.
 */
int knot_changes_add_old_rrsets(knot_rrset_t **rrsets, int count,
                                knot_changes_t *changes, int add_rdata);

int knot_changes_add_new_rrsets(knot_rrset_t **rrsets, int count,
                                knot_changes_t *changes, int add_rdata);

#endif /* _KNOT_CHANGESETS_H_ */

/*! @} */
