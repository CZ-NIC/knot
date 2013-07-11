/*!
 * \file changesets.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>, Jan Kadlec <jan.kadlec@nic.cz>
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
#include "common/lists.h"
#include "common/mempattern.h"

/*----------------------------------------------------------------------------*/

/*! \brief Changeset flags, stored as first 4 bytes in serialized changeset. */
typedef enum {
	KNOT_CHANGESET_TYPE_IXFR = 1 << 0,
	KNOT_CHANGESET_TYPE_DDNS = 1 << 1
} knot_changeset_flag_t;


/*! \brief One changeset received from wire, with parsed RRs. */
typedef struct knot_changeset {
	node n; /*!< List node. */
	mm_ctx_t mem_ctx; /*!< Memory context - pool allocator. */
	knot_rrset_t *soa_from; /*!< Start SOA. */
	list remove; /*!< List of RRs to remove. */

	knot_rrset_t *soa_to; /*!< Destination SOA. */
	list add; /*!< List of RRs to add. */

	uint8_t *data; /*!< Serialized changeset. */
	size_t size; /*!< Size of serialized changeset. */
	uint32_t serial_from; /*!< SOA start serial. */
	uint32_t serial_to; /*!< SOA destination serial. */

	uint32_t flags; /*!< DDNS / IXFR flags. */
} knot_changeset_t;

/*----------------------------------------------------------------------------*/

/*! \brief Wrapper for oh-so-great BIRD lists. */
typedef struct knot_rr_node {
	node n; /*!< List node. */
	knot_rrset_t *rr; /*!< Actual usable data. */
} knot_rr_node_t;

/*! \brief Partial changes done to zones - used for update/transfer rollback. */
typedef struct {
	/*!
	 * Memory context. We need a pool allocator since there is a possibility
	 * of many changes in one transfer/update.
	 */
	mm_ctx_t mem_ctx;
	/*!
	 * Deleted after successful update.
	 */
	list old_rrsets;

	/*!
	 * Deleted after failed update.
	 */
	list new_rrsets;

	/*!
	 * Deleted (without contents) after successful update.
	 */
	list old_nodes;
	/*!
	 * Deleted (without contents) after successful update.
	 */
	list old_nsec3;
} knot_changes_t;

/*----------------------------------------------------------------------------*/

typedef struct {
	mm_ctx_t mem_ctx; /*!< Memory context - pool allocator. */
	list sets; /*!< List of changesets. */
	size_t count; /*!< Changeset coung. */
	knot_rrset_t *first_soa; /*!< First received SOA. */
	uint32_t flags; /*!< DDNS / IXFR flags. */
	knot_changes_t *changes; /*!< Partial changes. */
} knot_changesets_t;

/*----------------------------------------------------------------------------*/

typedef enum {
	KNOT_CHANGESET_ADD,
	KNOT_CHANGESET_REMOVE
} knot_changeset_part_t;

/*----------------------------------------------------------------------------*/

int knot_changesets_init(knot_changesets_t **changesets,
                        uint32_t flags);

knot_changesets_t *knot_changesets_create(uint32_t flags);

knot_changeset_t *knot_changesets_create_changeset(knot_changesets_t *ch);

int knot_changeset_add_rrset(knot_changeset_t *chgs,
                             knot_rrset_t *rrset, knot_changeset_part_t part);

int knot_changeset_add_rr(knot_changeset_t *chgs,
                          knot_rrset_t *rrset, knot_changeset_part_t part);

void knot_changeset_store_soa(knot_rrset_t **chg_soa,
                              uint32_t *chg_serial, knot_rrset_t *soa);

int knot_changeset_add_soa(knot_changeset_t *changeset, knot_rrset_t *soa,
                           knot_changeset_part_t part);

int knot_changesets_check_size(knot_changesets_t *changesets);

void knot_changeset_set_flags(knot_changeset_t *changeset,
                             uint32_t flags);

uint32_t knot_changeset_flags(knot_changeset_t *changeset);

int knot_changeset_is_empty(const knot_changeset_t *changeset);

void knot_free_changesets(knot_changesets_t **changesets);

int knot_changes_rrsets_reserve(knot_rrset_t ***rrsets,
                                int *count, int *allocated, int to_add);

int knot_changes_nodes_reserve(knot_node_t ***nodes,
                               int *count, int *allocated);

int knot_changes_rdata_reserve(knot_rrset_t ***rdatas,
                               int count, int *allocated, int to_add);

void knot_changes_add_rdata(knot_rrset_t **rdatas, int *count,
                            knot_rrset_t *rrset);

int knot_changes_add_rrsets(const knot_rrset_t **from, size_t count,
                            knot_rrset_t **to, int proc_sigs);

#endif /* _KNOT_CHANGESETS_H_ */

/*! @} */
