/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "contrib/semaphore.h"
#include "knot/zone/contents.h"
#include "knot/updates/changesets.h"
#include "contrib/ucw/lists.h"

enum {
	APPLY_STRICT     = 1 << 0, /*!< Apply strictly, don't ignore removing non-existent RRs. */
	APPLY_UNIFY_FULL = 1 << 1, /*!< When cleaning up successful update, perform full trees nodes unify. */
};

struct apply_ctx {
	zone_contents_t *contents;
	zone_tree_t *node_ptrs;   /*!< Just pointers to the affected nodes in contents. */
	zone_tree_t *nsec3_ptrs;  /*!< The same for NSEC3 nodes. */
	zone_tree_t *adjust_ptrs; /*!< Pointers to nodes affected by adjusting. */
	uint32_t flags;
	knot_sem_t *cow_mutex;
};

typedef struct apply_ctx apply_ctx_t;

/*!
 * \brief Initialize a new context structure.
 *
 * \param ctx       Context to be initialized.
 * \param contents  Zone contents to apply changes onto.
 * \param flags     Flags to control the application process.
 *
 * \return KNOT_E*
 */
int apply_init_ctx(apply_ctx_t *ctx, zone_contents_t *contents, uint32_t flags);

/*!
 * \brief Adds a single RR into zone contents.
 *
 * \param ctx  Apply context.
 * \param rr   RRSet to add.
 *
 * \return KNOT_E*
 */
int apply_add_rr(apply_ctx_t *ctx, const knot_rrset_t *rr);

/*!
 * \brief Removes single RR from zone contents.
 *
 * \param ctx  Apply context.
 * \param rr   RRSet to remove.
 *
 * \return KNOT_E*
 */
int apply_remove_rr(apply_ctx_t *ctx, const knot_rrset_t *rr);

/*!
 * \brief Remove SOA and add a new SOA.
 *
 * \param ctx  Apply context.
 * \param rr   New SOA to be added.
 *
 * \return KNOT_E*
 */
int apply_replace_soa(apply_ctx_t *ctx, const knot_rrset_t *rr);

/*!
 * \brief Cleanups successful zone update.
 *
 * \param ctx  Context used to create the update.
 */
void apply_cleanup(apply_ctx_t *ctx);

/*!
 * \brief Rollbacks failed zone update.
 *
 * \param ctx  Context used to create the update.
 */
void apply_rollback(apply_ctx_t *ctx);

/*!
 * \brief Shallow frees zone contents - either shallow copy after failed update
 *        or original zone contents after successful update.
 *
 * \param contents  Contents to free.
 */
void update_free_zone(zone_contents_t *contents);
