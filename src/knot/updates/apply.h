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

#include "knot/zone/contents.h"
#include "knot/updates/changesets.h"
#include "contrib/ucw/lists.h"

enum {
	APPLY_STRICT = 1 << 0,    /* Apply strictly, don't ignore removing non-existent RRs. */
};

struct apply_ctx {
	zone_contents_t *contents;
	list_t old_data;          /*!< Old data, to be freed after successful update. */
	list_t new_data;          /*!< New data, to be freed after failed update. */
	uint32_t flags;
};

typedef struct apply_ctx apply_ctx_t;

/*!
 * \brief Initialize a new context structure.
 *
 * \param ctx       Context to be initialized.
 * \param contents  Zone contents to apply changes onto.
 * \param flags     Flags to control the application process.
 */
void apply_init_ctx(apply_ctx_t *ctx, zone_contents_t *contents, uint32_t flags);

/*!
 * \brief Creates a shallow zone contents copy.
 *
 * \param old_contents  Source.
 * \param new_contents  Target.
 *
 * \return KNOT_E*
 */
int apply_prepare_zone_copy(zone_contents_t *old_contents,
                            zone_contents_t **new_contents);

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
 * \brief Adds a single RR into zone contents.
 *
 * \param ctx  Apply context.
 * \param ch   Changeset to be applied to the zone.
 *
 * \return KNOT_E*
 */
int apply_replace_soa(apply_ctx_t *ctx, const changeset_t *ch);

/*!
 * \brief Prepares the new zone contents for signing.
 *
 * Adjusted pointers are required for DNSSEC.
 *
 * \param ctx  Apply context.
 *
 * \return KNOT_E*
 */
int apply_prepare_to_sign(apply_ctx_t *ctx);

/*!
 * \brief Applies changesets to a shallow zone-copy.
 *
 * \param ctx           Apply context.
 * \param old_contents  Zone to be updated.
 * \param chsets        List of changesets to be applied.
 * \param new_contents  Storage for the new zone contents pointer.
 *
 * \return KNOT_E*
 */
int apply_changesets(apply_ctx_t *ctx, zone_contents_t *old_contents,
                     list_t *chsets, zone_contents_t **new_contents);

/*!
 * \brief Applies changeset to a shallow zone-copy.
 *
 * \param ctx           Apply context.
 * \param old_contents  Zone to be updated.
 * \param ch            Changeset to be applied.
 * \param new_contents  Storage for the new zone contents pointer.
 *
 * \return KNOT_E*
 */
int apply_changeset(apply_ctx_t *ctx, zone_contents_t *old_contents,
                    changeset_t *ch, zone_contents_t **new_contents);

/*!
 * \brief Applies changesets directly to the zone, without copying it.
 *
 * \warning Modified zone is in inconsitent state after error and should be freed.
 *
 * \param ctx     Apply context.
 * \param chsets  List of changesets to be applied to the zone.
 *
 * \return KNOT_E*
 */
int apply_changesets_directly(apply_ctx_t *ctx, list_t *chsets);

/*!
 * \brief Applies changeset directly to the zone, without copying it.
 *
 * \param ctx  Apply context.
 * \param ch   Changeset to be applied to the zone.
 *
 * \return KNOT_E*
 */
int apply_changeset_directly(apply_ctx_t *ctx, const changeset_t *ch);

/*!
 * \brief Finalizes the zone contents for publishing.
 *
 * Fully adjusts the zone.
 *
 * \param ctx  Apply context.
 *
 * \return KNOT_E*
 */
int apply_finalize(apply_ctx_t *ctx);

/*!
 * \brief Cleanups successful zone update.
 *
 * \param ctx  Context used to create the update.
 */
void update_cleanup(apply_ctx_t *ctx);

/*!
 * \brief Rollbacks failed zone update.
 *
 * \param ctx  Context used to create the update.
 */
void update_rollback(apply_ctx_t *ctx);

/*!
 * \brief Shallow frees zone contents - either shallow copy after failed update
 *        or original zone contents after successful update.
 *
 * \param contents  Contents to free.
 */
void update_free_zone(zone_contents_t **contents);
