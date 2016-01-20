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
 * \brief Changesets application and update helpers.
 *
 * \addtogroup ddns
 * @{
 */

#pragma once

#include "knot/zone/zone.h"
#include "knot/updates/changesets.h"
#include "contrib/ucw/lists.h"

/*!
 * \brief Applies changesets *with* zone shallow copy.
 *
 * \param zone          Zone to be updated.
 * \param chsets        Changes to be made.
 * \param new_contents  New zone will be returned using this arg.
 *
 * \return KNOT_E*
 */
int apply_changesets(zone_t *zone, list_t *chsets,
                     zone_contents_t **new_contents);

/*!
 * \brief Applies changeset *with* zone shallow copy.
 *
 * \param zone          Zone to be updated.
 * \param ch            Change to be made.
 * \param new_contents  New zone will be returned using this arg.
 *
 * \return KNOT_E*
 */
int apply_changeset(zone_t *zone, changeset_t *ch,
                    zone_contents_t **new_contents);

/*!
 * \brief Applies changesets directly to the zone, without copying it.
 *
 * \param contents Zone contents to apply the changesets to. Will be modified.
 * \param chsets   Changesets to be applied to the zone.
 *
 * \return KNOT_E*
 */
int apply_changesets_directly(zone_contents_t *contents, list_t *chsets);

/*!
 * \brief Applies changeset directly to the zone, without copying it.
 *
 * \param contents Zone contents to apply the changesets to. Will be modified.
 * \param chsets   Changeset to be applied to the zone.
 *
 * \return KNOT_E*
 */
int apply_changeset_directly(zone_contents_t *contents, changeset_t *ch);

/*!
 * \brief Cleanups successful zone updates.

 * \param chgs  Changesets used to create the update.
 */
void updates_cleanup(list_t *chgs);

/*!
 * \brief Cleanups successful zone update.

 * \param chgs  Changeset used to create the update.
 */
void update_cleanup(changeset_t *change);

/*!
 * \brief Rollbacks failed zone updates.
 *
 * \param chgs   Changesets used to create the update.
 */
void updates_rollback(list_t *chgs);

/*!
 * \brief Rollbacks failed zone update.
 *
 * \param chgs   Changeset. used to create the update.
 */
void update_rollback(changeset_t *change);

/*!
 * \brief Shallow frees zone contents - either shallow copy after failed update
 *        or original zone contents after successful update.
 *
 * \param contents  Contents to free.
 */
void update_free_zone(zone_contents_t **contents);

/*! @} */
