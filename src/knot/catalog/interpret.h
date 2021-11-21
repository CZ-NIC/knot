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

#include "knot/catalog/catalog_update.h"

struct zone_contents;

/*!
 * \brief Validate if given zone is valid catalog.
 *
 * \param zone   Catalog zone in question.
 *
 * \retval KNOT_EZONEINVAL   Invalid version record.
 * \retval KNOT_EISRECORD    Some of single-record RRSets has multiple RRs.
 * \return KNOT_EOK          All OK.
 */
int catalog_zone_verify(const struct zone_contents *zone);

/*!
 * \brief Iterate over PTR records in given zone contents and add members to catalog update.
 *
 * \param u                  Catalog update to be updated.
 * \param zone               Zone contents to be searched for member PTR records.
 * \param complete_contents  Complete zone contents (zone might be from a changeset).
 * \param remove             Add removals of found member zones.
 * \param check              Optional: existing catalog database to be checked for existence
 *                           of such record (useful for removals).
 * \param upd_count          Output: number of resulting updates to catalog database.
 *
 * \return KNOT_E*
 */
int catalog_update_from_zone(catalog_update_t *u, struct zone_contents *zone,
                             const struct zone_contents *complete_contents,
                             bool remove, catalog_t *check, ssize_t *upd_count);
