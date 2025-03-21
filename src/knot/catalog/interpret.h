/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "knot/catalog/catalog_update.h"

struct zone_contents;
struct zone_diff;

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
 * \param zone_diff          Zone diff to interpret for removals and additions.
 * \param complete_contents  Complete zone contents (zone might be from a changeset).
 * \param remove             Add removals of found member zones.
 * \param check              Optional: existing catalog database to be checked for existence
 *                           of such record (useful for removals).
 * \param upd_count          Output: number of resulting updates to catalog database.
 *
 * \return KNOT_E*
 */
int catalog_update_from_zone(catalog_update_t *u, struct zone_contents *zone,
                             const struct zone_diff *zone_diff,
                             const struct zone_contents *complete_contents,
                             bool remove, catalog_t *check, ssize_t *upd_count);
