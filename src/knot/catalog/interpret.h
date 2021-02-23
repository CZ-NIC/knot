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
 * \brief Iterate over PTR records in given zone contents and add members to catalog update.
 *
 * \param u            Catalog update to be updated.
 * \param zone         Zone contents to be searched for member PTR records.
 * \param remove       Add removals of found member zones.
 * \param check_ver    Do check catalog zone version record first.
 * \param check        Optional: existing catalog database to be checked for existence
 *                     of such record (useful for removals).
 *
 * \return KNOT_E*
 */
int catalog_update_from_zone(catalog_update_t *u, struct zone_contents *zone,
                             bool remove, bool check_ver, catalog_t *check);
