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

#define CATALOG_SOA_REFRESH	3600
#define CATALOG_SOA_RETRY	600
#define CATALOG_SOA_EXPIRE	(INT32_MAX - 1)

struct knot_zonedb;

/*!
 * \brief Compare old and new zonedb, create incremental catalog upd in each catz->cat_members
 */
void catalogs_generate(struct knot_zonedb *db_new, struct knot_zonedb *db_old);

struct zone_contents;

/*!
 * \brief Generate catalog zone contents from (full) catalog update.
 *
 * \param u           Catalog update to read.
 * \param catzone     Catalog zone name.
 * \param soa_serial  SOA serial of the generated zone.
 *
 * \return Catalog zone contents, or NULL if ENOMEM.
 */
struct zone_contents *catalog_update_to_zone(catalog_update_t *u, const knot_dname_t *catzone,
                                             uint32_t soa_serial);

struct zone_update;

/*!
 * \brief Incrementally update catalog zone from catalog update.
 *
 * \param u    Catalog update to read.
 * \param zu   Zone update to be updated.
 *
 * \return KNOT_E*
 */
int catalog_update_to_update(catalog_update_t *u, struct zone_update *zu);
