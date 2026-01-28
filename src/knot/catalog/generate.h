/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "knot/catalog/catalog_update.h"

#define CATALOG_SOA_REFRESH	3600
#define CATALOG_SOA_RETRY	600
#define CATALOG_SOA_EXPIRE	(INT32_MAX - 1)

/*!
 * \brief Return generated catalog member record owner name.
 *
 * \param member       Member name.
 * \param catzone      Catalog zone name.
 * \param member_time  Time when the member was included in the generated catalog.
 *
 * \return Owner name or NULL.
 */
knot_dname_t *catalog_member_owner(const knot_dname_t *member, const knot_dname_t *catzone,
                                   time_t member_time);

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
