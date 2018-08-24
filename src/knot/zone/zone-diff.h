/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "knot/zone/contents.h"
#include "knot/updates/changesets.h"

/*!
 * \brief Create diff between two zone trees.
 * */
int zone_contents_diff(const zone_contents_t *zone1, const zone_contents_t *zone2,
                       changeset_t *changeset, bool ignore_dnssec);

/*!
 * \brief Add diff between two zone trees into the changeset.
 */
int zone_tree_add_diff(zone_tree_t *t1, zone_tree_t *t2, changeset_t *changeset);
