/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "knot/zone/contents.h"
#include "knot/zone/skip.h"
#include "knot/updates/changesets.h"

/*!
 * \brief Create diff between two zone trees.
 * */
int zone_contents_diff(const zone_contents_t *zone1, const zone_contents_t *zone2,
                       changeset_t *changeset, zone_skip_t *skip);

/*!
 * \brief Add diff between two zone trees into the changeset.
 */
int zone_tree_add_diff(zone_tree_t *t1, zone_tree_t *t2, changeset_t *changeset);
