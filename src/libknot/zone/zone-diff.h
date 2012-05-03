/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#ifndef _KNOT_ZONE_DIFF_H_
#define _KNOT_ZONE_DIFF_H_

#include "libknot/zone/zone-contents.h"
#include "libknot/updates/changesets.h"

/*! \brief zone1 -> zone2 */
int knot_zone_contents_diff(knot_zone_contents_t *zone1,
                            knot_zone_contents_t *zone2,
                            knot_changeset_t **changeset);

int knot_zone_diff_zones(const char *zonefile1, const char *zonefile2);
int knot_zone_diff_apply_diff_from_file(knot_zone_t *old_zone,
                                        knot_zone_t *new_zone);

#endif // _KNOT_ZONE_DIFF_H_
