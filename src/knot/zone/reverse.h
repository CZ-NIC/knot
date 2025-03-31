/*  Copyright (C) 2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "knot/updates/zone-update.h"

/*!
 * \brief Create/update reverse zone based on forward zone.
 *
 * \param from           Forward zone to be reversed.
 * \param to_conts       Out/optional: resulting reverse zone.
 * \param to_upd         Out/optional: resulting update of reverse zone.
 * \param to_upd_rem     Trigger removal from reverse zone.
 *
 * \return KNOT_E*
 */
int zone_reverse(zone_contents_t *from, zone_contents_t *to_conts,
                 zone_update_t *to_upd, bool to_upd_rem);

inline static int changeset_reverse(changeset_t *from, zone_update_t *to)
{
	int ret = zone_reverse(from->remove, NULL, to, true);
	if (ret == KNOT_EOK) {
		ret = zone_reverse(from->add, NULL, to, false);
	}
	return ret;
}

/*!
 * \brief Reverse based on multiple forward zones.
 *
 * \param zones      Ptrlist with zones to be reversed.
 * \param to_conts   Out: resulting reverse zone.
 * \param fail_fwd   Out/optional: name of a forward zone that failed.
 *
 * \retval KNOT_EAGAIN   Some of the zones are not yet loaded, try again completely later.
 * \return KNOT_E*
 */
int zones_reverse(list_t *zones, zone_contents_t *to_conts, const knot_dname_t **fail_fwd);
