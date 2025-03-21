/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
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
