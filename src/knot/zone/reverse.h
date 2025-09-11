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
 * \param method         Including mode.
 *
 * \return KNOT_E*
 */
int zone_reverse(zone_contents_t *from, zone_contents_t *to_conts,
                 zone_update_t *to_upd, bool to_upd_rem,
                 zone_include_method_t method);

inline static int changeset_reverse(changeset_t *from, zone_update_t *to)
{
	int ret = zone_reverse(from->remove, NULL, to, true, ZONE_INCLUDE_REVERSE);
	if (ret == KNOT_EOK) {
		ret = zone_reverse(from->add, NULL, to, false, ZONE_INCLUDE_REVERSE);
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
