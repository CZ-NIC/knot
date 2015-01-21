/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#pragma once

#include "dnssec/kasp.h"

typedef bool (*key_match_cb)(const dnssec_kasp_key_t *key, void *data);

/*!
 * Get latest matching key for a zone.
 */
dnssec_kasp_key_t *last_matching_key(dnssec_kasp_zone_t *zone,
				     key_match_cb match_cb, void *data);

/*!
 * Check if zone has KSK and ZSK key.
 */
void zone_check_ksk_and_zsk(dnssec_kasp_zone_t *zone,
			    bool *has_ksk, bool *has_zsk);
