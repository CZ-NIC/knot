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

#include "dnssec/event.h"

/*!
 * Generate new key with parameters from KASP policy and add it into zone.
 *
 * \param[in]  ctx  Event context.
 * \param[in]  ksk  Generate KSK key instead of ZSK key.
 * \param[out] key  Generated key, can be NULL.
 */
int generate_key(dnssec_event_ctx_t *ctx, bool ksk, dnssec_kasp_key_t **key);
