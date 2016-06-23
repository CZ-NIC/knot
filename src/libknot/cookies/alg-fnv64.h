/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "libknot/cookies/client.h"
#include "libknot/cookies/server.h"

/*!
 * \brief FNV-64 client cookie algorithm.
 */
extern const struct knot_cc_alg knot_cc_alg_fnv64;

/*!
 * \brief FNV-64 server hash algorithm.
 *
 * \note The algorithm expects a nonce value, time stamp and hash value.
 */
extern const struct knot_sc_alg knot_sc_alg_fnv64;
