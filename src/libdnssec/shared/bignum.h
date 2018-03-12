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
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <stdlib.h>

#include "libdnssec/binary.h"
#include "contrib/wire_ctx.h"

/*!
 * Size needed to write unsigned number in unsigned encoding.
 */
size_t bignum_size_u(const dnssec_binary_t *value);

/*!
 * Size needed to write unsigned number in signed encoding.
 *
 * Signed encoding expects the MSB to be zero.
 */
size_t bignum_size_s(const dnssec_binary_t *value);

/*!
 * Write unsigned number on a fixed width in a big-endian byte order.
 *
 * The destination size has to be set properly to accommodate used encoding.
 */
void bignum_write(wire_ctx_t *ctx, size_t width, const dnssec_binary_t *value);
