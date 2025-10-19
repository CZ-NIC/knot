/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
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
