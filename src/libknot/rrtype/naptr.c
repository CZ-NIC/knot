/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <assert.h>
#include <stdint.h>

#include "libknot/attribute.h"
#include "libknot/rrtype/naptr.h"
#include "contrib/wire_ctx.h"

_public_
int knot_naptr_header_size(const uint8_t *naptr, const uint8_t *maxp)
{
	if (!naptr || !maxp || naptr >= maxp) {
		return KNOT_EINVAL;
	}

	wire_ctx_t wire = wire_ctx_init_const(naptr, maxp - naptr);

	/* Fixed fields size (order, preference) */
	wire_ctx_skip(&wire, 2 * sizeof(uint16_t));

	/* Variable fields size (flags, services, regexp) */
	for (int i = 0; i < 3; i++) {
		uint8_t size = wire_ctx_read_u8(&wire);
		wire_ctx_skip(&wire, size);
	}

	if (wire.error != KNOT_EOK) {
		return KNOT_EMALF;
	}

	return wire_ctx_offset(&wire);
}
