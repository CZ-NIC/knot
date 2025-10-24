/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include <stdlib.h>

#include "contrib/wire_ctx.h"
#include "libknot/dnssec/binary.h"

static inline wire_ctx_t binary_init(const dnssec_binary_t *binary)
{
	assert(binary);

	return wire_ctx_init(binary->data, binary->size);
}

static inline void binary_read(wire_ctx_t *ctx, dnssec_binary_t *data)
{
	assert(data);

	wire_ctx_read(ctx, data->data, data->size);
}

static inline void binary_available(wire_ctx_t *ctx, dnssec_binary_t *data)
{
	assert(ctx);
	assert(data);

	data->data = ctx->position;
	data->size = wire_ctx_available(ctx);
}

static inline void binary_write(wire_ctx_t *ctx, const dnssec_binary_t *data)
{
	assert(ctx);
	assert(data);

	wire_ctx_write(ctx, data->data, data->size);
}
