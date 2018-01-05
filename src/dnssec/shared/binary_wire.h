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

#include "contrib/wire_ctx.h"
#include "binary.h"

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
