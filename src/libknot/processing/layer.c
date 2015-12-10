/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <assert.h>

#include "libknot/attribute.h"
#include "libknot/processing/layer.h"

/*! \brief Helper for conditional layer call. */
#define LAYER_CALL(layer, func, ...) \
	assert(layer->api); \
	if (layer->api->func) { \
		layer->state = layer->api->func(layer, ##__VA_ARGS__); \
	}

_public_
int knot_layer_begin(knot_layer_t *ctx, const knot_layer_api_t *api, void *param)
{
	ctx->api = api;

	LAYER_CALL(ctx, begin, param);

	return ctx->state;
}

_public_
int knot_layer_reset(knot_layer_t *ctx)
{
	LAYER_CALL(ctx, reset);
	return ctx->state;
}

_public_
int knot_layer_finish(knot_layer_t *ctx)
{
	LAYER_CALL(ctx, finish);
	return ctx->state;
}

_public_
int knot_layer_consume(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	LAYER_CALL(ctx, consume, pkt);
	return ctx->state;
}

_public_
int knot_layer_produce(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	switch (ctx->state) {
	case KNOT_STATE_FAIL: LAYER_CALL(ctx, fail, pkt); break;
	case KNOT_STATE_PRODUCE:
	default: LAYER_CALL(ctx, produce, pkt); break;
	}

	return ctx->state;
}

#undef LAYER_STATE_STR
