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

#include "libknot/processing/layer.h"
#include "common/debug.h"

/*! \brief Helper for conditional layer call. */
#define LAYER_CALL(layer, func, ...) \
	if (layer->api->func) { \
		layer->state = layer->api->func(layer, ##__VA_ARGS__); \
	}

/* State -> string translation table. */
#ifdef KNOT_NS_DEBUG
#define LAYER_STATE_STR(x) _state_table[x]
static const char* _state_table[] = {
        [NS_PROC_NOOP] = "NOOP",
        [NS_PROC_MORE] = "MORE",
        [NS_PROC_FULL] = "FULL",
        [NS_PROC_DONE] = "DONE",
        [NS_PROC_FAIL] = "FAIL"
};
#endif /* KNOT_NS_DEBUG */

int knot_layer_begin(knot_layer_t *ctx, const knot_layer_api_t *api, void *param)
{
	/* Only in inoperable state. */
	if (ctx->state != NS_PROC_NOOP) {
		return ctx->state;
	}

	ctx->api = api;

	LAYER_CALL(ctx, begin, param);

	dbg_ns("%s -> %s\n", __func__, LAYER_STATE_STR(ctx->state));
	return ctx->state;
}

int knot_layer_reset(knot_layer_t *ctx)
{
	LAYER_CALL(ctx, reset);
	dbg_ns("%s -> %s\n", __func__, LAYER_STATE_STR(ctx->state));
	return ctx->state;
}

int knot_layer_finish(knot_layer_t *ctx)
{
	/* Only in operable state. */
	if (ctx->state == NS_PROC_NOOP) {
		return ctx->state;
	}

	LAYER_CALL(ctx, finish);
	dbg_ns("%s -> %s\n", __func__, LAYER_STATE_STR(ctx->state));
	return ctx->state;
}

int knot_layer_in(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	/* Only if expecting data. */
	if (ctx->state != NS_PROC_MORE) {
		return ctx->state;
	}

	knot_pkt_parse(pkt, 0);

	LAYER_CALL(ctx, in, pkt);
	dbg_ns("%s -> %s\n", __func__, LAYER_STATE_STR(ctx->state));
	return ctx->state;
}

int knot_layer_out(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	switch (ctx->state) {
	case NS_PROC_FULL: LAYER_CALL(ctx, out, pkt); break;
	case NS_PROC_FAIL: LAYER_CALL(ctx, err, pkt); break;
	default:
		break;
	}

	dbg_ns("%s -> %s\n", __func__, LAYER_STATE_STR(ctx->state));
	return ctx->state;
}

#undef LAYER_STATE_STR
