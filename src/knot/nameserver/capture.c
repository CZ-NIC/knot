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

#include "knot/nameserver/capture.h"
#include "knot/server/tcp-handler.h"
#include "knot/server/udp-handler.h"

/* State-less packet capture, only incoming data is accepted. */
static int reset(knot_layer_t *ctx)  { return KNOT_STATE_PRODUCE; }
static int finish(knot_layer_t *ctx) { return KNOT_STATE_NOOP; }

/* Set capture parameters (sink). */
static int begin(knot_layer_t *ctx, void *module_param)
{
	ctx->data = module_param;
	return reset(ctx);
}

static int prepare_query(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	/* \note Don't touch the query, expect answer. */
	return KNOT_STATE_CONSUME;
}

/* Forward packet. */
static int capture(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	assert(pkt && ctx);
	struct capture_param *param = ctx->data;

	/* Copy packet contents and free. */
	knot_pkt_copy(param->sink, pkt);

	return KNOT_STATE_DONE;
}

/*! \brief Module implementation. */
static const knot_layer_api_t CAPTURE_LAYER = {
	&begin,
	&reset,
	&finish,
	&capture,
	&prepare_query,
	NULL
};

const knot_layer_api_t *capture_get_module(void)
{
	return &CAPTURE_LAYER;
}
