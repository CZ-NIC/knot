/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <assert.h>

#include "knot/query/capture.h"

static int reset(knot_layer_t *ctx)
{
	return KNOT_STATE_PRODUCE;
}

static int finish(knot_layer_t *ctx)
{
	return KNOT_STATE_NOOP;
}

static int begin(knot_layer_t *ctx, void *module_param)
{
	ctx->data = module_param; /* struct capture_param */
	return reset(ctx);
}

static int prepare_query(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	return KNOT_STATE_CONSUME;
}

static int capture(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	assert(pkt && ctx && ctx->data);
	struct capture_param *param = ctx->data;

	knot_pkt_copy(param->sink, pkt);

	return KNOT_STATE_DONE;
}

const knot_layer_api_t *query_capture_api(void)
{
	static const knot_layer_api_t API = {
		.begin = begin,
		.reset = reset,
		.finish = finish,
		.consume = capture,
		.produce = prepare_query,
	};

	return &API;
}
