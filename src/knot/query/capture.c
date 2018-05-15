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
	assert(pkt && ctx && ctx->data);
	struct capture_param *param = ctx->data;

	// Restore to original QNAME if requested.
	if (param->orig_qname != NULL && param->orig_qname[0] != '\0') {
		memcpy(pkt->wire + KNOT_WIRE_HEADER_SIZE,
		       param->orig_qname, pkt->qname_size);
	}

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
