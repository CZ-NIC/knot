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

#include "libknot/processing/process.h"
#include "common/debug.h"

/* State -> string translation table. */
#ifdef KNOT_NS_DEBUG
#define PROCESSING_STATE_STR(x) _state_table[x]
static const char* _state_table[] = {
        [NS_PROC_NOOP] = "NOOP",
        [NS_PROC_MORE] = "MORE",
        [NS_PROC_FULL] = "FULL",
        [NS_PROC_DONE] = "DONE",
        [NS_PROC_FAIL] = "FAIL"
};
#endif /* KNOT_NS_DEBUG */

int knot_process_begin(knot_process_t *ctx, void *module_param, const knot_process_module_t *module)
{
	/* Only in inoperable state. */
	if (ctx->state != NS_PROC_NOOP) {
		return NS_PROC_NOOP;
	}

#ifdef KNOT_NS_DEBUG
	/* Check module API. */
	assert(module->begin);
	assert(module->in);
	assert(module->out);
	assert(module->err);
	assert(module->reset);
	assert(module->finish);
#endif /* KNOT_NS_DEBUG */

	ctx->module = module;
	ctx->state = module->begin(ctx, module_param);

	dbg_ns("%s -> %s\n", __func__, PROCESSING_STATE_STR(ctx->state));
	return ctx->state;
}

int knot_process_reset(knot_process_t *ctx)
{
	ctx->state = ctx->module->reset(ctx);
	dbg_ns("%s -> %s\n", __func__, PROCESSING_STATE_STR(ctx->state));
	return ctx->state;
}

int knot_process_finish(knot_process_t *ctx)
{
	/* Only in operable state. */
	if (ctx->state == NS_PROC_NOOP) {
		return NS_PROC_NOOP;
	}

	ctx->state = ctx->module->finish(ctx);
	dbg_ns("%s -> %s\n", __func__, PROCESSING_STATE_STR(ctx->state));
	return ctx->state;
}

int knot_process_in(const uint8_t *wire, uint16_t wire_len, knot_process_t *ctx)
{
	/* Only if expecting data. */
	if (ctx->state != NS_PROC_MORE) {
		return NS_PROC_NOOP;
	}

	knot_pkt_t *pkt = knot_pkt_new((uint8_t *)wire, wire_len, &ctx->mm);
	knot_pkt_parse(pkt, 0);

	ctx->state = ctx->module->in(pkt, ctx);
	dbg_ns("%s -> %s\n", __func__, PROCESSING_STATE_STR(ctx->state));
	return ctx->state;
}

int knot_process_out(uint8_t *wire, uint16_t *wire_len, knot_process_t *ctx)
{
	knot_pkt_t *pkt = knot_pkt_new(wire, *wire_len, &ctx->mm);

	switch (ctx->state) {
	case NS_PROC_FULL: ctx->state = ctx->module->out(pkt, ctx); break;
	case NS_PROC_FAIL: ctx->state = ctx->module->err(pkt, ctx); break;
	default:
		assert(0); /* Improper use. */
		knot_pkt_free(&pkt);
		return NS_PROC_NOOP;
	}

	/* Accept only finished result. */
	if (ctx->state != NS_PROC_FAIL) {
		*wire_len = pkt->size;
	} else {
		*wire_len = 0;
	}

	knot_pkt_free(&pkt);

	dbg_ns("%s -> %s\n", __func__, PROCESSING_STATE_STR(ctx->state));
	return ctx->state;
}

#undef PROCESSING_STATE_STR
