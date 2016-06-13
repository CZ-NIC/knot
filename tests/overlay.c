/*  Copyright (C) 2013 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <tap/basic.h>
#include <string.h>
#include <stdlib.h>

#include "contrib/mempattern.h"
#include "contrib/ucw/mempool.h"
#include "knot/query/overlay.h"
#include "libknot/errcode.h"

/* @note Purpose of this test is to verify, that FSM chaining works. */

#define transition(expect, generate) \
{ \
	if (ctx->state != expect) { \
		return KNOT_STATE_FAIL; \
	} else { \
		return generate; \
	} \
}

static int fsm1_begin(knot_layer_t *ctx, void *param)
transition(KNOT_STATE_NOOP, KNOT_STATE_NOOP)
static int fsm1_in(knot_layer_t *ctx, knot_pkt_t *pkt)
transition(KNOT_STATE_CONSUME, KNOT_STATE_CONSUME)
static int fsm1_reset(knot_layer_t *ctx)
transition(KNOT_STATE_DONE, KNOT_STATE_DONE)
static int fsm1_out(knot_layer_t *ctx, knot_pkt_t *pkt)
transition(KNOT_STATE_PRODUCE, KNOT_STATE_FAIL)
static int fsm1_finish(knot_layer_t *ctx)
transition(KNOT_STATE_DONE, KNOT_STATE_DONE)

static int fsm2_begin(knot_layer_t *ctx, void *param)
transition(KNOT_STATE_NOOP, KNOT_STATE_CONSUME)
static int fsm2_in(knot_layer_t *ctx, knot_pkt_t *pkt)
transition(KNOT_STATE_CONSUME, KNOT_STATE_DONE)
static int fsm2_reset(knot_layer_t *ctx)
transition(KNOT_STATE_DONE, KNOT_STATE_PRODUCE)
static int fsm2_out(knot_layer_t *ctx, knot_pkt_t *pkt)
transition(KNOT_STATE_FAIL, KNOT_STATE_DONE)
static int fsm2_finish(knot_layer_t *ctx)
transition(KNOT_STATE_DONE, KNOT_STATE_NOOP)

const knot_layer_api_t fsm1_module = {
        &fsm1_begin, &fsm1_reset, &fsm1_finish, &fsm1_in, &fsm1_out, &fsm1_out
};
const knot_layer_api_t fsm2_module = {
        &fsm2_begin, &fsm2_reset, &fsm2_finish, &fsm2_in, &fsm2_out, &fsm2_out
};

/* Test implementations. */

int main(int argc, char *argv[])
{
	plan_lazy();

	knot_mm_t mm;
	mm_ctx_mempool(&mm, MM_DEFAULT_BLKSIZE);

	knot_pkt_t *buf = knot_pkt_new(NULL, 512, &mm);
	knot_pkt_put_question(buf, (const uint8_t *)"", 0, 0);

	/* Initialize overlay. */
	struct knot_overlay overlay;
	int ret = knot_overlay_init(&overlay, &mm);
	ok(ret == KNOT_EOK, "overlay: init");

	/* Add FSMs. */
	knot_overlay_add(&overlay, &fsm1_module, NULL);
	knot_overlay_add(&overlay, &fsm2_module, NULL);

	/* Run the sequence. */
	int state = knot_overlay_consume(&overlay, buf);
	is_int(KNOT_STATE_DONE, state, "overlay: in");
	state = knot_overlay_reset(&overlay);
	is_int(KNOT_STATE_PRODUCE, state, "overlay: reset");
	state = knot_overlay_produce(&overlay, buf);
	is_int(KNOT_STATE_DONE, state, "overlay: out");
	state = knot_overlay_finish(&overlay);
	is_int(KNOT_STATE_NOOP, state, "overlay: finish");

	/* Cleanup. */
	knot_overlay_deinit(&overlay);
	mp_delete((struct mempool *)mm.ctx);

	return 0;
}
