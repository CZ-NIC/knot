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

int knot_process_in(knot_layer_t *ctx, const uint8_t *wire, uint16_t wire_len)
{
	knot_pkt_t *pkt = knot_pkt_new((uint8_t *)wire, wire_len, ctx->mm);
	knot_pkt_parse(pkt, 0);

	return knot_layer_in(ctx, pkt);
}

int knot_process_out(knot_layer_t *ctx, uint8_t *wire, uint16_t *wire_len)
{
	knot_pkt_t *pkt = knot_pkt_new(wire, *wire_len, ctx->mm);

	ctx->state = knot_layer_out(ctx, pkt);

	/* Accept only finished result. */
	if (ctx->state != NS_PROC_FAIL) {
		*wire_len = pkt->size;
	} else {
		*wire_len = 0;
	}

	knot_pkt_free(&pkt);
	return ctx->state;
}
