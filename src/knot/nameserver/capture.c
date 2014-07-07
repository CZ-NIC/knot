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

#include "knot/nameserver/capture.h"
#include "knot/server/tcp-handler.h"
#include "knot/server/udp-handler.h"

/* State-less packet capture, only incoming data is accepted. */
static int reset(knot_process_t *ctx)  { return NS_PROC_MORE; }
static int finish(knot_process_t *ctx) { return NS_PROC_NOOP; }

/* Set capture parameters (sink). */
static int begin(knot_process_t *ctx, void *module_param)
{
	ctx->data = module_param;
	return NS_PROC_MORE;
}

/* Forward packet. */
static int capture(knot_pkt_t *pkt, knot_process_t *ctx)
{
	assert(pkt && ctx);
	struct process_capture_param *param = ctx->data;

	/* Copy packet contents and free. */
	knot_pkt_copy(param->sink, pkt);
	knot_pkt_free(&pkt);

	return NS_PROC_DONE;
}

/*! \brief Module implementation. */
static const knot_process_module_t PROCESS_CAPTURE_MODULE = {
	&begin,
	&reset,
	&finish,
	&capture,
	&knot_process_noop, /* No output. */
	&knot_process_noop  /* No error processing. */
};

const knot_process_module_t *proc_capture_get_module(void)
{
	return &PROCESS_CAPTURE_MODULE;
}
