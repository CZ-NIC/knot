/*!
 * \file process.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \addtogroup query_processing
 * @{
 */
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

#pragma once

#include <stdint.h>

#include "common/mempattern.h"
#include "libknot/consts.h"
#include "libknot/rrtype/tsig.h"
#include "libknot/packet/pkt.h"

/*! \brief Main packet processing states.
 *         Each state describes the current machine processing step
 *         and determines readiness for next action.
 */

enum knot_process_state {
	NS_PROC_NOOP = 0,      /* N/A */
	NS_PROC_MORE = 1 << 0, /* More input data. */
	NS_PROC_FULL = 1 << 1, /* Has output data. */
	NS_PROC_DONE = 1 << 2, /* Finished. */
	NS_PROC_FAIL = 1 << 3  /* Error. */
};

/* Forward declarations. */
struct knot_process_module;

/*! \brief Packet processing context. */
typedef struct knot_process_context
{
	uint16_t state;  /* Bitmap of enum knot_process_state. */
	uint16_t type;   /* Module identifier. */
	mm_ctx_t mm;     /* Processing memory context. */

	/* Module specific. */
	void *data;
	const struct knot_process_module *module;
} knot_process_t;

/*! \brief Packet processing module API. */
typedef struct knot_process_module {
	int (*begin)(knot_process_t *ctx, void *module_param);
	int (*reset)(knot_process_t *ctx);
	int (*finish)(knot_process_t *ctx);
	int (*in)(knot_pkt_t *pkt, knot_process_t *ctx);
	int (*out)(knot_pkt_t *pkt, knot_process_t *ctx);
	int (*err)(knot_pkt_t *pkt, knot_process_t *ctx);
} knot_process_module_t;

/*!
 * \brief Initialize packet processing context.
 *
 * Allowed from states: NOOP
 *
 * \param ctx Context.
 * \param module_param Parameters for given module.
 * \param module Module API.
 * \return (module specific state)
 */
int knot_process_begin(knot_process_t *ctx, void *module_param, const knot_process_module_t *module);

/*!
 * \brief Reset current packet processing context.
 * \param ctx Context.
 * \return (module specific state)
 */
int knot_process_reset(knot_process_t *ctx);

/*!
 * \brief Finish and close packet processing context.
 *
 * Allowed from states: MORE, FULL, DONE, FAIL
 *
 * \param ctx Context.
 * \return (module specific state)
 */
int knot_process_finish(knot_process_t *ctx);

/*!
 * \brief Input more data into packet processing.
 *
 * Allowed from states: MORE
 *
 * \param wire Source data.
 * \param wire_len Source data length.
 * \param ctx Context.
 * \return (module specific state)
 */
int knot_process_in(const uint8_t *wire, uint16_t wire_len, knot_process_t *ctx);

/*!
 * \brief Write out output from packet processing.
 *
 * Allowed from states: FULL, FAIL
 *
 * \param wire Destination.
 * \param wire_len Destination length.
 * \param ctx Context.
 * \return (module specific state)
 */
int knot_process_out(uint8_t *wire, uint16_t *wire_len, knot_process_t *ctx);

/*! @} */
