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
/*!
 * \file process.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \addtogroup query_processing
 * @{
 */

#pragma once

#include <stdint.h>

#include "libknot/processing/layer.h"

/* The functions below wrap regular layer operation. */

/*! \note See \fn knot_layer_begin */
#define knot_process_begin(args...) knot_layer_begin(args)
/*! \note See \fn knot_layer_reset */
#define knot_process_reset(args...) knot_layer_reset(args)
/*! \note See \fn knot_layer_finish */
#define knot_process_finish(args...) knot_layer_finish(args)

/*!
 * \brief Input more data into data processing.
 *
 * Allowed from states: MORE
 *
 * \param wire Source data.
 * \param wire_len Source data length.
 * \param ctx Context.
 * \return (module specific state)
 */
int knot_process_in(knot_layer_t *ctx, const uint8_t *wire, uint16_t wire_len);

/*!
 * \brief Generate output from data processing.
 *
 * Allowed from states: FULL, FAIL
 *
 * \param wire Destination.
 * \param wire_len Destination length.
 * \param ctx Context.
 * \return (module specific state)
 */
int knot_process_out(knot_layer_t *ctx, uint8_t *wire, uint16_t *wire_len);

/*! @} */
