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
 * \file overlay.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \addtogroup query_processing
 * @{
 */

#pragma once

#include "common/lists.h"

#include "libknot/processing/layer.h"

/*! \brief Processsing overlay (list of chained FSMs). */
struct knot_overlay {
	int state;
	list_t layers;
	mm_ctx_t *mm;
};

/*!
 * \brief Initialize overlay and memory context.
 *
 * \param overlay
 * \param mm
 */
void knot_overlay_init(struct knot_overlay *overlay, mm_ctx_t *mm);

/*!
 * \brief Clear structure nad free list of layers.
 *
 * \param overlay
 */
void knot_overlay_deinit(struct knot_overlay *overlay);

/*!
 * \brief Add an overlay on top of the list and begin execution.
 *
 * \fn knot_layer_begin
 *
 * \param overlay
 * \param module
 * \param module_param
 *
 * \return KNOT_EOK or an error
 */
int knot_overlay_add(struct knot_overlay *overlay, const knot_layer_api_t *module,
                     void *module_param);

/*!
 * \brief Reset layer processing.
 *
 * \fn knot_layer_reset
 */
int knot_overlay_reset(struct knot_overlay *overlay);

/*!
 * \brief Finish layer processing.
 *
 * Allowed from states: MORE, FULL, DONE, FAIL
 *
 * \fn knot_layer_finish
 */
int knot_overlay_finish(struct knot_overlay *overlay);

/*!
 * \brief Add more data to layer processing.
 *
 * Allowed from states: MORE
 *
 * \fn knot_layer_in
 */
int knot_overlay_in(struct knot_overlay *overlay, knot_pkt_t *pkt);

/*!
 * \brief Generate output from layers.
 *
 * Allowed from states: FULL, FAIL
 *
 * \fn knot_layer_out
 */
int knot_overlay_out(struct knot_overlay *overlay, knot_pkt_t *pkt);

/*! @} */
