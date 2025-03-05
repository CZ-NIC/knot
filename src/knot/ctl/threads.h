/*  Copyright (C) 2025 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include "knot/ctl/process.h"

typedef struct {
	knot_ctl_t **ctls;
	server_t *server;
	dt_unit_t *unit;
	int thrs_per_sock;
} ctl_socket_ctx_t;

/*!
 * \brief Initialize CTL socket handling threads.
 *
 * \param ctx     Socket thread contexts.
 * \param n_ctls  Number of socket threads.
 *
 * \return KNOT_E*
 */
int ctl_socket_thr_init(ctl_socket_ctx_t *ctx, size_t n_ctls);

/*!
 * \brief De-initialize CTL socket handling thread.
 *
 * \param ctx     Socket thread context.
 */
void ctl_socket_thr_end(ctl_socket_ctx_t *ctx);
