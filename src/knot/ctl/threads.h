/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "knot/ctl/process.h"

typedef struct {
	knot_ctl_t **ctls;
	server_t *server;
	dt_unit_t *unit;
	unsigned thr_count;
} ctl_socket_ctx_t;

/*!
 * \brief Initialize CTL socket handling threads.
 *
 * \param ctx         Socket thread contexts.
 * \param sock_count  Number of socket threads.
 *
 * \return KNOT_E*
 */
int ctl_socket_thr_init(ctl_socket_ctx_t *ctx, unsigned sock_count);

/*!
 * \brief De-initialize CTL socket handling threads.
 *
 * \param ctx     Socket thread context.
 */
void ctl_socket_thr_end(ctl_socket_ctx_t *ctx);
