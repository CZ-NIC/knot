/*  Copyright (C) 2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#ifdef ENABLE_XDP

#include "knot/query/layer.h"
#include "libknot/xdp/xdp.h"

#define XDP_BATCHLEN  32 /*!< XDP receive batch size. */

struct xdp_handle_ctx;
struct server;

/*!
 * \brief Initialize XDP packet handling context.
 */
struct xdp_handle_ctx *xdp_handle_init(struct server *server, knot_xdp_socket_t *sock);

/*!
 * \brief Deinitialize XDP packet handling context.
 */
void xdp_handle_free(struct xdp_handle_ctx *ctx);

/*!
 * \brief Receive packets thru XDP socket.
 */
int xdp_handle_recv(struct xdp_handle_ctx *ctx);

/*!
 * \brief Answer packets including DNS layers.
 *
 * \warning In case of TCP, this also sends some packets, e.g. ACK.
 */
void xdp_handle_msgs(struct xdp_handle_ctx *ctx, knot_layer_t *layer,
                     struct server *server, unsigned thread_id);

/*!
 * \brief Send packets thru XDP socket.
 */
void xdp_handle_send(struct xdp_handle_ctx *ctx);

/*!
 * \brief Check for old TCP connections and close/reset them.
 */
void xdp_handle_sweep(struct xdp_handle_ctx *ctx);

/*!
 * \brief Update configuration parameters of running ctx.
 */
void xdp_handle_reconfigure(struct xdp_handle_ctx *ctx);

#endif // ENABLE_XDP
