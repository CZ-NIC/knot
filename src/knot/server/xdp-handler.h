/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

struct xdp_handle_ctx;
struct server;

/*!
 * \brief Initialize XDP packet handling context.
 */
struct xdp_handle_ctx *xdp_handle_init(void);

/*!
 * \brief Deinitialize XDP packet handling context.
 */
void xdp_handle_free(struct xdp_handle_ctx *ctx);

/*!
 * \brief Reset XDP packet handling context.
 */
void xdp_handle_cleanup(struct xdp_handle_ctx *ctx);

/*!
 * \brief Receive packets thru XDP socket.
 */
int xdp_handle_recv(struct xdp_handle_ctx *ctx, knot_xdp_socket_t *xdp_sock);

/*!
 * \brief Answer packets including DNS layers.
 *
 * \warning In case of TCP, this also sends some packets, e.g. ACK.
 */
int xdp_handle_msgs(struct xdp_handle_ctx *ctx, knot_xdp_socket_t *sock,
                    knot_layer_t *layer, struct server *server, unsigned thread_id);

/*!
 * \brief Send packets thru XDP socket.
 */
int xdp_handle_send(struct xdp_handle_ctx *ctx, knot_xdp_socket_t *xdp_sock);

/*!
 * \brief Check for old TCP connections and close/reset them.
 */
int xdp_handle_timeout(struct xdp_handle_ctx *ctx, knot_xdp_socket_t *xdp_sock);

#endif // ENABLE_XDP
