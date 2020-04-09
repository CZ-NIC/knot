/*  Copyright (C) 2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <stdbool.h>
#include <poll.h>
#include <sys/socket.h>
#include "contrib/quicly/quicly.h"

/*! \brief QUIC params. */
typedef struct {
    bool enable;
} quic_params_t;

/*! \brief QUIC context. */
typedef struct {
    const quic_params_t *params;
    struct pollfd pfd;
    int wait;
    quicly_context_t quicly;
    quicly_conn_t *client;
    quicly_cid_plaintext_t cid;
} quic_ctx_t;

int quic_ctx_init(quic_ctx_t *ctx, const quic_params_t *params, int wait);

int quic_ctx_connect(quic_ctx_t *ctx, const int fd, struct sockaddr *sa, socklen_t salen);

int quic_ctx_send(quic_ctx_t *ctx, const uint8_t *buf, const size_t buflen);

int quic_ctx_receive(quic_ctx_t *ctx, uint8_t *buf, size_t buflen);

void quic_ctx_close(quic_ctx_t *ctx);