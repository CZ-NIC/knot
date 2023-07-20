/*  Copyright (C) 2023 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "contrib/sockaddr.h"

struct knot_quic_creds;
struct knot_quic_reply;

int knot_qreq_connect(struct knot_quic_reply **out,
                      int fd,
                      struct sockaddr_storage *remote,
                      struct sockaddr_storage *local,
                      const struct knot_quic_creds *local_creds,
                      const uint8_t *peer_pin,
                      uint8_t peer_pin_len,
                      bool *reused_fd,
                      int timeout_ms);

int knot_qreq_send(struct knot_quic_reply *r, const struct iovec *data);

int knot_qreq_recv(struct knot_quic_reply *r, struct iovec *out, int timeout_ms);

void knot_qreq_close(struct knot_quic_reply *r, bool send_close);
