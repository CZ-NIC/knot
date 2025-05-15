/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "contrib/sockaddr.h"
#include "libknot/quic/quic.h"

int knot_qreq_connect(struct knot_quic_reply **out,
                      int fd,
                      struct sockaddr_storage *remote,
                      struct sockaddr_storage *local,
                      const struct knot_creds *local_creds,
                      const char *peer_hostname,
                      const uint8_t *peer_pin,
                      uint8_t peer_pin_len,
                      bool *reused_fd,
                      int timeout_ms);

int knot_qreq_send(struct knot_quic_reply *r, const struct iovec *data);

int knot_qreq_recv(struct knot_quic_reply *r, struct iovec *out, int timeout_ms);

void knot_qreq_close(struct knot_quic_reply *r, bool send_close);
