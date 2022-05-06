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

#include "contrib/libngtcp2/ngtcp2/ngtcp2.h"
#include "contrib/libngtcp2/ngtcp2/ngtcp2_crypto.h"
#include "contrib/libngtcp2/ngtcp2/ngtcp2_crypto_gnutls.h"

#include "libknot/xdp/quic_conn.h"
#include "libknot/xdp/xdp.h"

// special values for stream_id signalling a need for special treatment
#define XQUIC_SEND_VERSION_NEGOTIATION    NGTCP2_ERR_VERSION_NEGOTIATION
#define XQUIC_SEND_RETRY                  NGTCP2_ERR_RETRY
#define XQUIC_SEND_STATELESS_RESET        (-NGTCP2_STATELESS_RESET_TOKENLEN)

typedef struct knot_quic_creds {
	gnutls_certificate_credentials_t tls_cert;
	gnutls_anti_replay_t tls_anti_replay;
	gnutls_datum_t tls_ticket_key;
	uint8_t static_secret[32];
} knot_xquic_creds_t;

int knot_xquic_init_creds(knot_xquic_creds_t *creds, const char *tls_cert, const char *tls_key);

void knot_xquic_free_creds(knot_xquic_creds_t *creds);

bool xquic_conn_timeout(knot_xquic_conn_t *conn);

int knot_xquic_client(knot_xquic_table_t *table, struct sockaddr_storage *dest,
                      struct sockaddr_storage *via, knot_xquic_conn_t **out_conn);

/*!
 * \brief Process received packets, pic incomming DNS data.
 *
 * \param relays        Out: affected QUIC connections.
 * \param msgs          Incomming packets.
 * \param count         Number of incomming packets.
 * \param quic_table    Connection table.
 *
 * \return KNOT_E*
 */
int knot_xquic_recv(knot_xquic_conn_t **relays,
                    knot_xdp_msg_t *msgs, uint32_t count,
                    knot_xquic_table_t *quic_table);

int knot_xquic_send(knot_xdp_socket_t *sock, knot_xquic_conn_t *relay, unsigned max_msgs);
