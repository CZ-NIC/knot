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

/*!
 * \brief Init server TLS certificate for DoQ.
 *
 * \param creds       Creds structure to be initialized.
 * \param server      Initializing for server-side (client otherwise).
 * \param tls_cert    X509 certificate file path/name.
 * \param tls_key     Key file path/name.
 *
 * \return KNOT_E*
 */
int knot_xquic_init_creds(knot_xquic_creds_t *creds, bool server,
                          const char *tls_cert, const char *tls_key);

/*!
 * \brief Init server TLS certificate for DoQ.
 */
void knot_xquic_free_creds(knot_xquic_creds_t *creds);

/*!
 * \brief Check if connection timed out due to inactivity.
 *
 * \param conn   QUIC connection.
 * \param now    In/out: current monotonic time. Use zero first and reuse for next calls for optimization.
 *
 * \return True if the connection timed out idle.
 */
bool xquic_conn_timeout(knot_xquic_conn_t *conn, uint64_t *now);
