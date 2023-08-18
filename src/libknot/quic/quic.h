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

/*!
 * \file
 *
 * \brief General QUIC functionality.
 *
 * \addtogroup quic
 * @{
 */

#pragma once

#include <sys/types.h>
#include <netinet/in.h>

#include "libknot/quic/quic_conn.h"

#define KNOT_QUIC_PIN_LEN	32

struct gnutls_x509_crt_int;
struct knot_quic_creds;
struct knot_quic_session;

typedef enum {
	KNOT_QUIC_SEND_IGNORE_LASTBYTE = (1 << 0),
} knot_quic_send_flag_t;

typedef struct knot_quic_reply {
	const struct sockaddr_storage *ip_rem;
	const struct sockaddr_storage *ip_loc;
	struct iovec *in_payload;
	struct iovec *out_payload;
	void *in_ctx;
	void *out_ctx;

	void *sock;
	int handle_ret;
	uint8_t ecn;

	int (*alloc_reply)(struct knot_quic_reply *);
	int (*send_reply)(struct knot_quic_reply *);
	void (*free_reply)(struct knot_quic_reply *);
} knot_quic_reply_t;

#define KNOT_QUIC_HANDLE_RET_CLOSE  (2000)

/*!
 * \brief Check if session ticket can be taken out of this connection.
 */
bool knot_quic_session_available(knot_quic_conn_t *conn);

/*!
 * \brief Gets data needed for session resumption.
 *
 * \param conn   QUIC connection.
 *
 * \return QUIC session context.
 */
struct knot_quic_session *knot_quic_session_save(knot_quic_conn_t *conn);

/*!
 * \brief Loads data needed for session resumption.
 *
 * \param conn     QUIC connection.
 * \param session  QUIC session context.
 *
 * \return KNOT_E*
 */
int knot_quic_session_load(knot_quic_conn_t *conn, struct knot_quic_session *session);

/*!
 * \brief Init server TLS certificate for DoQ.
 *
 * \param cert_file     X509 certificate PEM file path/name (NULL if auto-generated).
 * \param key_file      Key PEM file path/name.
 *
 * \return Initialized creds.
 */
struct knot_quic_creds *knot_quic_init_creds(const char *cert_file,
                                             const char *key_file);

/*!
 * \brief Init peer TLS certificate for DoQ.
 *
 * \param local_creds   Local credentials if server.
 * \param peer_pin      Optional peer certificate pin to check.
 * \param peer_pin_len  Length of the peer pin. Set 0 if not specified.
 *
 * \return Initialized creds.
 */
struct knot_quic_creds *knot_quic_init_creds_peer(const struct knot_quic_creds *local_creds,
                                                  const uint8_t *peer_pin,
                                                  uint8_t peer_pin_len);

/*!
 * \brief Gets the certificate from credentials.
 *
 * \param creds  TLS credentials.
 * \param cert   Output certificate.
 *
 * \return KNOT_E*
 */
int knot_quic_creds_cert(struct knot_quic_creds *creds, struct gnutls_x509_crt_int **cert);

/*!
 * \brief Deinit server TLS certificate for DoQ.
 */
void knot_quic_free_creds(struct knot_quic_creds *creds);

/*!
 * \brief Returns timeout value for the connection.
 */
uint64_t quic_conn_get_timeout(knot_quic_conn_t *conn);

/*!
 * \brief Check if connection timed out due to inactivity.
 *
 * \param conn   QUIC connection.
 * \param now    In/out: current monotonic time. Use zero first and reuse for
 *               next calls for optimization.
 *
 * \return True if the connection timed out idle.
 */
bool quic_conn_timeout(knot_quic_conn_t *conn, uint64_t *now);

/*!
 * \brief Returns measured connection RTT in usecs.
 */
uint32_t knot_quic_conn_rtt(knot_quic_conn_t *conn);

/*!
 * \brief Returns the port from local-address of given conn IN BIG ENDIAN.
 */
uint16_t knot_quic_conn_local_port(knot_quic_conn_t *conn);

/*!
 * \brief Gets local or remote certificate pin.
 *
 * \note Zero output pin_size value means no certificate available or error.
 *
 * \param conn      QUIC connection.
 * \param pin       Output certificate pin.
 * \param pin_size  Input size of the storage / output size of the stored pin.
 * \param local     Local or remote certificate indication.
 */
void knot_quic_conn_pin(knot_quic_conn_t *conn, uint8_t *pin, size_t *pin_size, bool local);

/*!
 * \brief Create new outgoing QUIC connection.
 *
 * \param table       QUIC connections table to be added to.
 * \param dest        Destination IP address.
 * \param via         Source IP address.
 * \param server_name Optional server name.
 * \param out_conn    Out: new connection.
 *
 * \return KNOT_E*
 */
int knot_quic_client(knot_quic_table_t *table, struct sockaddr_in6 *dest,
                     struct sockaddr_in6 *via, const char *server_name,
                     knot_quic_conn_t **out_conn);

/*!
 * \brief Handle incoming QUIC packet.
 *
 * \param table           QUIC connectoins table.
 * \param reply           Incoming packet info.
 * \param idle_timeout    Configured idle timeout for connections (in nanoseconds).
 * \param out_conn        Out: QUIC connection that this packet belongs to.
 *
 * \return KNOT_E* or -QUIC_SEND_*
 */
int knot_quic_handle(knot_quic_table_t *table, knot_quic_reply_t *reply,
                     uint64_t idle_timeout, knot_quic_conn_t **out_conn);

/*!
 * \brief Send outgoing QUIC packet(s) for a connection.
 *
 * \param quic_table         QUIC connection table.
 * \param conn               QUIC connection.
 * \param reply              Incoming/outgoing packet info.
 * \param max_msgs           Maxmimum packets to be sent.
 * \param flags              Various options for special use-cases.
 *
 * \return KNOT_E*
 */
int knot_quic_send(knot_quic_table_t *quic_table, knot_quic_conn_t *conn,
                   knot_quic_reply_t *reply, unsigned max_msgs,
                   knot_quic_send_flag_t flags);

/*! @} */
