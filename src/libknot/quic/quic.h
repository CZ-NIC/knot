/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
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
#include "libknot/quic/tls_common.h"

#define KNOT_QUIC_HANDLE_RET_CLOSE	2000

// RFC 9250
#define KNOT_QUIC_ERR_EXCESSIVE_LOAD	0x4

typedef enum {
	KNOT_QUIC_SEND_IGNORE_LASTBYTE = (1 << 0),
	KNOT_QUIC_SEND_IGNORE_BLOCKED  = (1 << 1),
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
struct knot_tls_session *knot_quic_session_save(knot_quic_conn_t *conn);

/*!
 * \brief Loads data needed for session resumption.
 *
 * \param conn     QUIC connection.
 * \param session  QUIC session context.
 *
 * \return KNOT_E*
 */
int knot_quic_session_load(knot_quic_conn_t *conn, struct knot_tls_session *session);

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

int64_t knot_quic_conn_next_timeout(knot_quic_conn_t *conn);

int knot_quic_hanle_expiry(knot_quic_conn_t *conn);

/*!
 * \brief Returns measured connection RTT in usecs.
 */
uint32_t knot_quic_conn_rtt(knot_quic_conn_t *conn);

/*!
 * \brief Returns the port from local-address of given conn IN BIG ENDIAN.
 */
uint16_t knot_quic_conn_local_port(knot_quic_conn_t *conn);

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
