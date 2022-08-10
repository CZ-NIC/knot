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

/*!
 * \file
 *
 * \brief QUIC connection management.
 *
 * \addtogroup xdp
 * @{
 */

#pragma once

#include <linux/if_ether.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/uio.h>

#define MAX_STREAMS_PER_CONN 10

struct ngtcp2_cid; // declaration taken from wherever in ngtcp2
struct knot_quic_creds;
struct knot_sweep_stats;

// those are equivalent to contrib/ucw/lists.h , just must not be included.
typedef struct knot_xquic_ucw_node {
	struct knot_xquic_ucw_node *next, *prev;
} knot_xquic_ucw_node_t;
typedef struct knot_xquic_ucw_list {
	knot_xquic_ucw_node_t head, tail;
} knot_xquic_ucw_list_t;

typedef struct {
	void *get_conn;
	void *user_data;
} nc_conn_ref_placeholder_t;

typedef struct {
	knot_xquic_ucw_node_t node;
	size_t len;
	uint8_t buf[];
} knot_xquic_obuf_t;

typedef struct {
	struct iovec inbuf;
	bool inbuf_fin;
	knot_xquic_ucw_list_t outbufs;
	size_t obufs_size;

	knot_xquic_obuf_t *unsent_obuf;
	size_t first_offset;
	size_t unsent_offset;
} knot_xquic_stream_t;

typedef struct knot_xquic_conn {
	knot_xquic_ucw_node_t timeout; // MUST be first field of the struct
	uint64_t last_ts;

	nc_conn_ref_placeholder_t conn_ref; // placeholder for internal struct ngtcp2_crypto_conn_ref

	struct ngtcp2_conn *conn;

	struct gnutls_session_int *tls_session;

	knot_xquic_stream_t *streams;
	int16_t streams_count; // number of allocated streams structures
	int16_t stream_inprocess; // index of first stream that has complete incomming data to be processed (aka inbuf_fin)
	bool handshake_done;
	bool session_taken; // TODO ... ?
	int64_t streams_first; // stream_id/4 of first allocated stream
	size_t ibufs_size;
	size_t obufs_size;

	struct knot_xquic_table *xquic_table;

	struct knot_xquic_conn *next;
} knot_xquic_conn_t;

typedef struct knot_xquic_cid {
	uint8_t cid_placeholder[32];
	knot_xquic_conn_t *conn;
	struct knot_xquic_cid *next;
} knot_xquic_cid_t;

typedef struct knot_xquic_table {
	size_t size;
	size_t usage;
	size_t pointers;
	size_t max_conns;
	size_t ibufs_max;
	size_t obufs_max;
	size_t ibufs_size;
	size_t obufs_size;
	size_t udp_payload_limit; // for simplicity not distinguishing IPv4/6
	void (*log_cb)(const char *);
	uint64_t hash_secret[4];
	struct knot_quic_creds *creds;
	knot_xquic_ucw_list_t timeout;
	knot_xquic_cid_t *conns[];
} knot_xquic_table_t;

/*!
 * \brief Allocate QUIC connections hash table.
 *
 * \param max_conns    Maximum nuber of connections.
 * \param max_ibufs    Maximum size of buffers for fragmented incomming DNS msgs.
 * \param max_obufs    Maximum size of buffers for un-ACKed outgoing data.
 * \param udp_pl       Maximum UDP payload size (both IPv4 and 6).
 * \param creds        QUIC crypto context..
 *
 * \return Allocated table, or NULL.
 */
knot_xquic_table_t *knot_xquic_table_new(size_t max_conns, size_t max_ibufs, size_t max_obufs,
                                         size_t udp_payload, struct knot_quic_creds *creds);

/*!
 * \brief Free QUIC table including its contents.
 *
 * \param table    Table to be freed.
 */
void knot_xquic_table_free(knot_xquic_table_t *table);

/*!
 * \brief Close timed out connections and some oldest ones if table full.
 *
 * \param table       QUIC table to be cleaned up.
 * \param stats       Out: sweep statistics.
 *
 * \return KNOT_E*
 */
int knot_xquic_table_sweep(knot_xquic_table_t *table, struct knot_sweep_stats *stats);

/*!
 * \brief Add new connection/CID link to table.
 *
 * \param xconn    QUIC connection linked.
 * \param cid      New CID to be added.
 * \param table    QUIC table to be modified.
 *
 * \return Pointer on the CID reference in table, or NULL.
 */
knot_xquic_cid_t **xquic_table_insert(knot_xquic_conn_t *xconn,
                                      const struct ngtcp2_cid *cid,
                                      knot_xquic_table_t *table);

/*!
 * \brief Add new connection to the table, allocating conn struct.
 *
 * \param conn      Ngtcp2 conn struct.
 * \param cid       CID to be linked (usually oscid for server).
 * \param table     QUIC table to be modified.
 *
 * \return Allocated (and linked) Knot conn struct, or NULL.
 */
knot_xquic_conn_t *xquic_table_add(struct ngtcp2_conn *conn,
                                   const struct ngtcp2_cid *cid,
                                   knot_xquic_table_t *table);

/*!
 * \brief Lookup connection/CID link in table.
 *
 * \param cid      CID to be searched for.
 * \param table    QUIC table.
 *
 * \return Pointer on the CID reference in table, or NULL.
 */
knot_xquic_cid_t **xquic_table_lookup2(const struct ngtcp2_cid *cid,
                                       knot_xquic_table_t *table);

/*!
 * \brief Lookup QUIC connection in table.
 *
 * \param cid      CID to be searched for.
 * \param table    QUIC table.
 *
 * \return Connection that the CID belongs to, or NULL.
 */
knot_xquic_conn_t *xquic_table_lookup(const struct ngtcp2_cid *cid,
                                      knot_xquic_table_t *table);

/*!
 * \brief Put the connection on the end of timeout queue.
 */
void xquic_conn_mark_used(knot_xquic_conn_t *conn, knot_xquic_table_t *table,
                          uint64_t now);

/*!
 * \brief Remove connection/CID link from table.
 *
 * \param pcid     CID to be removed.
 * \param table    QUIC table.
 */
void xquic_table_rem2(knot_xquic_cid_t **pcid, knot_xquic_table_t *table);

/*!
 * \brief Remove specified stream from QUIC connection, freeing all buffers.
 *
 * \param xconn         QUIC connection to remove from.
 * \param stream_id     Stream QUIC ID.
 */
void xquic_stream_free(knot_xquic_conn_t *xconn, int64_t stream_id);

/*!
 * \brief Remove and deinitialize connection completely.
 *
 * \param conn      Connection to be removed.
 * \param table     Table to remove from.
 */
void knot_xquic_table_rem(knot_xquic_conn_t *conn, knot_xquic_table_t *table);

/*!
 * \brief Fetch or initialize a QUIC stream.
 *
 * \param xconn          QUIC connection.
 * \param stream_id      Stream QUIC ID.
 * \param create         Trigger stream creation if not exists.
 *
 * \return Stream or NULL.
 */
knot_xquic_stream_t *knot_xquic_conn_get_stream(knot_xquic_conn_t *xconn,
                                                int64_t stream_id, bool create);

/*!
 * \brief Process incomming stream data to stream structure.
 *
 * \param xconn         QUIC connection that has received data.
 * \param stream_id     Stream QUIC ID of the incomming data.
 * \param data          Incomming payload data.
 * \param len           Incomming payload data length.
 * \param fin           FIN flag set for incomming data.
 *
 * \return KNOT_E*
 */
int knot_xquic_stream_recv_data(knot_xquic_conn_t *xconn, int64_t stream_id,
                                const uint8_t *data, size_t len, bool fin);

/*!
 * \brief Get next stream which has pending incomming data to be processed.
 *
 * \param xconn        QUIC connection.
 * \param stream_id    Out: strem QUIC ID of the returned stream.
 *
 * \return Stream with incomming data.
 */
knot_xquic_stream_t *knot_xquic_stream_get_process(knot_xquic_conn_t *xconn,
                                                   int64_t *stream_id);

/*!
 * \brief Add outgiong data to the stream for sending.
 *
 * \param xconn         QUIC connection that shall send data.
 * \param stream_id     Stream ID for outgoing data.
 * \param data          Data payload.
 * \param len           Data payload length.
 *
 * \return NULL if error, or pinter at the data in outgiong buffer.
 */
uint8_t *knot_xquic_stream_add_data(knot_xquic_conn_t *xconn, int64_t stream_id,
                                    uint8_t *data, size_t len);

/*!
 * \brief Mark outgiong data as acknowledged after ACK received.
 *
 * \param xconn          QUIC connection that received ACK.
 * \param stream_id      Stream ID of ACKed data.
 * \param end_acked      Offset of ACKed data + ACKed length.
 * \param keep_stream    Don't free the stream even when ACKed all outgoing data.
 */
void knot_xquic_stream_ack_data(knot_xquic_conn_t *xconn, int64_t stream_id,
                                size_t end_acked, bool keep_stream);

/*!
 * \brief Mark outgoing data as sent.
 *
 * \param xconn          QUIC connection that sent data.
 * \param stream_id      Stream ID of sent data.
 * \param amount_sent    Length of sent data.
 */
void knot_xquic_stream_mark_sent(knot_xquic_conn_t *xconn, int64_t stream_id,
                                 size_t amount_sent);

/*!
 * \brief Toggle sending Retry packet as a reaction to Initial packet of new connection.
 *
 * \param table       Connection table.
 *
 * \return True if instead of continuing handshake, Retry packet shall be sent
 *              to verify counterpart's address.
 */
bool xquic_require_retry(knot_xquic_table_t *table);

/*! @} */
