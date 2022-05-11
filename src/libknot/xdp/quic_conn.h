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

#include <linux/if_ether.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/uio.h>

struct ngtcp2_cid; // declaration taken from wherever in ngtcp2

// those are equivalent to contrib/ucw/lists.h , just must not be included.
typedef struct knot_xquic_ucw_node {
	struct knot_xquic_ucw_node *next, *prev;
} knot_xquic_ucw_node_t;
typedef struct knot_xquic_ucw_list {
	knot_xquic_ucw_node_t head, tail;
} knot_xquic_ucw_list_t;

typedef enum {
	XQUIC_STREAM_FREED = 0,
	XQUIC_STREAM_RECVING,
	XQUIC_STREAM_RECVD,
	XQUIC_STREAM_ANSWD,
	XQUIC_STREAM_SENT,
} knot_xquic_stream_state_t;

typedef struct {
	knot_xquic_ucw_node_t node;
	size_t len;
	uint8_t buf[];
} knot_xquic_obuf_t;

typedef struct {
	struct iovec inbuf;
	knot_xquic_ucw_list_t outbufs;
	size_t obufs_size;

	knot_xquic_obuf_t *unsent_obuf;
	size_t first_offset;
	size_t unsent_offset;
} knot_xquic_stream_t;

typedef struct knot_xquic_conn {
	knot_xquic_ucw_node_t timeout; // MUST be first field of the struct

	struct ngtcp2_conn *conn;

	struct gnutls_session_int *tls_session;

	knot_xquic_stream_t *streams;
	int64_t streams_count; // number of allocated streams structures. Special negative values denote fake knot_xquic_conn_t intended to send version negotiation, retry, or stateless reset.
	int64_t streams_first; // stream_id/4 of first allocated stream
	size_t ibufs_size; // FIXME also global statistics of this counter; sweeping conns based on this
	size_t obufs_size;

	struct knot_xquic_table *xquic_table;

	struct knot_xquic_conn *next;
} knot_xquic_conn_t;

typedef struct knot_xquic_table {
	size_t size;
	size_t usage;
	size_t pointers;
	size_t obufs_size;
	bool log;
	uint64_t hash_secret[4];
	struct knot_quic_creds *creds;
	knot_xquic_ucw_list_t timeout;
	knot_xquic_conn_t *conns[];
} knot_xquic_table_t;

/*!
 * \brief Allocate QUIC connections hash table.
 *
 * \param max_conns    Maximum nuber of connections.
 * \param tls_cert     Server TLS certificate.
 * \param tls_key      TLS private key.
 *
 * \return Allocated table or NULL;
 */
knot_xquic_table_t *knot_xquic_table_new(size_t max_conns, const char *tls_cert, const char *tls_key);

/*!
 * \brief Free QUIC table including its contents.
 *
 * \param table    Table to be freed.
 */
void knot_xquic_table_free(knot_xquic_table_t *table);

int knot_xquic_table_sweep(knot_xquic_table_t *table, size_t max_conns, size_t max_obufs);

knot_xquic_conn_t **xquic_table_insert(knot_xquic_conn_t *xconn, const struct ngtcp2_cid *cid,
                                       knot_xquic_table_t *table);

knot_xquic_conn_t **xquic_table_add(struct ngtcp2_conn *conn, const struct ngtcp2_cid *cid, knot_xquic_table_t *table);

knot_xquic_conn_t **xquic_table_lookup(const struct ngtcp2_cid *cid, knot_xquic_table_t *table);

void xquic_conn_mark_used(knot_xquic_conn_t *conn, knot_xquic_table_t *table);

void xquic_table_rem2(knot_xquic_conn_t **pconn, knot_xquic_table_t *table);

void xquic_stream_free(knot_xquic_conn_t *xconn, int64_t stream_id);

void xquic_table_rem(knot_xquic_conn_t *conn, knot_xquic_table_t *table);

knot_xquic_stream_t *knot_xquic_conn_get_stream(knot_xquic_conn_t *xconn, int64_t stream_id, bool create);

int knot_xquic_stream_recv_data(knot_xquic_conn_t *xconn, int64_t stream_id, const uint8_t *data, size_t len, bool fin);

uint8_t *knot_xquic_stream_add_data(knot_xquic_conn_t *xconn, int64_t stream_id, uint8_t *data, size_t len);

void knot_xquic_stream_ack_data(knot_xquic_conn_t *xconn, int64_t stream_id, size_t end_acked, bool keep_stream);

void knot_xquic_stream_mark_sent(knot_xquic_conn_t *xconn, int64_t stream_id, size_t amount_sent);
