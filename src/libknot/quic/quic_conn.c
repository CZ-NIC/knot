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

#include <assert.h>
#include <gnutls/gnutls.h>
#include <ngtcp2/ngtcp2.h>
#include <string.h>

#include "libknot/quic/quic_conn.h"

#include "contrib/macros.h"
#include "contrib/openbsd/siphash.h"
#include "contrib/ucw/lists.h"
#include "libdnssec/random.h"
#include "libknot/attribute.h"
#include "libknot/error.h"
#include "libknot/quic/quic.h"
#include "libknot/xdp/tcp_iobuf.h"
#include "libknot/wire.h"

#define STREAM_INCR 4 // DoQ only uses client-initiated bi-directional streams, so stream IDs increment by four
#define BUCKETS_PER_CONNS 8 // Each connecion has several dCIDs, and each CID takes one hash table bucket.

_public_
knot_quic_table_t *knot_quic_table_new(size_t max_conns, size_t max_ibufs, size_t max_obufs,
                                       size_t udp_payload, struct knot_quic_creds *creds)
{
	size_t table_size = max_conns * BUCKETS_PER_CONNS;

	knot_quic_table_t *res = calloc(1, sizeof(*res) + table_size * sizeof(res->conns[0]));
	if (res == NULL) {
		return NULL;
	}

	res->size = table_size;
	res->max_conns = max_conns;
	res->ibufs_max = max_ibufs;
	res->obufs_max = max_obufs;
	res->udp_payload_limit = udp_payload;
	init_list((list_t *)&res->timeout);

	res->creds = creds;

	res->hash_secret[0] = dnssec_random_uint64_t();
	res->hash_secret[1] = dnssec_random_uint64_t();
	res->hash_secret[2] = dnssec_random_uint64_t();
	res->hash_secret[3] = dnssec_random_uint64_t();

	return res;
}

_public_
void knot_quic_table_free(knot_quic_table_t *table)
{
	if (table != NULL) {
		knot_quic_conn_t *c, *next;
		list_t *tto = (list_t *)&table->timeout;
		WALK_LIST_DELSAFE(c, next, *tto) {
			knot_quic_table_rem(c, table);
			knot_quic_cleanup(&c, 1);
		}
		assert(table->usage == 0);
		assert(table->pointers == 0);
		assert(table->ibufs_size == 0);
		assert(table->obufs_size == 0);

		free(table);
	}
}

_public_
void knot_quic_table_sweep(knot_quic_table_t *table, struct knot_sweep_stats *stats)
{
	uint64_t now = 0;
	knot_quic_conn_t *c, *next;
	list_t *tto = (list_t *)&table->timeout;
	WALK_LIST_DELSAFE(c, next, *tto) {
		if (quic_conn_timeout(c, &now)) {
			knot_sweep_stats_incr(stats, KNOT_SWEEP_CTR_TIMEOUT);
			knot_quic_table_rem(c, table);
		} else if (table->usage > table->max_conns) {
			knot_sweep_stats_incr(stats, KNOT_SWEEP_CTR_LIMIT_CONN);
			knot_quic_table_rem(c, table);
			// NOTE here it would be correct to send Immediate close
			// with DoQ errcode DOQ_EXCESSIVE_LOAD
			// nowever, we don't do this for the sake of simplicty
			// it would be possible to send by using ngtcp2_conn_get_path()...
			// (also applies to below case)
		} else if (table->obufs_size > table->obufs_max) {
			if (c->obufs_size > 0) {
				knot_sweep_stats_incr(stats, KNOT_SWEEP_CTR_LIMIT_OBUF);
				knot_quic_table_rem(c, table);
			}
		} else if (table->ibufs_size > table->ibufs_max) {
			if (c->ibufs_size > 0) {
				knot_sweep_stats_incr(stats, KNOT_SWEEP_CTR_LIMIT_IBUF);
				knot_quic_table_rem(c, table);
			}
		} else {
			break;
		}
		knot_quic_cleanup(&c, 1);
	}
}

static uint64_t cid2hash(const ngtcp2_cid *cid, knot_quic_table_t *table)
{
	SIPHASH_CTX ctx;
	SipHash24_Init(&ctx, (const SIPHASH_KEY *)(table->hash_secret));
	SipHash24_Update(&ctx, cid->data, MIN(cid->datalen, 8));
	uint64_t ret = SipHash24_End(&ctx);
	return ret;
}

knot_quic_cid_t **quic_table_insert(knot_quic_conn_t *conn, const ngtcp2_cid *cid,
                                    knot_quic_table_t *table)
{
	uint64_t hash = cid2hash(cid, table);

	knot_quic_cid_t *cidobj = malloc(sizeof(*cidobj));
	if (cidobj == NULL) {
		return NULL;
	}
	_Static_assert(sizeof(*cid) <= sizeof(cidobj->cid_placeholder), "insufficient placeholder for CID struct");
	memcpy(cidobj->cid_placeholder, cid, sizeof(*cid));
	cidobj->conn = conn;

	knot_quic_cid_t **addto = table->conns + (hash % table->size);

	cidobj->next = *addto;
	*addto = cidobj;
	table->pointers++;

	return addto;
}

knot_quic_conn_t *quic_table_add(ngtcp2_conn *ngconn, const ngtcp2_cid *cid,
                                 knot_quic_table_t *table)
{
	knot_quic_conn_t *conn = calloc(1, sizeof(*conn));
	if (conn == NULL) {
		return NULL;
	}

	conn->conn = ngconn;
	conn->quic_table = table;
	conn->stream_inprocess = -1;
	conn->qlog_fd = -1;

	knot_quic_cid_t **addto = quic_table_insert(conn, cid, table);
	if (addto == NULL) {
		free(conn);
		return NULL;
	}
	table->usage++;

	return conn;
}

knot_quic_cid_t **quic_table_lookup2(const ngtcp2_cid *cid, knot_quic_table_t *table)
{
	uint64_t hash = cid2hash(cid, table);

	knot_quic_cid_t **res = table->conns + (hash % table->size);
	while (*res != NULL && !ngtcp2_cid_eq(cid, (const ngtcp2_cid *)(*res)->cid_placeholder)) {
		res = &(*res)->next;
	}
	return res;
}

knot_quic_conn_t *quic_table_lookup(const ngtcp2_cid *cid, knot_quic_table_t *table)
{
	knot_quic_cid_t **pcid = quic_table_lookup2(cid, table);
	assert(pcid != NULL);
	return *pcid == NULL ? NULL : (*pcid)->conn;
}

void quic_conn_mark_used(knot_quic_conn_t *conn, knot_quic_table_t *table,
                          uint64_t now)
{
	node_t *n = (node_t *)&conn->timeout;
	list_t *l = (list_t *)&table->timeout;
	if (n->next != NULL) {
		rem_node(n);
	}
	add_tail(l, n);
	conn->last_ts = now;
}

void quic_table_rem2(knot_quic_cid_t **pcid, knot_quic_table_t *table)
{
	knot_quic_cid_t *cid = *pcid;
	*pcid = cid->next;
	free(cid);
	table->pointers--;
}

_public_
void knot_quic_conn_stream_free(knot_quic_conn_t *conn, int64_t stream_id)
{
	knot_quic_stream_t *s = knot_quic_conn_get_stream(conn, stream_id, false);
	if (s != NULL && s->inbuf.iov_len > 0) {
		free(s->inbuf.iov_base);
		conn->ibufs_size -= buffer_alloc_size(s->inbuf.iov_len);
		conn->quic_table->ibufs_size -= buffer_alloc_size(s->inbuf.iov_len);
		memset(&s->inbuf, 0, sizeof(s->inbuf));
	}
	while (s != NULL && s->inbufs != NULL) {
		void *tofree = s->inbufs;
		s->inbufs = s->inbufs->next;
		free(tofree);
	}
	knot_quic_stream_ack_data(conn, stream_id, SIZE_MAX, false);
}

_public_
void knot_quic_table_rem(knot_quic_conn_t *conn, knot_quic_table_t *table)
{
	if (conn->conn == NULL) {
		return;
	}

	if (conn->streams_count == -1) { // kxdpgun special
		conn->streams_count = 1;
	}
	for (ssize_t i = conn->streams_count - 1; i >= 0; i--) {
		knot_quic_conn_stream_free(conn, (i + conn->streams_first) * 4);
	}
	assert(conn->streams_count <= 0);
	assert(conn->obufs_size == 0);

	size_t num_scid = ngtcp2_conn_get_scid(conn->conn, NULL);
	ngtcp2_cid *scids = calloc(num_scid, sizeof(*scids));
	ngtcp2_conn_get_scid(conn->conn, scids);

	for (size_t i = 0; i < num_scid; i++) {
		knot_quic_cid_t **pcid = quic_table_lookup2(&scids[i], table);
		assert(pcid != NULL);
		if (*pcid == NULL) {
			continue;
		}
		assert((*pcid)->conn == conn);
		quic_table_rem2(pcid, table);
	}

	rem_node((node_t *)&conn->timeout);

	free(scids);

	gnutls_deinit(conn->tls_session);
	ngtcp2_conn_del(conn->conn);
	conn->conn = NULL;

	table->usage--;
}

_public_
knot_quic_stream_t *knot_quic_conn_get_stream(knot_quic_conn_t *conn,
                                              int64_t stream_id, bool create)
{
	if (stream_id % 4 != 0) {
		return NULL;
	}
	stream_id /= 4;

	if (conn->streams_first > stream_id) {
		return NULL;
	}
	if (conn->streams_count > stream_id - conn->streams_first) {
		return &conn->streams[stream_id - conn->streams_first];
	}

	if (create) {
		size_t new_streams_count;
		knot_quic_stream_t *new_streams;

		if (conn->streams_count == 0) {
			new_streams = malloc(sizeof(new_streams[0]));
			if (new_streams == NULL) {
				return NULL;
			}
			new_streams_count = 1;
			conn->streams_first = stream_id;
		} else {
			new_streams_count = stream_id + 1 - conn->streams_first;
			if (new_streams_count > MAX_STREAMS_PER_CONN) {
				return NULL;
			}
			new_streams = realloc(conn->streams, new_streams_count * sizeof(*new_streams));
			if (new_streams == NULL) {
				return NULL;
			}
		}

		for (knot_quic_stream_t *si = new_streams;
		     si < new_streams + conn->streams_count; si++) {
			if (si->obufs_size == 0) {
				init_list((list_t *)&si->outbufs);
			} else {
				fix_list((list_t *)&si->outbufs);
			}
		}

		for (knot_quic_stream_t *si = new_streams + conn->streams_count;
		     si < new_streams + new_streams_count; si++) {
			memset(si, 0, sizeof(*si));
			init_list((list_t *)&si->outbufs);
		}
		conn->streams = new_streams;
		conn->streams_count = new_streams_count;

		return &conn->streams[stream_id - conn->streams_first];
	}
	return NULL;
}

_public_
knot_quic_stream_t *knot_quic_conn_new_stream(knot_quic_conn_t *conn)
{
	int64_t new_id = (conn->streams_first + conn->streams_count) * 4;
	return knot_quic_conn_get_stream(conn, new_id, true);
}

static void stream_inprocess(knot_quic_conn_t *conn, knot_quic_stream_t *stream)
{
	int16_t idx = stream - conn->streams;
	assert(idx >= 0);
	assert(idx < conn->streams_count);
	if (conn->stream_inprocess < 0 || conn->stream_inprocess > idx) {
		conn->stream_inprocess = idx;
	}
}

static void stream_outprocess(knot_quic_conn_t *conn, knot_quic_stream_t *stream)
{
	if (stream != &conn->streams[conn->stream_inprocess]) {
		return;
	}

	for (int16_t idx = conn->stream_inprocess + 1; idx < conn->streams_count; idx++) {
		stream = &conn->streams[idx];
		if (stream->inbufs != NULL) {
			conn->stream_inprocess = stream - conn->streams;
			return;
		}
	}
	conn->stream_inprocess = -1;
}

int knot_quic_stream_recv_data(knot_quic_conn_t *conn, int64_t stream_id,
                               const uint8_t *data, size_t len, bool fin)
{
	if (len == 0) {
		return KNOT_EINVAL;
	}

	knot_quic_stream_t *stream = knot_quic_conn_get_stream(conn, stream_id, true);
	if (stream == NULL) {
		return KNOT_ENOENT;
	}

	struct iovec in = { (void *)data, len };
	ssize_t prev_ibufs_size = conn->ibufs_size;
	int ret = knot_tcp_inbufs_upd(&stream->inbuf, in, true,
	                              &stream->inbufs, &conn->ibufs_size);
	conn->quic_table->ibufs_size += (ssize_t)conn->ibufs_size - prev_ibufs_size;
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (fin && stream->inbufs == NULL) {
		return KNOT_ESEMCHECK;
	}

	if (stream->inbufs != NULL) {
		stream_inprocess(conn, stream);
	}
	return KNOT_EOK;
}

_public_
knot_quic_stream_t *knot_quic_stream_get_process(knot_quic_conn_t *conn,
                                                 int64_t *stream_id)
{
	if (conn->stream_inprocess < 0) {
		return NULL;
	}

	knot_quic_stream_t *stream = &conn->streams[conn->stream_inprocess];
	*stream_id = (conn->streams_first + conn->stream_inprocess) * 4;
	stream_outprocess(conn, stream);
	return stream;
}

_public_
uint8_t *knot_quic_stream_add_data(knot_quic_conn_t *conn, int64_t stream_id,
                                   uint8_t *data, size_t len)
{
	knot_quic_stream_t *s = knot_quic_conn_get_stream(conn, stream_id, true);
	if (s == NULL) {
		return NULL;
	}

	size_t prefix = sizeof(uint16_t);

	knot_quic_obuf_t *obuf = malloc(sizeof(*obuf) + prefix + len);
	if (obuf == NULL) {
		return NULL;
	}

	obuf->len = len + prefix;
	knot_wire_write_u16(obuf->buf, len);
	if (data != NULL) {
		memcpy(obuf->buf + prefix, data, len);
	}

	list_t *list = (list_t *)&s->outbufs;
	if (EMPTY_LIST(*list)) {
		s->unsent_obuf = obuf;
	}
	add_tail((list_t *)&s->outbufs, (node_t *)obuf);
	s->obufs_size += obuf->len;
	conn->obufs_size += obuf->len;
	conn->quic_table->obufs_size += obuf->len;

	return obuf->buf + prefix;
}

void knot_quic_stream_ack_data(knot_quic_conn_t *conn, int64_t stream_id,
                               size_t end_acked, bool keep_stream)
{
	knot_quic_stream_t *s = knot_quic_conn_get_stream(conn, stream_id, false);
	if (s == NULL) {
		return;
	}

	list_t *obs = (list_t *)&s->outbufs;

	knot_quic_obuf_t *first;
	while (!EMPTY_LIST(*obs) && end_acked >= (first = HEAD(*obs))->len + s->first_offset) {
		rem_node((node_t *)first);
		assert(HEAD(*obs) != first); // help CLANG analyzer understand what rem_node did and that further usage of HEAD(*obs) is safe
		s->obufs_size -= first->len;
		conn->obufs_size -= first->len;
		conn->quic_table->obufs_size -= first->len;
		s->first_offset += first->len;
		free(first);
		if (s->unsent_obuf == first) {
			s->unsent_obuf = EMPTY_LIST(*obs) ? NULL : HEAD(*obs);
			s->unsent_offset = 0;
		}
	}

	if (EMPTY_LIST(*obs) && !keep_stream) {
		stream_outprocess(conn, s);
		memset(s, 0, sizeof(*s));
		init_list((list_t *)&s->outbufs);
		while (s = &conn->streams[0], s->inbuf.iov_len == 0 && s->inbufs == NULL && s->obufs_size == 0) {
			assert(conn->streams_count > 0);
			conn->streams_count--;

			if (conn->streams_count == 0) {
				free(conn->streams);
				conn->streams = 0;
				conn->streams_first = 0;
				break;
			} else {
				conn->streams_first++;
				conn->stream_inprocess--;
				memmove(s, s + 1, sizeof(*s) * conn->streams_count);
				// possible realloc to shrink allocated space, but probably useless
				for (knot_quic_stream_t *si = s;  si < s + conn->streams_count; si++) {
					if (si->obufs_size == 0) {
						init_list((list_t *)&si->outbufs);
					} else {
						fix_list((list_t *)&si->outbufs);
					}
				}
			}
		}
	}
}

void knot_quic_stream_mark_sent(knot_quic_conn_t *conn, int64_t stream_id,
                                size_t amount_sent)
{
	knot_quic_stream_t *s = knot_quic_conn_get_stream(conn, stream_id, false);
	if (s == NULL) {
		return;
	}

	s->unsent_offset += amount_sent;
	assert(s->unsent_offset <= s->unsent_obuf->len);
	if (s->unsent_offset == s->unsent_obuf->len) {
		s->unsent_offset = 0;
		s->unsent_obuf = (knot_quic_obuf_t *)s->unsent_obuf->node.next;
		if (s->unsent_obuf->node.next == NULL) { // already behind the tail of list
			s->unsent_obuf = NULL;
		}
	}
}

_public_
void knot_quic_cleanup(knot_quic_conn_t *conns[], size_t n_conns)
{
	for (size_t i = 0; i < n_conns; i++) {
		if (conns[i] != NULL && conns[i]->conn == NULL) {
			free(conns[i]);
			for (size_t j = i + 1; j < n_conns; j++) {
				if (conns[j] == conns[i]) {
					conns[j] = NULL;
				}
			}
		}
	}
}

bool quic_require_retry(knot_quic_table_t *table)
{
	(void)table;
	return false;
}
