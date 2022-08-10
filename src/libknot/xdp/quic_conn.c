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

#include <assert.h>
#include <gnutls/gnutls.h>
#include <ngtcp2/ngtcp2.h>
#include <string.h>

#include "libknot/xdp/quic_conn.h"

#include "contrib/macros.h"
#include "contrib/openbsd/siphash.h"
#include "contrib/ucw/lists.h"
#include "libdnssec/random.h"
#include "libknot/attribute.h"
#include "libknot/error.h"
#include "libknot/xdp/quic.h"
#include "libknot/xdp/tcp_iobuf.h"
#include "libknot/wire.h"

#define STREAM_INCR 4 // DoQ only uses client-initiated bi-directional streams, so stream IDs increment by four
#define BUCKETS_PER_CONNS 8 // Each connecion has several dCIDs, and each CID takes one hash table bucket.

_public_
knot_xquic_table_t *knot_xquic_table_new(size_t max_conns, size_t max_ibufs, size_t max_obufs,
                                         size_t udp_payload, struct knot_quic_creds *creds)
{
	size_t table_size = max_conns * BUCKETS_PER_CONNS;

	knot_xquic_table_t *res = calloc(1, sizeof(*res) + table_size * sizeof(res->conns[0]));
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
void knot_xquic_table_free(knot_xquic_table_t *table)
{
	if (table != NULL) {
		knot_xquic_conn_t *c, *next;
		list_t *tto = (list_t *)&table->timeout;
		WALK_LIST_DELSAFE(c, next, *tto) {
			knot_xquic_table_rem(c, table);
		}
		assert(table->usage == 0);
		assert(table->pointers == 0);
		assert(table->obufs_size == 0);

		free(table);
	}
}

_public_
int knot_xquic_table_sweep(knot_xquic_table_t *table, struct knot_sweep_stats *stats)
{
	uint64_t now = 0;
	knot_xquic_conn_t *c, *next;
	list_t *tto = (list_t *)&table->timeout;
	WALK_LIST_DELSAFE(c, next, *tto) {
		if (xquic_conn_timeout(c, &now)) {
			knot_sweep_stats_incr(stats, KNOT_SWEEP_CTR_TIMEOUT);
			knot_xquic_table_rem(c, table);
		} else if (table->usage > table->max_conns) {
			knot_sweep_stats_incr(stats, KNOT_SWEEP_CTR_LIMIT_CONN);
			knot_xquic_table_rem(c, table);
			// NOTE here it would be correct to send Immediate close
			// with DoQ errcode DOQ_EXCESSIVE_LOAD
			// nowever, we don't do this for the sake of simplicty
			// it would be possible to send by using ngtcp2_conn_get_path()...
			// (also applies to below case)
		} else if (table->obufs_size > table->obufs_max) {
			if (c->obufs_size > 0) {
				knot_sweep_stats_incr(stats, KNOT_SWEEP_CTR_LIMIT_OBUF);
				knot_xquic_table_rem(c, table);
			}
		} else if (table->ibufs_size > table->ibufs_max) {
			if (c->ibufs_size > 0) {
				knot_sweep_stats_incr(stats, KNOT_SWEEP_CTR_LIMIT_IBUF);
				knot_xquic_table_rem(c, table);
			}
		} else {
			break;
		}
	}
	return KNOT_EOK;
}

static uint64_t cid2hash(const ngtcp2_cid *cid, knot_xquic_table_t *table)
{
	SIPHASH_CTX ctx;
	SipHash24_Init(&ctx, (const SIPHASH_KEY *)(table->hash_secret));
	SipHash24_Update(&ctx, cid->data, MIN(cid->datalen, 8));
	uint64_t ret = SipHash24_End(&ctx);
	return ret;
}

knot_xquic_cid_t **xquic_table_insert(knot_xquic_conn_t *xconn, const ngtcp2_cid *cid,
                                      knot_xquic_table_t *table)
{
	uint64_t hash = cid2hash(cid, table);

	knot_xquic_cid_t *cidobj = malloc(sizeof(*cidobj));
	if (cidobj == NULL) {
		return NULL;
	}
	_Static_assert(sizeof(*cid) <= sizeof(cidobj->cid_placeholder), "insufficient placeholder for CID struct");
	memcpy(cidobj->cid_placeholder, cid, sizeof(*cid));
	cidobj->conn = xconn;

	knot_xquic_cid_t **addto = table->conns + (hash % table->size);

	cidobj->next = *addto;
	*addto = cidobj;
	table->pointers++;

	return addto;
}

knot_xquic_conn_t *xquic_table_add(ngtcp2_conn *conn, const ngtcp2_cid *cid,
                                   knot_xquic_table_t *table)
{
	knot_xquic_conn_t *xconn = calloc(1, sizeof(*xconn));
	if (xconn == NULL) {
		return NULL;
	}

	xconn->conn = conn;
	xconn->xquic_table = table;
	xconn->stream_inprocess = -1;

	knot_xquic_cid_t **addto = xquic_table_insert(xconn, cid, table);
	if (addto == NULL) {
		free(xconn);
		return NULL;
	}
	table->usage++;

	return xconn;
}

knot_xquic_cid_t **xquic_table_lookup2(const ngtcp2_cid *cid, knot_xquic_table_t *table)
{
	uint64_t hash = cid2hash(cid, table);

	knot_xquic_cid_t **res = table->conns + (hash % table->size);
	while (*res != NULL && !ngtcp2_cid_eq(cid, (const ngtcp2_cid *)(*res)->cid_placeholder)) {
		res = &(*res)->next;
	}
	return res;
}

knot_xquic_conn_t *xquic_table_lookup(const ngtcp2_cid *cid, knot_xquic_table_t *table)
{
	knot_xquic_cid_t **pcid = xquic_table_lookup2(cid, table);
	assert(pcid != NULL);
	return *pcid == NULL ? NULL : (*pcid)->conn;
}

void xquic_conn_mark_used(knot_xquic_conn_t *conn, knot_xquic_table_t *table,
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

void xquic_table_rem2(knot_xquic_cid_t **pcid, knot_xquic_table_t *table)
{
	knot_xquic_cid_t *cid = *pcid;
	*pcid = cid->next;
	free(cid);
	table->pointers--;
}

void xquic_stream_free(knot_xquic_conn_t *xconn, int64_t stream_id)
{
	knot_xquic_stream_ack_data(xconn, stream_id, SIZE_MAX, false);
}

_public_
void knot_xquic_table_rem(knot_xquic_conn_t *conn, knot_xquic_table_t *table)
{
	if (conn->streams_count == -1) { // kxdpgun special
		conn->streams_count = 1;
	}
	for (ssize_t i = conn->streams_count - 1; i >= 0; i--) {
		xquic_stream_free(conn, (i + conn->streams_first) * 4);
	}
	assert(conn->streams_count <= 0);
	assert(conn->obufs_size == 0);

	size_t num_scid = ngtcp2_conn_get_num_scid(conn->conn);
	ngtcp2_cid *scids = calloc(num_scid, sizeof(*scids));
	ngtcp2_conn_get_scid(conn->conn, scids);

	for (size_t i = 0; i < num_scid; i++) {
		knot_xquic_cid_t **pcid = xquic_table_lookup2(&scids[i], table);
		assert(pcid != NULL);
		if (*pcid == NULL) {
			continue;
		}
		assert((*pcid)->conn == conn);
		xquic_table_rem2(pcid, table);
	}

	rem_node((node_t *)&conn->timeout);

	free(scids);

	gnutls_deinit(conn->tls_session);
	ngtcp2_conn_del(conn->conn);

	free(conn);

	table->usage--;
}

_public_
knot_xquic_stream_t *knot_xquic_conn_get_stream(knot_xquic_conn_t *xconn,
                                                int64_t stream_id, bool create)
{
	if (stream_id % 4 != 0) {
		return NULL;
	}
	stream_id /= 4;

	if (xconn->streams_first > stream_id) {
		return NULL;
	}
	if (xconn->streams_count > stream_id - xconn->streams_first) {
		return &xconn->streams[stream_id - xconn->streams_first];
	}

	if (create) {
		size_t new_streams_count;
		knot_xquic_stream_t *new_streams;

		if (xconn->streams_count == 0) {
			new_streams = malloc(sizeof(new_streams[0]));
			if (new_streams == NULL) {
				return NULL;
			}
			new_streams_count = 1;
			xconn->streams_first = stream_id;
		} else {
			new_streams_count = stream_id + 1 - xconn->streams_first;
			if (new_streams_count > MAX_STREAMS_PER_CONN) {
				return NULL;
			}
			new_streams = realloc(xconn->streams, new_streams_count * sizeof(*new_streams));
			if (new_streams == NULL) {
				return NULL;
			}
		}

		for (knot_xquic_stream_t *si = new_streams + xconn->streams_count;
		     si < new_streams + new_streams_count; si++) {
			memset(si, 0, sizeof(*si));
			init_list((list_t *)&si->outbufs);
		}
		xconn->streams = new_streams;
		xconn->streams_count = new_streams_count;

		return &xconn->streams[stream_id - xconn->streams_first];
	}
	return NULL;
}

static void stream_inprocess(knot_xquic_conn_t *xconn, knot_xquic_stream_t *stream)
{
	int16_t idx = stream - xconn->streams;
	assert(idx >= 0);
	assert(idx < xconn->streams_count);
	if (xconn->stream_inprocess < 0 || xconn->stream_inprocess > idx) {
		xconn->stream_inprocess = idx;
	}
}

static void stream_outprocess(knot_xquic_conn_t *xconn, knot_xquic_stream_t *stream)
{
	if (stream != &xconn->streams[xconn->stream_inprocess]) {
		return;
	}

	for (int16_t idx = xconn->stream_inprocess + 1; idx < xconn->streams_count; idx++) {
		stream = &xconn->streams[idx];
		if (stream->inbuf_fin) {
			xconn->stream_inprocess = stream - xconn->streams;
			return;
		}
	}
	xconn->stream_inprocess = -1;
}

int knot_xquic_stream_recv_data(knot_xquic_conn_t *xconn, int64_t stream_id,
                                const uint8_t *data, size_t len, bool fin)
{
	if (len == 0) {
		return KNOT_EINVAL;
	}

	knot_xquic_stream_t *stream = knot_xquic_conn_get_stream(xconn, stream_id, true);
	if (stream == NULL) {
		return KNOT_ENOENT;
	}

	struct iovec in = { (void *)data, len }, *outs;
	size_t outs_count;
	int ret = knot_tcp_inbuf_update(&stream->inbuf, in, &outs, &outs_count,
	                                &xconn->ibufs_size);
	if (ret != KNOT_EOK || (outs_count == 0 && !fin)) {
		return ret;
	}
	if (outs_count != 1 || !fin) {
		free(outs);
		return KNOT_ESEMCHECK;
	}

	stream->inbuf = outs[0];
	stream->inbuf_fin = true;
	stream_inprocess(xconn, stream);
	free(outs);
	return KNOT_EOK;
}

_public_
knot_xquic_stream_t *knot_xquic_stream_get_process(knot_xquic_conn_t *xconn,
                                                   int64_t *stream_id)
{
	if (xconn->stream_inprocess < 0) {
		return NULL;
	}

	knot_xquic_stream_t *stream = &xconn->streams[xconn->stream_inprocess];
	*stream_id = (xconn->streams_first + xconn->stream_inprocess) * 4;
	stream_outprocess(xconn, stream);
	return stream;
}

_public_
uint8_t *knot_xquic_stream_add_data(knot_xquic_conn_t *xconn, int64_t stream_id,
                                    uint8_t *data, size_t len)
{
	knot_xquic_stream_t *s = knot_xquic_conn_get_stream(xconn, stream_id, true);
	if (s == NULL) {
		return NULL;
	}

	size_t prefix = sizeof(uint16_t);

	knot_xquic_obuf_t *obuf = malloc(sizeof(*obuf) + prefix + len);
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
	xconn->obufs_size += obuf->len;
	xconn->xquic_table->obufs_size += obuf->len;

	return obuf->buf + prefix;
}

void knot_xquic_stream_ack_data(knot_xquic_conn_t *xconn, int64_t stream_id,
                                size_t end_acked, bool keep_stream)
{
	knot_xquic_stream_t *s = knot_xquic_conn_get_stream(xconn, stream_id, false);
	if (s == NULL) {
		return;
	}

	list_t *obs = (list_t *)&s->outbufs;

	knot_xquic_obuf_t *first;
	while (!EMPTY_LIST(*obs) && end_acked >= (first = HEAD(*obs))->len + s->first_offset) {
		rem_node((node_t *)first);
		s->obufs_size -= first->len;
		xconn->obufs_size -= first->len;
		xconn->xquic_table->obufs_size -= first->len;
		s->first_offset += first->len;
		free(first);
		if (s->unsent_obuf == first) {
			s->unsent_obuf = EMPTY_LIST(*obs) ? NULL : HEAD(*obs);
			s->unsent_offset = 0;
		}
	}

	if (EMPTY_LIST(*obs) && !keep_stream) {
		stream_outprocess(xconn, s);
		memset(s, 0, sizeof(*s));
		while (s = &xconn->streams[0], s->inbuf.iov_len == 0 && s->obufs_size == 0) {
			assert(xconn->streams_count > 0);
			xconn->streams_count--;

			if (xconn->streams_count == 0) {
				free(xconn->streams);
				xconn->streams = 0;
				xconn->streams_first = 0;
				break;
			} else {
				xconn->streams_first++;
				xconn->stream_inprocess--;
				memmove(s, s + 1, sizeof(*s) * xconn->streams_count);
				// possible realloc to shrink allocated space, but probably useless
			}
		}
	}
}

void knot_xquic_stream_mark_sent(knot_xquic_conn_t *xconn, int64_t stream_id,
                                 size_t amount_sent)
{
	knot_xquic_stream_t *s = knot_xquic_conn_get_stream(xconn, stream_id, false);
	if (s == NULL) {
		return;
	}

	s->unsent_offset += amount_sent;
	assert(s->unsent_offset <= s->unsent_obuf->len);
	if (s->unsent_offset == s->unsent_obuf->len) {
		s->unsent_offset = 0;
		s->unsent_obuf = (knot_xquic_obuf_t *)s->unsent_obuf->node.next;
		if (s->unsent_obuf->node.next == NULL) { // already behind the tail of list
			s->unsent_obuf = NULL;
		}
	}
}

bool xquic_require_retry(knot_xquic_table_t *table)
{
	(void)table;
	return false;
}
