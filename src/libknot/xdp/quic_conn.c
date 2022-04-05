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

#include "libknot/xdp/quic_conn.h"
#include "libknot/xdp/quic.h"

#include <assert.h>
#include <string.h>

#include "contrib/libngtcp2/ngtcp2/ngtcp2.h"
#include "contrib/macros.h"
#include "contrib/openbsd/siphash.h"
#include "contrib/ucw/lists.h"
#include "libdnssec/random.h"

#include "libknot/attribute.h"
#include "libknot/error.h"
#include "libknot/xdp/tcp_iobuf.h"
#include "libknot/wire.h"

#define STREAM_INCR 4 // DoQ only uses client-initiated bi-directional streams, so stream IDs increment by four
#define BUCKETS_PER_CONNS 8 // Each connecion has several dCIDs, and each CID takes one hash table bucket.

_public_
knot_xquic_table_t *knot_xquic_table_new(size_t max_conns, const char *tls_cert, const char *tls_key)
{
	size_t table_size = max_conns * BUCKETS_PER_CONNS;

	knot_xquic_table_t *res = calloc(1, sizeof(*res) + table_size * sizeof(res->conns[0]) + sizeof(knot_xquic_creds_t));
	if (res == NULL) {
		return NULL;
	}

	res->size = table_size;
	init_list((list_t *)&res->timeout);
	res->creds = (void *)res + sizeof(*res) + table_size * sizeof(res->conns[0]);

	if (knot_xquic_init_creds(res->creds, tls_cert, tls_key) != KNOT_EOK) {
		free(res);
		return NULL;
	}

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
		WALK_LIST_DELSAFE(c, next, *(list_t *)&table->timeout) {
			xquic_table_rem(c, table);
		}
		assert(table->usage == 0);
		assert(table->pointers == 0);
		assert(table->obufs_size == 0);

		knot_xquic_free_creds(table->creds);

		free(table);
	}
}

_public_
int knot_xquic_table_sweep(knot_xquic_table_t *table, size_t max_conns, size_t max_obufs)
{
	knot_xquic_conn_t *c, *next;
	WALK_LIST_DELSAFE(c, next, *(list_t *)&table->timeout) {
		if (xquic_conn_timeout(c)) {
			xquic_table_rem(c, table);
		} else if (table->usage > max_conns) {
			xquic_table_rem(c, table); // FIXME send some reset
		} else if (table->obufs_size > max_obufs) {
			if (c->obufs_size > 0) {
				xquic_table_rem(c, table); // FIXME send some reset
			}
		} else {
			break;
		}
	}
	return KNOT_EOK;
}

static bool cid_eq(const ngtcp2_cid *a, const ngtcp2_cid *b) // FIXME ngtcp2_cid_eq
{
	return a->datalen == b->datalen &&
	       memcmp(a->data, b->data, a->datalen) == 0;
}

static uint64_t cid2hash(const ngtcp2_cid *cid, knot_xquic_table_t *table)
{
	SIPHASH_CTX ctx;
	SipHash24_Init(&ctx, (const SIPHASH_KEY *)(table->hash_secret));
	SipHash24_Update(&ctx, cid->data, MIN(cid->datalen, 8));
	uint64_t ret = SipHash24_End(&ctx);
	printf("hash cid %lx secret %lx result %lx\n", *(uint64_t *)cid->data, *(uint64_t *)table->hash_secret, ret);
	return ret;
}

knot_xquic_conn_t **xquic_table_insert(knot_xquic_conn_t *xconn, const ngtcp2_cid *cid,
                                       knot_xquic_table_t *table)
{
	uint64_t hash = cid2hash(cid, table);

	knot_xquic_conn_t **addto = table->conns + (hash % table->size);
	xconn->next = *addto;
	*addto = xconn;
	table->pointers++;

	return addto;
}

knot_xquic_conn_t **xquic_table_add(ngtcp2_conn *conn, const ngtcp2_cid *cid, knot_xquic_table_t *table)
{
	knot_xquic_conn_t *xconn = calloc(1, sizeof(*xconn));
	if (xconn == NULL) {
		return NULL;
	}

	xconn->conn = conn;
	xconn->xquic_table = table;

	knot_xquic_conn_t **addto = xquic_table_insert(xconn, cid, table);
	printf("TABLE addto %p conn %p\n", addto, xconn);
	table->usage++;

	return addto;
}

knot_xquic_conn_t **xquic_table_lookup(const ngtcp2_cid *cid, knot_xquic_table_t *table)
{
	uint64_t hash = cid2hash(cid, table);

	knot_xquic_conn_t **res = table->conns + (hash % table->size);
	while (*res != NULL) {
		const ngtcp2_cid *ocid = ngtcp2_conn_get_client_initial_dcid((*res)->conn);
		if (cid_eq(ocid, cid) || true /* FIXME !! */) {
			break;
		}
		res = &(*res)->next;
	}
	printf("TABLE lookup hash 0x%lx: %p at %p\n", hash, *res, res);
	return res;
}

void xquic_conn_mark_used(knot_xquic_conn_t *conn, knot_xquic_table_t *table)
{
	node_t *n = (node_t *)&conn->timeout;
	list_t *l = (list_t *)&table->timeout;
	if (n->next != NULL) {
		rem_node(n);
	}
	add_tail(l, n);
}

void xquic_table_rem2(knot_xquic_conn_t **pconn, knot_xquic_table_t *table)
{
	knot_xquic_conn_t *conn = *pconn;
	*pconn = conn->next;
	table->pointers--;
}

void xquic_stream_free(knot_xquic_conn_t *xconn, int64_t stream_id)
{
	knot_xquic_stream_ack_data(xconn, stream_id, SIZE_MAX, false);
}

void xquic_table_rem(knot_xquic_conn_t *conn, knot_xquic_table_t *table)
{
	for (ssize_t i = conn->streams_count - 1; i >= 0; i--) {
		xquic_stream_free(conn, (i + conn->streams_first) * 4);
	}
	assert(conn->streams_count == 0);
	assert(conn->obufs_size == 0);

	size_t num_scid = ngtcp2_conn_get_num_scid(conn->conn);
	ngtcp2_cid *scids = calloc(num_scid, sizeof(*scids));
	ngtcp2_conn_get_scid(conn->conn, scids);
	printf("rem conn num_scid: %zu, num_dcid: %zu\n", ngtcp2_conn_get_num_scid(conn->conn), ngtcp2_conn_get_num_active_dcid(conn->conn));

	for (size_t i = 0; i < num_scid; i++) {
		knot_xquic_conn_t **pconn = xquic_table_lookup(&scids[i], table);
		assert(pconn != NULL); // FIXME: harden against weird attacks by if(pconn==NULL)continue; once tested well
		assert(*pconn == conn);
		xquic_table_rem2(pconn, table);
	}

	rem_node((node_t *)&conn->timeout);

	free(scids);

	gnutls_deinit(conn->tls_session);
	ngtcp2_conn_del(conn->conn);

	free(conn);

	table->usage--;
}

knot_xquic_stream_t *knot_xquic_conn_get_stream(knot_xquic_conn_t *xconn, int64_t stream_id, bool create)
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
		size_t new_streams_count = stream_id + 1 - xconn->streams_first;
		knot_xquic_stream_t *new_streams = xconn->streams_count == 0
		                                 ? malloc(new_streams_count * sizeof(*new_streams))
		                                 : realloc(xconn->streams, new_streams_count * sizeof(*new_streams));
		if (new_streams == NULL) {
			return NULL;
		}

		for (knot_xquic_stream_t *si = new_streams + xconn->streams_count; si < new_streams + new_streams_count; si++) {
			memset(si, 0, sizeof(*si));
			init_list((list_t *)&si->outbufs);
		}
		xconn->streams = new_streams;
		xconn->streams_count = new_streams_count;

		return &xconn->streams[stream_id - xconn->streams_first];
	}
	return NULL;
}

int knot_xquic_stream_recv_data(knot_xquic_conn_t *xconn, int64_t stream_id, const uint8_t *data, size_t len, bool fin)
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
	int ret = tcp_inbuf_update(&stream->inbuf, in, &outs, &outs_count, &xconn->ibufs_size);
	printf("TIU (%s) count %zu fin %d stream %zd\n", knot_strerror(ret), outs_count, fin, stream_id);
	if (ret != KNOT_EOK || (outs_count == 0 && !fin)) {
		return ret;
	}
	if (outs_count != 1 || !fin) {
		free(outs);
		return KNOT_ESEMCHECK;
	}

	stream->inbuf = outs[0];
	free(outs);
	return KNOT_EOK;
}

uint8_t *knot_xquic_stream_add_data(knot_xquic_conn_t *xconn, int64_t stream_id, uint8_t *data, size_t len)
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

	if (EMPTY_LIST(*(list_t *)&s->outbufs)) {
		s->unsent_obuf = obuf;
	}
	add_tail((list_t *)&s->outbufs, (node_t *)obuf);
	s->obufs_size += obuf->len;
	xconn->obufs_size += obuf->len;
	xconn->xquic_table->obufs_size += obuf->len;

	return obuf->buf + prefix;
}

void knot_xquic_stream_ack_data(knot_xquic_conn_t *xconn, int64_t stream_id, size_t end_acked, bool keep_stream)
{
	knot_xquic_stream_t *s = knot_xquic_conn_get_stream(xconn, stream_id, false);
	if (s == NULL) {
		return;
	}

	list_t *obs = (list_t *)&s->outbufs;

	knot_xquic_obuf_t *first;
	while (!EMPTY_LIST(*obs) && end_acked >= (first = HEAD(*obs))->len + s->first_offset) {
		assert(first != s->unsent_obuf);
		rem_node((node_t *)first);
		s->obufs_size -= first->len;
		xconn->obufs_size -= first->len;
		xconn->xquic_table->obufs_size -= first->len;
		s->first_offset += first->len;
		free(first);
	}

	if (EMPTY_LIST(*obs) && !keep_stream) {
		if (s == xconn->streams) {
			xconn->streams_count--;

			if (xconn->streams_count == 0) {
				free(xconn->streams);
				xconn->streams = 0;
				xconn->streams_first = 0;
			} else {
				xconn->streams_first++;
				memmove(s, s + 1, sizeof(*s) * xconn->streams_count);
				// possible realloc to shrink allocated space, but probably useless
			}
		} else {
			memset(s, 0, sizeof(*s));
		}
	}
}

void knot_xquic_stream_mark_sent(knot_xquic_conn_t *xconn, int64_t stream_id, size_t amount_sent)
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
