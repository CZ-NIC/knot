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
#include <stdlib.h>
#include <string.h>

#include "knot/query/quic-requestor.h"

#include "contrib/net.h"
#include "contrib/time.h"
#include "knot/common/log.h" // please use this only for tiny stuff like quic-log
#include "knot/conf/conf.h" // please use this only for tiny stuff like quic-log
#include "knot/server/handler.h"
#include "libknot/error.h"
#include "libknot/quic/quic.h"

#define QUIC_BUF_SIZE 4096

static void quic_log_cb(const char *line)
{
	log_debug("QUIC requestor: %s", line);
}

static int quic_exchange(knot_quic_conn_t *conn, knot_quic_reply_t *r, int timeout_ms)
{
	int fd = (int)(size_t)r->sock;

	int ret = knot_quic_send(conn->quic_table, conn, r, QUIC_MAX_SEND_PER_RECV, false);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = net_dgram_recv(fd, r->in_payload->iov_base, QUIC_BUF_SIZE, timeout_ms);
	if (ret == 0) {
		return KNOT_ECONN;
	} else if (ret < 0) {
		return ret;
	}
	r->in_payload->iov_len = ret;

	knot_quic_conn_t *hconn = NULL;
	ret = knot_quic_handle(conn->quic_table, r, timeout_ms * 1000L, &hconn);
	if (hconn == NULL) {
		return KNOT_EOK;
	} else if (hconn != conn) {
		return KNOT_ESEMCHECK;
	} else {
		return ret;
	}
}

int qr_alloc_reply(struct knot_quic_reply *r)
{
	r->out_payload->iov_len = QUIC_BUF_SIZE;
	return KNOT_EOK;
}

int qr_send_reply(struct knot_quic_reply *r)
{
	int fd = (int)(size_t)r->sock;
	int ret = net_dgram_send(fd, r->out_payload->iov_base,
	                         r->out_payload->iov_len, r->ip_rem);
	if (ret < 0) {
		return ret;
	} else if (ret == r->out_payload->iov_len) {
		return KNOT_EOK;
	} else {
		return KNOT_EAGAIN;
	}
}

void qr_free_reply(struct knot_quic_reply *r)
{
	(void)r;
}

int knot_qreq_connect(struct knot_quic_reply **out,
                      int fd,
                      struct sockaddr_storage *remote,
                      struct sockaddr_storage *local,
                      const struct knot_quic_creds *local_creds,
                      const uint8_t *peer_pin,
                      uint8_t peer_pin_len,
                      int timeout_ms)
{
	struct knot_quic_reply *r = calloc(1, sizeof(*r) + 2 * sizeof(struct iovec) +
	                                      2 * QUIC_BUF_SIZE);
	if (r == NULL) {
		return KNOT_ENOMEM;
	}

	r->ip_rem = remote;
	r->ip_loc = local;
	r->in_payload = ((void *)r) + sizeof(*r);
	r->out_payload = r->in_payload + 1;
	r->in_payload->iov_base = ((void *)r->out_payload) + sizeof(*r->out_payload);
	r->out_payload->iov_base = r->in_payload->iov_base + QUIC_BUF_SIZE;
	r->sock = (void *)(size_t)fd;
	r->alloc_reply = qr_alloc_reply;
	r->send_reply = qr_send_reply;
	r->free_reply = qr_free_reply;

	struct knot_quic_creds *creds = knot_quic_init_creds_peer(local_creds,
	                                                          peer_pin, peer_pin_len);
	if (creds == NULL) {
		free(r);
		return KNOT_ENOMEM;
	}

	// NOTE the limits on conns and buffers do not do anything since we do not sweep
	knot_quic_table_t *table = knot_quic_table_new(1, QUIC_BUF_SIZE,
	                                               QUIC_BUF_SIZE, 0, creds);
	if (table == NULL) {
		knot_quic_free_creds(creds);
		free(r);
		return KNOT_ENOMEM;
	}

	conf_val_t qlval = conf_get(conf(), C_XDP, C_QUIC_LOG);
	if (conf_bool(&qlval)) {
		table->log_cb = quic_log_cb;
	}

	knot_quic_conn_t *conn = NULL;
	int ret = knot_quic_client(table, (struct sockaddr_in6 *)r->ip_rem,
	                           (struct sockaddr_in6 *)r->ip_loc, NULL, &conn);
	r->in_ctx = conn;
	if (ret != KNOT_EOK) {
		knot_qreq_close(r);
		return ret;
	}

	struct timespec t_start = time_now(), t_cur;
	while (!conn->handshake_done) {
		t_cur = time_now();
		if (time_diff_ms(&t_start, &t_cur) > timeout_ms ||
		    (ret = quic_exchange(conn, r, timeout_ms)) != KNOT_EOK) {
			knot_qreq_close(r);
			return ret;
		}
	}

	r->in_ctx = conn;
	*out = r;

	return KNOT_EOK;
}

int knot_qreq_send(struct knot_quic_reply *r, const struct iovec *data)
{
	knot_quic_conn_t *conn = r->in_ctx;
	return knot_quic_stream_add_data(conn, conn->streams_count * 4, data->iov_base,
	                                 data->iov_len) == NULL ? KNOT_NET_ESEND : KNOT_EOK;
}

int knot_qreq_recv(struct knot_quic_reply *r, struct iovec *out, int timeout_ms)
{
	knot_quic_conn_t *conn = r->in_ctx;
	knot_quic_stream_t *stream = &conn->streams[conn->streams_count - 1];

	assert(conn->streams_count != 0);

	knot_tinbufu_res_t *firstib = stream->inbufs;
	if (firstib != NULL && firstib->n_inbufs >= 2) { // first inbuf has been processed last time
		assert(firstib->n_inbufs == 2);
		struct iovec *inbufs = knot_tinbufu_res_inbufs(firstib);
		if (inbufs[1].iov_len > out->iov_len) {
			return KNOT_ESPACE;
		}
		out->iov_len = inbufs[1].iov_len;
		memcpy(out->iov_base, inbufs[1].iov_base, out->iov_len);
		stream->inbufs = firstib->next;
		free(firstib);
		return KNOT_EOK;
	}

	struct timespec t_start = time_now(), t_cur;
	while (stream->inbufs == NULL) {
		int ret = quic_exchange(conn, r, timeout_ms);
		if (ret != KNOT_EOK) {
			return ret;
		}
		t_cur = time_now();
		if (time_diff_ms(&t_start, &t_cur) > timeout_ms) {
			return KNOT_NET_ETIMEOUT;
		}
		if (conn->streams_count == 0) {
			return KNOT_ECONN;
		}
	}

	firstib = stream->inbufs;
	if (firstib->n_inbufs > 2) {
		return KNOT_ESEMCHECK; // this hardly happens
	}

	struct iovec *inbufs = knot_tinbufu_res_inbufs(firstib);
	if (inbufs[0].iov_len <= out->iov_len) {
		out->iov_len = inbufs[0].iov_len;
		memcpy(out->iov_base, inbufs[0].iov_base, out->iov_len);
		if (firstib->n_inbufs < 2) {
			stream->inbufs = firstib->next;
			free(firstib);
		}
	} else {
		return KNOT_ESPACE;
	}

	return KNOT_EOK;
}

void knot_qreq_close(struct knot_quic_reply *r)
{
	knot_quic_conn_t *conn = r->in_ctx;
	knot_quic_table_t *table = conn->quic_table;
	knot_quic_table_rem(conn, table);
	knot_quic_cleanup(&conn, 1);
	knot_quic_free_creds(table->creds);
	knot_quic_table_free(table);
	free(r);
}
