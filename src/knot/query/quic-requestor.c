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

#include "contrib/conn_pool.h"
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
	log_fmt(LOG_DEBUG, LOG_SOURCE_QUIC, "QUIC requestor, %s", line);
}

typedef union {
	struct cmsghdr cmsg;
	uint8_t buf[CMSG_SPACE(sizeof(int))];
} cmsg_tos_t;

static int quic_exchange(knot_quic_conn_t *conn, knot_quic_reply_t *r, int timeout_ms)
{
	int fd = (int)(size_t)r->sock;

	int ret = knot_quic_send(conn->quic_table, conn, r, QUIC_MAX_SEND_PER_RECV, 0);
	if (ret != KNOT_EOK) {
		return ret;
	}

	cmsg_tos_t tos = { 0 };
	r->in_payload->iov_len = QUIC_BUF_SIZE;
	struct msghdr msg = {
		.msg_iov = r->in_payload,
		.msg_iovlen = 1,
		.msg_control = &tos,
		.msg_controllen = sizeof(tos),
	};
	ret = net_msg_recv(fd, &msg, timeout_ms);
	if (ret == 0) {
		return KNOT_ECONN;
	} else if (ret < 0) {
		return ret;
	}
	r->in_payload->iov_len = ret;
	r->ecn = net_cmsg_ecn(&msg);

	knot_quic_conn_t *hconn = NULL;
	ret = knot_quic_handle(conn->quic_table, r, timeout_ms * 1000000LU, &hconn);
	if (hconn == NULL) {
		return KNOT_EOK;
	} else if (hconn != conn) {
		return KNOT_ESEMCHECK;
	}

	if (ret == KNOT_EOK && global_sessticket_pool != NULL &&
	    knot_quic_session_available(conn)) {
		void *sessticket = knot_quic_session_save(conn);
		if (sessticket != NULL) {
			intptr_t tofree = conn_pool_put(global_sessticket_pool, r->ip_loc,
			                                r->ip_rem, (intptr_t)sessticket);
			global_sessticket_pool->close_cb(tofree);
		}
	}

	return ret;
}

int qr_alloc_reply(struct knot_quic_reply *r)
{
	r->out_payload->iov_len = QUIC_BUF_SIZE;
	return KNOT_EOK;
}

int qr_send_reply(struct knot_quic_reply *r)
{
	int fd = (int)(size_t)r->sock;

	cmsg_tos_t tos = {
		.cmsg.cmsg_len = CMSG_LEN(sizeof(int))
	};
	*(int *)CMSG_DATA(&tos.cmsg) = r->ecn;
	struct msghdr msg = {
		.msg_iov = r->out_payload,
		.msg_iovlen = 1,
		.msg_control = &tos,
		.msg_controllen = sizeof(tos),
	};
	if (r->ip_rem->ss_family == AF_INET6) {
		tos.cmsg.cmsg_level = IPPROTO_IPV6;
		tos.cmsg.cmsg_type = IPV6_TCLASS;
	} else {
#ifdef IP_RECVTOS
		tos.cmsg.cmsg_level = IPPROTO_IP;
		tos.cmsg.cmsg_type = IP_TOS;
#else /* Disallow setting TOS if RECVTOS isn't supported (OpenBSD). */
		msg.msg_control = NULL;
		msg.msg_controllen = 0;
#endif
	}

	int ret = net_msg_send(fd, &msg, 0);
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
                      bool *reused_fd,
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
	r->out_payload = ((void *)r->in_payload) + sizeof(*r->in_payload);
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

	if (log_enabled_quic_debug()) {
		table->log_cb = quic_log_cb;
	}

	knot_quic_conn_t *conn = NULL;
	int ret = knot_quic_client(table, (struct sockaddr_in6 *)r->ip_rem,
	                           (struct sockaddr_in6 *)r->ip_loc, NULL, &conn);
	r->in_ctx = conn;
	if (ret != KNOT_EOK) {
		knot_qreq_close(r, false);
		return ret;
	}

	(void)net_cmsg_ecn_enable(fd, remote->ss_family);

	intptr_t sessticket = conn_pool_get(global_sessticket_pool, r->ip_loc, r->ip_rem);
	if (sessticket != CONN_POOL_FD_INVALID) {
		ret = knot_quic_session_load(conn, (void *)sessticket);
		if (ret != KNOT_EOK) {
			global_sessticket_pool->close_cb(sessticket);
			sessticket = CONN_POOL_FD_INVALID;
		} else if (reused_fd != NULL) {
			*reused_fd = true;
		}
	}

	struct timespec t_start = time_now(), t_cur;
	while (!(conn->flags & KNOT_QUIC_CONN_HANDSHAKE_DONE) && sessticket == CONN_POOL_FD_INVALID) {
		t_cur = time_now();
		if (time_diff_ms(&t_start, &t_cur) > timeout_ms ||
		    (ret = quic_exchange(conn, r, timeout_ms)) != KNOT_EOK) {
			knot_qreq_close(r, false);
			return ret;
		}
	}

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

	knot_tcp_inbufs_upd_res_t *firstib = stream->inbufs;
	assert(stream->firstib_consumed < firstib->n_inbufs);
	struct iovec *inbufs = firstib->inbufs;
	struct iovec *consum = &inbufs[stream->firstib_consumed];
	if (consum->iov_len > out->iov_len) {
		return KNOT_ESPACE;
	}
	out->iov_len = consum->iov_len;
	memcpy(out->iov_base, consum->iov_base, out->iov_len);
	if (++stream->firstib_consumed == firstib->n_inbufs) {
		stream->firstib_consumed = 0;
		stream->inbufs = firstib->next;
		free(firstib);
	}

	return KNOT_EOK;
}

void knot_qreq_close(struct knot_quic_reply *r, bool send_close)
{
	knot_quic_conn_t *conn = r->in_ctx;
	knot_quic_table_t *table = conn->quic_table;

	if (send_close && conn->conn != NULL) {
		r->handle_ret = KNOT_QUIC_HANDLE_RET_CLOSE;
		(void)knot_quic_send(table, conn, r, QUIC_MAX_SEND_PER_RECV, 0);
	}

	knot_quic_table_rem(conn, table);
	knot_quic_cleanup(&conn, 1);
	knot_quic_free_creds(table->creds);
	knot_quic_table_free(table);
	free(r);
}
