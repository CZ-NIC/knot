/*  Copyright (C) 2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <poll.h>
#include <sys/time.h>

#include "libknot/errcode.h"
#include "utils/common/quic.h"

#include "contrib/quicly/defaults.h"
#include "contrib/quicly/streambuf.h"
#include "contrib/quicly/picotls/picotls.h"
#include "contrib/quicly/picotls/picotls/openssl.h"

static void on_stop_sending(quicly_stream_t *stream, int err)
{
	fprintf(stderr, "received STOP_SENDING: %" PRIu16 "\n", QUICLY_ERROR_GET_ERROR_CODE(err));
	quicly_close(stream->conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "");
}

static void on_receive_reset(quicly_stream_t *stream, int err)
{
	fprintf(stderr, "received RESET_STREAM: %" PRIu16 "\n", QUICLY_ERROR_GET_ERROR_CODE(err));
	quicly_close(stream->conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "");
}

static void on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len)
{
	/* read input to receive buffer */
	if (quicly_streambuf_ingress_receive(stream, off, src, len) != 0) {
		return;
	}

	/* obtain contiguous bytes from the receive buffer */
	ptls_iovec_t input = quicly_streambuf_ingress_get(stream);

	/* client: print to stdout */
	fwrite(input.base, 1, input.len, stdout);
	fflush(stdout);
	/* initiate connection close after receiving all data */
	if (quicly_recvstate_transfer_complete(&stream->recvstate)) {
		quicly_close(stream->conn, 0, "");
	}

	/* remove used bytes from receive buffer */
	quicly_streambuf_ingress_shift(stream, input.len);
}

static int on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream)
{
	static const quicly_stream_callbacks_t stream_callbacks = {
		quicly_streambuf_destroy, quicly_streambuf_egress_shift, quicly_streambuf_egress_emit,
		on_stop_sending, on_receive, on_receive_reset
	};
	int ret;

	if ((ret = quicly_streambuf_create(stream, sizeof(quicly_streambuf_t))) != 0)
		return ret;
	stream->callbacks = &stream_callbacks;
	return 0;
}

int quic_ctx_init(quic_ctx_t *ctx, const quic_params_t *params, int wait)
{
	ptls_openssl_sign_certificate_t sign_certificate;
	ptls_context_t tlsctx = {
		.random_bytes = ptls_openssl_random_bytes,
		.get_time = &ptls_get_time,
		.key_exchanges = ptls_openssl_key_exchanges,
		.cipher_suites = ptls_openssl_cipher_suites,
	};
	quicly_stream_open_t stream_open = {on_stream_open};

	/* setup quic context */
	ctx->quicly = quicly_spec_context;
	ctx->quicly.tls = &tlsctx;
	quicly_amend_ptls_context(ctx->quicly.tls);
	ctx->quicly.stream_open = &stream_open;

	ctx->params = params;

	return KNOT_EOK;
}



static void process_msg(quic_ctx_t *ctx, quicly_conn_t *conn, struct msghdr *msg, size_t dgram_len)
{
    size_t off, packet_len, i;

    /* split UDP datagram into multiple QUIC packets */
    for (off = 0; off < dgram_len; off += packet_len) {
        quicly_decoded_packet_t decoded;
        if ((packet_len = quicly_decode_packet(&ctx, &decoded, msg->msg_iov[0].iov_base + off, dgram_len - off)) == SIZE_MAX)
            return;
        /* TODO handle version negotiation, rebinding, retry, etc. */
        //if (quicly_is_destination(conn, NULL, msg->msg_name, &decoded)) {
		//}
        if (conn != NULL) {
            /* let the current connection handle ingress packets */
            quicly_receive(conn, NULL, msg->msg_name, &decoded);
        }
    }
}

static int send_one(int fd, quicly_datagram_t *p)
{
    struct iovec vec = {.iov_base = p->data.base, .iov_len = p->data.len};
    struct msghdr mess = {
        .msg_name = &p->dest.sa, .msg_namelen = quicly_get_socklen(&p->dest.sa), .msg_iov = &vec, .msg_iovlen = 1};
    int ret;

    while ((ret = (int)sendmsg(fd, &mess, 0)) == -1 && errno == EINTR)
        ;
    return ret;
}

static int quic_ctx_handshake(quic_ctx_t *ctx, struct pollfd *pfd)
{
	//quicly_conn_t *conns[256] = { ctx->client }; /* a null-terminated list of connections; proper app should use a hashmap or something */
	//int fd = pfd[0].fd;

	size_t i;
	while (1) {
		/* wait for sockets to become readable, or some event in the QUIC stack to fire */
		// struct timeval tv;
		// do {
		// 	int64_t first_timeout = INT64_MAX, now = ctx->quicly.now->cb(ctx->quicly.now);
		// 	for (i = 0; conns[i] != NULL; ++i) {
		// 	int64_t conn_timeout = quicly_get_first_timeout(conns[i]);
		// 		if (conn_timeout < first_timeout)
		// 			first_timeout = conn_timeout;
		// 	}
		// 	if (now < first_timeout) {
		// 		int64_t delta = first_timeout - now;
		// 		if (delta > 1000 * 1000)
		// 			delta = 1000 * 1000;
		// 		tv.tv_sec = delta / 1000;
		// 		tv.tv_usec = (delta % 1000) * 1000;
		// 	} else {
		// 		tv.tv_sec = 1000;
		// 		tv.tv_usec = 0;
		// 	}
		// } while (poll(pfd, 1, 1000) <= 0 && errno != EINTR);
		if (poll(pfd, 1, 1000) < 0 || errno == EINTR) {
			return KNOT_NET_ECONNECT;
		}

		if (pfd[0].revents & POLLIN) {
			/* read the QUIC fd */
			uint8_t buf[4096];
			struct sockaddr_storage sa;

			struct iovec vec = {.iov_base = buf, .iov_len = sizeof(buf)};
			struct msghdr msg = {.msg_name = &sa, .msg_namelen = sizeof(sa), .msg_iov = &vec, .msg_iovlen = 1};

			ssize_t rret;
			while ((rret = recvmsg(ctx->fd, &msg, 0)) == -1 && errno == EINTR)
				;
			if (rret > 0) {
				process_msg(ctx, ctx->client, &msg, rret);
			}
		}

		/* send QUIC packets, if any */
		quicly_datagram_t *dgrams[16];
		size_t num_dgrams = sizeof(dgrams) / sizeof(*dgrams);
		int ret = quicly_send(ctx->client, dgrams, &num_dgrams);
		switch (ret) {
		case 0: 
			if (num_dgrams) {
				size_t j;
				for (size_t j = 0; j < num_dgrams; ++j) {
					send_one(ctx->fd, dgrams[j]);
					ctx->quicly.packet_allocator->free_packet(ctx->quicly.packet_allocator, dgrams[j]);
				}
			} 
			else {
				return KNOT_EOK;
			}
			break;
		case QUICLY_ERROR_FREE_CONNECTION:
			/* connection has been closed, free, and exit when running as a client */
			quicly_free(ctx->client);
			ctx->client = NULL;
			return 0;
		default:
			fprintf(stderr, "quicly_send returned %d\n", ret);
			return 1;
		}
	}
	return KNOT_EOK;
}

int quic_ctx_connect(quic_ctx_t *ctx, struct pollfd *pfd, struct sockaddr *sa, socklen_t salen)
{

	int ret;
	if ((ret = quicly_connect(&ctx->client, &ctx->quicly, "homer", sa, NULL, &ctx->next_cid, ptls_iovec_init(NULL, 0), NULL, NULL)) != 0) {
		fprintf(stderr, "quicly_connect failed:%d\n", ret);
		return KNOT_NET_ECONNECT;
	}
	quicly_stream_t *stream; /* we retain the opened stream via the on_stream_open callback */
	quicly_open_stream(ctx->client, &stream, 0);

	if (ret = quic_ctx_handshake(ctx, pfd) != KNOT_EOK) {
		return KNOT_NET_ECONNECT;
	}

	ctx->fd = pfd->fd;
	
	return KNOT_EOK;
}

int quic_ctx_send(quic_ctx_t *ctx, const uint8_t *buf, const size_t buflen) {
	quicly_stream_t *stream;

	if ((stream = quicly_get_stream(ctx->client, 0)) == NULL || !quicly_sendstate_is_open(&stream->sendstate)) {
		return 0;
	}

	/* write data to send buffer */
	quicly_streambuf_egress_write(stream, buf, buflen);

	/* message send, close the send-side of stream */
	//quicly_streambuf_egress_shutdown(stream);

	/* send QUIC packets, if any */
	quicly_datagram_t *dgrams[16];
	size_t num_dgrams = sizeof(dgrams) / sizeof(*dgrams);
	int ret = quicly_send(ctx->client, dgrams, &num_dgrams);
	switch (ret) {
	case 0: 
		if (num_dgrams) {
			size_t j;
			for (size_t j = 0; j < num_dgrams; ++j) {
				send_one(ctx->fd, dgrams[j]);
				ctx->quicly.packet_allocator->free_packet(ctx->quicly.packet_allocator, dgrams[j]);
			}
		} 
		else {
			return KNOT_EOK;
		}
		break;
	case QUICLY_ERROR_FREE_CONNECTION:
		/* connection has been closed, free, and exit when running as a client */
		quicly_free(ctx->client);
		ctx->client = NULL;
		return 0;
	default:
		fprintf(stderr, "quicly_send returned %d\n", ret);
		return 1;
	}

	return KNOT_EOK;
}

int quic_ctx_receive(quic_ctx_t *ctx, uint8_t *buf, size_t buflen) {
	struct pollfd pfd = {
		.fd = ctx->fd,
		.events = POLLIN,
		.revents = 0
	};

	if (poll(&pfd, 1, 1000) < 0 || errno == EINTR) {
		return KNOT_NET_ECONNECT;
	}

	if (pfd.revents & POLLIN) {
		/* read the QUIC fd */
		uint8_t buf[4096];
		struct sockaddr_storage sa;

		struct iovec vec = {.iov_base = buf, .iov_len = sizeof(buf)};
		struct msghdr msg = {.msg_name = &sa, .msg_namelen = sizeof(sa), .msg_iov = &vec, .msg_iovlen = 1};

		ssize_t rret;
		while ((rret = recvmsg(ctx->fd, &msg, 0)) == -1 && errno == EINTR)
			;
		if (rret > 0) {
			process_msg(ctx, ctx->client, &msg, rret);
		}
	}
	return KNOT_EOK;
}