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
#include "utils/common/msg.h"

#include "contrib/quicly/defaults.h"
#include "contrib/quicly/streambuf.h"
#include "contrib/quicly/picotls/picotls.h"
#include "contrib/quicly/picotls/picotls/openssl.h"

static void on_stop_sending(quicly_stream_t *stream, int err)
{
	WARN("QUIC, stop sending has been received\n");
	quicly_close(stream->conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "");
}

static void on_receive_reset(quicly_stream_t *stream, int err)
{
	WARN("QUIC, stream reset has been received\n");
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
	struct recv_buf *buff = quic_conn_get_ctx(stream->conn);
	memcpy(buff->ptr, input.base, input.len);
	buff->ptr += input.len;

	/* remove used bytes from receive buffer */
	quicly_streambuf_ingress_shift(stream, input.len);
	/* 
	 * TODO Right now, im reading egress->written to get size of data, and ingress->base for data itself.
	 * It is possible, that ingress->base data are overwritten while processing message, and egress->written
	 * is overwritten for long packet data (received in 2 QUIC packets). It would be nice to verificate
	 * (test) it.
	*/
}

static int on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream)
{
	static const quicly_stream_callbacks_t stream_callbacks = {
		quicly_streambuf_destroy, quicly_streambuf_egress_shift, quicly_streambuf_egress_emit,
		on_stop_sending, on_receive, on_receive_reset
	};

	int ret;
	if ((ret = quicly_streambuf_create(stream, sizeof(quicly_streambuf_t))) != 0) {
		WARN("QUIC, unable to create streambuf")
		return ret;
	}
	stream->callbacks = &stream_callbacks;
	return 0;
}

int quic_ctx_init(quic_ctx_t *ctx, const quic_params_t *params, const int wait)
{
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
	ctx->wait = wait;

	return KNOT_EOK;
}

static void process_msg(quic_ctx_t *ctx, quicly_conn_t *conn, struct msghdr *msg, size_t dgram_len)
{
	size_t off, packet_len;

	/* split UDP datagram into multiple QUIC packets */
	for (off = 0; off < dgram_len; off += packet_len) {
		quicly_decoded_packet_t decoded;
		if ((packet_len = quicly_decode_packet(&ctx->quicly, &decoded, msg->msg_iov[0].iov_base + off, dgram_len - off)) == SIZE_MAX) {
			WARN("QUIC, unable to decode packet");
			return;
		}
		if (conn != NULL) {
			/* let the current connection handle ingress packets */
			quicly_receive(conn, NULL, msg->msg_name, &decoded);
		}
	}
}

static int send_one(const int fd, quicly_datagram_t *p)
{
	struct iovec vec = {.iov_base = p->data.base, .iov_len = p->data.len};
	struct msghdr mess = {
		.msg_name = &p->dest.sa, .msg_namelen = quicly_get_socklen(&p->dest.sa), .msg_iov = &vec, .msg_iovlen = 1};
	int ret;

	while ((ret = (int)sendmsg(fd, &mess, 0)) == -1 && errno == EINTR)
		; // spin-lock
	return ret;
}

int quic_ctx_connect(quic_ctx_t *ctx, const int fd, struct sockaddr *sa, const char *remote_str)
{
	const char *hostname = (ctx->params->hostname) ? ctx->params->hostname : remote_str;
	if (!hostname) {
		WARN("QUIC, undefined hostname")
		return KNOT_NET_ECONNECT;
	}

	int ret;
	if ((ret = quicly_connect(&ctx->client, &ctx->quicly, hostname, sa, NULL, &ctx->cid, ptls_iovec_init(NULL, 0), NULL, NULL)) != 0) {
		WARN("QUIC, connect failed\n");
		return KNOT_NET_ECONNECT;
	}

	ctx->pfd.fd = fd;
	ctx->pfd.events = POLLIN;
	ctx->pfd.revents = 0;
	
	return KNOT_EOK;
}

int quic_ctx_send(quic_ctx_t *ctx, const uint8_t *buf, const size_t buflen)
{
	quicly_stream_t *stream;
	quicly_open_stream(ctx->client, &stream, 0);

	if (!quicly_sendstate_is_open(&stream->sendstate)) {
		WARN("QUIC, error while sending");
		return KNOT_NET_ESEND;
	}

	/* write data to send buffer */
	quicly_streambuf_egress_write(stream, buf, buflen);

	/* message send, close the send-side of stream */
	quicly_streambuf_egress_shutdown(stream);

	return KNOT_EOK;
}

static int _quic_ctx_send(quic_ctx_t *ctx)
{
	quicly_datagram_t *dgrams[16];
	size_t num_dgrams = sizeof(dgrams) / sizeof(*dgrams);
	int ret = quicly_send(ctx->client, dgrams, &num_dgrams);
	if (ret == 0) {
		for (size_t j = 0; j < num_dgrams; ++j) {
			send_one(ctx->pfd.fd, dgrams[j]);
			ctx->quicly.packet_allocator->free_packet(ctx->quicly.packet_allocator, dgrams[j]);
		}
	}
	return ret;
}

int quic_ctx_receive(quic_ctx_t *ctx, uint8_t *buf, size_t buflen)
{
	// Get stream
	quicly_stream_t *stream;
	stream = quicly_get_stream(ctx->client, 0);
	
	// Setup receive buffer
	//quicly_streambuf_t *sbuf = (quicly_streambuf_t *)stream->data;
	//if(sbuf->ingress.is_allocated) {
	//	free(sbuf->ingress.base);
	//}
	//sbuf->ingress.base = buf;
	//sbuf->ingress.capacity = buflen;
	//sbuf->ingress.is_allocated = 0;
	ctx->buf.base = buf;
	ctx->buf.ptr = buf;
	ctx->buf.capacity = buflen;


	while (1) {
		// Send what needed to be sent by QUIC
		int ret = _quic_ctx_send(ctx);
		if (ret == QUICLY_ERROR_FREE_CONNECTION) {
			WARN("QUIC, connection lost");
			return KNOT_NET_ECONNECT;
		} else if (ret) {
			WARN("QUIC, error while receiving");
			return KNOT_NET_ERECV;
		}

		//if (quicly_recvstate_transfer_complete(&stream->recvstate)) {
		if (ctx->buf.ptr - ctx->buf.base) {
			//return sbuf->egress.bytes_written;
			return ctx->buf.ptr - ctx->buf.base;
		}

		//Receive
		if (poll(&ctx->pfd, 1, /*ctx->wait **/ 1000) < 0) {
			return KNOT_NET_ETIMEOUT;
		}
		if (ctx->pfd.revents & POLLIN) {
			uint8_t tmp_buf[4096];
			struct sockaddr_storage sa;

			struct iovec vec = {.iov_base = tmp_buf, .iov_len = sizeof(tmp_buf)};
			struct msghdr msg = {.msg_name = &sa, .msg_namelen = sizeof(sa), .msg_iov = &vec, .msg_iovlen = 1};

			ssize_t rret;
			rret = recvmsg(ctx->pfd.fd, &msg, 0);
			if (rret > 0) {
				process_msg(ctx, ctx->client, &msg, rret);
			}
		}
	}
}

void quic_ctx_close(quic_ctx_t *ctx)
{
	if (ctx) {
		quicly_close(ctx->client, 0, "");		
		_quic_ctx_send(ctx);
		quicly_free(ctx->client);
	}
}

struct recv_buf *quic_conn_get_ctx(quicly_conn_t *conn)
{
	return (struct recv_buf *)(quicly_get_context(conn) + 1);
}
