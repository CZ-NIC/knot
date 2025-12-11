/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>
#include <ngtcp2/ngtcp2.h>

#include "contrib/net.h"
#include "libknot/errcode.h"
#include "utils/kdig_qtest/qtest_quic.h"
#include "utils/common/msg.h"
#include "utils/kdig_qtest/qtest_kdig_params.h"
#include "utils/kdig_qtest/qtest_params.h"

int quic_params_copy(quic_params_t *dst, const quic_params_t *src)
{
	if (dst == NULL || src == NULL) {
		return KNOT_EINVAL;
	}

	dst->enable = src->enable;

	return KNOT_EOK;
}

void quic_params_clean(quic_params_t *params)
{
	if (params == NULL) {
		return;
	}

	params->enable = false;
}

#ifdef ENABLE_QUIC

#include <assert.h>
#include <poll.h>
#include <gnutls/crypto.h>

#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>

#include "contrib/macros.h"
#include "libdnssec/error.h"
#include "libdnssec/random.h"
#include "libknot/xdp/tcp_iobuf.h"

#define quic_get_encryption_level(level) ngtcp2_crypto_gnutls_from_gnutls_record_encryption_level(level)
// #define quic_send(ctx, sockfd, family) ctx->uc_net_cbs->quic_send_data(ctx, sockfd, family, NULL, 0)
#define set_application_error(ctx, error_code, reason, reason_len) \
	ngtcp2_ccerr_set_application_error(&(ctx)->last_err, \
	        error_code, reason, reason_len)
#define set_transport_error(ctx, error_code, reason, reason_len) \
	ngtcp2_ccerr_set_transport_error(&(ctx)->last_err, \
	        error_code, reason, reason_len)
#define gecount(ctx) \
	ctx->env->counter
#define iecount(ctx) \
	ctx->env->counter++;

const gnutls_datum_t doq_alpn = {
	(unsigned char *)"doq", 3
};

int recv_stream_data_cb(ngtcp2_conn *conn, uint32_t flags,
	int64_t stream_id, uint64_t offset, const uint8_t *data,
	size_t datalen, void *user_data, void *stream_user_data)
{
	(void)conn;
	(void)flags;
	(void)offset;
	(void)stream_user_data;

	quic_ctx_t *ctx = (quic_ctx_t *)user_data;

	if (stream_id != ctx->stream.id) {
		const uint8_t msg[] = "Unknown stream";
		set_application_error(ctx, DOQ_PROTOCOL_ERROR, msg, sizeof(msg) - 1);
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	struct iovec in = {
		.iov_base = (uint8_t *)data,
		.iov_len = datalen
	};

	int ret = knot_tcp_inbufs_upd(&ctx->stream.in_buffer, in, true,
	                              &ctx->stream.in_parsed,
	                              &ctx->stream.in_parsed_total);
	if (ret != KNOT_EOK) {
		const uint8_t msg[] = "Malformed payload";
		set_application_error(ctx, DOQ_PROTOCOL_ERROR, msg, sizeof(msg) - 1);
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	ctx->stream.in_parsed_it = 0;
	return 0;
}

int recv_stream_data_ignore_all_but_0(ngtcp2_conn *conn, uint32_t flags,
	int64_t stream_id, uint64_t offset, const uint8_t *data,
	size_t datalen, void *user_data, void *stream_user_data)
{
	(void)conn;
	(void)flags;
	(void)offset;
	(void)stream_user_data;

	quic_ctx_t *ctx = (quic_ctx_t *)user_data;

	if (stream_id != 0) {
		return KNOT_EOK;
	}

	struct iovec in = {
		.iov_base = (uint8_t *)data,
		.iov_len = datalen
	};

	int ret = knot_tcp_inbufs_upd(&ctx->stream.in_buffer, in, true,
	                              &ctx->stream.in_parsed,
	                              &ctx->stream.in_parsed_total);
	if (ret != KNOT_EOK) {
		const uint8_t msg[] = "Malformed payload";
		set_application_error(ctx, DOQ_PROTOCOL_ERROR, msg, sizeof(msg) - 1);
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	ctx->stream.in_parsed_it = 0;
	return 0;
}


static int stream_open_cb(ngtcp2_conn *conn, int64_t stream_id,
	void *user_data)
{
	(void)conn;

	quic_ctx_t *ctx = (quic_ctx_t *)user_data;
	set_application_error(ctx, DOQ_PROTOCOL_ERROR, NULL, 0);
	return NGTCP2_ERR_CALLBACK_FAILURE;
}

static int acked_stream_data_offset_cb(ngtcp2_conn *conn, int64_t stream_id,
	uint64_t offset, uint64_t datalen, void *user_data,
	void *stream_user_data)
{
	(void)conn;
	(void)offset;
	(void)stream_user_data;

	quic_ctx_t *ctx = (quic_ctx_t *)user_data;
	if (ctx->stream.id == stream_id) {
		ctx->stream.out_ack -= datalen;
	}
	return KNOT_EOK;
}

static int stream_close_cb(ngtcp2_conn *conn, uint32_t flags,
	int64_t stream_id, uint64_t app_error_code, void *user_data,
	void *stream_user_data)
{
	// ngtcp2_conn_extend_max_streams_bidi(conn, 1);
	(void)conn;
	(void)flags;
	(void)app_error_code;
	(void)stream_user_data;

	quic_ctx_t *ctx = (quic_ctx_t *)user_data;
	if (ctx && stream_id == ctx->stream.id) {
		ctx->stream.id = -1;
	}
	return KNOT_EOK;
}

static int quic_open_bidi_stream(quic_ctx_t *ctx)
{
	if (ctx->stream.id >= 0) {
		return KNOT_EOK;
	}

	int ret = ngtcp2_conn_open_bidi_stream(ctx->conn, &ctx->stream.id, NULL);
	if (ret) {
		return KNOT_ERROR;
	}
	return KNOT_EOK;
}

static void rand_cb(uint8_t *dest, size_t destlen,
	const ngtcp2_rand_ctx *rand_ctx)
{
	(void)rand_ctx;

	dnssec_random_buffer(dest, destlen);
}

static int get_new_connection_id_cb(ngtcp2_conn *conn, ngtcp2_cid *cid,
	uint8_t *token, size_t cidlen, void *user_data)
{
	(void)conn;

	quic_ctx_t *ctx = (quic_ctx_t *)user_data;

	if (dnssec_random_buffer(cid->data, cidlen) != DNSSEC_EOK) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}
	cid->datalen = cidlen;

	if (ngtcp2_crypto_generate_stateless_reset_token(token, ctx->secret,
		sizeof(ctx->secret), cid) != 0)
	{
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

static int stream_reset_cb(ngtcp2_conn *conn, int64_t stream_id,
	uint64_t final_size, uint64_t app_error_code, void *user_data,
	void *stream_user_data)
{
	quic_ctx_t *ctx = (quic_ctx_t *)user_data;
	if (ctx->stream.id == stream_id) {
		set_transport_error(ctx, NGTCP2_PROTOCOL_VIOLATION, NULL, 0);
		quic_ctx_close(ctx);
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

static int handshake_confirmed_cb(ngtcp2_conn *conn, void *user_data)
{
	(void)conn;

	quic_ctx_t *ctx = (quic_ctx_t *)user_data;
	ctx->state = CONNECTED;
	return 0;
}

static int recv_rx_key_cb(ngtcp2_conn *conn, ngtcp2_encryption_level level,
	void *user_data)
{
	quic_ctx_t *ctx = user_data;
	if (level == NGTCP2_ENCRYPTION_LEVEL_1RTT) {
		ctx->state = CONNECTED;
	}

	return 0;
}

static int hook_func(gnutls_session_t session, unsigned int htype,
	unsigned when, unsigned int incoming, const gnutls_datum_t *msg)
{
	(void)session;
	(void)htype;
	(void)when;
	(void)incoming;
	(void)msg;

	return GNUTLS_E_SUCCESS;
}

int quic_send_data(quic_ctx_t *ctx, int sockfd, int family,
	ngtcp2_vec *datav, size_t datavlen)
{
	uint8_t enc_buf[MAX_PACKET_SIZE];
	struct iovec msg_iov = {
		.iov_base = enc_buf,
		.iov_len = 0
	};
	struct msghdr msg = {
		.msg_iov = &msg_iov,
		.msg_iovlen = 1
	};
	uint64_t ts = ctx->cbs->quic_timestamp();

	uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_NONE;
	int64_t stream_id = -1;
	if (datavlen > 0) {
		flags = NGTCP2_WRITE_STREAM_FLAG_FIN;
		stream_id = ctx->stream.id;
	}
	ngtcp2_ssize send_datalen = 0;
	ngtcp2_ssize nwrite = ngtcp2_conn_writev_stream(ctx->conn,
		(ngtcp2_path *)ngtcp2_conn_get_path(ctx->conn), &ctx->pi,
		enc_buf, sizeof(enc_buf), &send_datalen, flags, stream_id,
		datav, datavlen, ts);
	if (nwrite <= 0) {
		switch(nwrite) {
		case 0:
			ngtcp2_conn_update_pkt_tx_time(ctx->conn, ts);
			return KNOT_EOK;
		case NGTCP2_ERR_WRITE_MORE:
			assert(0);
			return KNOT_NET_ESEND;
		default:
			set_transport_error(ctx,
				ngtcp2_err_infer_quic_transport_error_code(nwrite),
				NULL, 0);
			if (ngtcp2_err_is_fatal(nwrite)) {
				return KNOT_NET_ESEND;
			} else {
				return KNOT_EOK;
			}
		}
	}

	msg_iov.iov_len = (size_t)nwrite;

	int ret = ctx->cbs->net_ecn_set(sockfd, family, ctx->pi.ecn);
	if (ret != KNOT_EOK && ret != KNOT_ENOTSUP) {
		return ret;
	}

	if (sendmsg(sockfd, &msg, 0) == -1) {
		set_transport_error(ctx, NGTCP2_INTERNAL_ERROR, NULL, 0);
		return KNOT_NET_ESEND;
	}

	if (send_datalen > 0) {
		return send_datalen;
	}

	return KNOT_EOK;
}

int quic_send_data_test(quic_ctx_t *ctx, int sockfd, int family,
	ngtcp2_vec *datav, size_t datavlen)
{
	uint8_t enc_buf[MAX_PACKET_SIZE];
	struct iovec msg_iov = {
		.iov_base = enc_buf,
		.iov_len = 0
	};
	struct msghdr msg = {
		.msg_iov = &msg_iov,
		.msg_iovlen = 1
	};
	uint64_t ts = ctx->cbs->quic_timestamp();

	uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_NONE;
	int64_t stream_id = -1;
	if (datavlen > 0) {
		flags = NGTCP2_WRITE_STREAM_FLAG_FIN;
		stream_id = ctx->stream.id;
	}
	ngtcp2_ssize send_datalen = 0;
	if (ctx->env->scenario == 1 && stream_id != -1) {
		// return KNOT_EOK;
		return KNOT_EOK;
	}
	ngtcp2_ssize nwrite = ngtcp2_conn_writev_stream(ctx->conn,
		(ngtcp2_path *)ngtcp2_conn_get_path(ctx->conn), &ctx->pi,
		enc_buf, sizeof(enc_buf), &send_datalen, flags, stream_id,
		datav, datavlen, ts);
	if (nwrite <= 0) {
		switch(nwrite) {
		case 0:
			ngtcp2_conn_update_pkt_tx_time(ctx->conn, ts);
			return KNOT_EOK;
		case NGTCP2_ERR_WRITE_MORE:
			assert(0);
			return KNOT_NET_ESEND;
		default:
			set_transport_error(ctx,
				ngtcp2_err_infer_quic_transport_error_code(nwrite),
				NULL, 0);
			if (ngtcp2_err_is_fatal(nwrite)) {
				return KNOT_NET_ESEND;
			} else {
				return KNOT_EOK;
			}
		}
	}

	msg_iov.iov_len = (size_t)nwrite;

	int ret = ctx->cbs->net_ecn_set(sockfd, family, ctx->pi.ecn);
	if (ret != KNOT_EOK && ret != KNOT_ENOTSUP) {
		return ret;
	}

	if (sendmsg(sockfd, &msg, 0) == -1) {
		set_transport_error(ctx, NGTCP2_INTERNAL_ERROR, NULL, 0);
		return KNOT_NET_ESEND;
	}

	if (send_datalen > 0) {
		return send_datalen;
	}

	return KNOT_EOK;
}

int quic_send_data_split(quic_ctx_t *ctx, int sockfd, int family,
	ngtcp2_vec *datav, size_t datavlen)
{
	uint8_t enc_buf[MAX_PACKET_SIZE];
	struct iovec msg_iov = {
		.iov_base = enc_buf,
		.iov_len = 0
	};
	struct msghdr msg = {
		.msg_iov = &msg_iov,
		.msg_iovlen = 1
	};
	uint64_t ts = ctx->cbs->quic_timestamp();

	uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_NONE;
	int64_t stream_id = -1;
	if (datavlen > 0) {
		/* this testcase carries flag in env */
		flags = ctx->env->scenario;
		stream_id = ctx->stream.id;
	}
	ngtcp2_ssize send_datalen = 0;

	ngtcp2_ssize nwrite = ngtcp2_conn_writev_stream(ctx->conn,
		(ngtcp2_path *)ngtcp2_conn_get_path(ctx->conn), &ctx->pi,
		enc_buf, sizeof(enc_buf), &send_datalen, flags, stream_id,
		datav, datavlen, ts);
	if (nwrite <= 0) {
		switch(nwrite) {
		case 0:
			ngtcp2_conn_update_pkt_tx_time(ctx->conn, ts);
			return KNOT_EOK;
		case NGTCP2_ERR_WRITE_MORE:
			assert(0);
			return KNOT_NET_ESEND;
		case NGTCP2_ERR_STREAM_SHUT_WR:
			set_transport_error(ctx,
				ngtcp2_err_infer_quic_transport_error_code(nwrite),
				NULL, 0);
			return KNOT_NET_ESEND;
		default:
			set_transport_error(ctx,
				ngtcp2_err_infer_quic_transport_error_code(nwrite),
				NULL, 0);
			if (ngtcp2_err_is_fatal(nwrite)) {
				return KNOT_NET_ESEND;
			} else {
				return KNOT_EOK;
			}
		}
	}

	msg_iov.iov_len = (size_t)nwrite;

	int ret = ctx->cbs->net_ecn_set(sockfd, family, ctx->pi.ecn);
	if (ret != KNOT_EOK && ret != KNOT_ENOTSUP) {
		return ret;
	}

	if (sendmsg(sockfd, &msg, 0) == -1) {
		set_transport_error(ctx, NGTCP2_INTERNAL_ERROR, NULL, 0);
		return KNOT_NET_ESEND;
	}

	if (send_datalen > 0) {
		return send_datalen;
	}

	return KNOT_EOK;
}

int quic_send_data_stop_sending(quic_ctx_t *ctx, int sockfd, int family,
	ngtcp2_vec *datav, size_t datavlen)
{
	uint8_t enc_buf[MAX_PACKET_SIZE];
	struct iovec msg_iov = {
		.iov_base = enc_buf,
		.iov_len = 0
	};
	struct msghdr msg = {
		.msg_iov = &msg_iov,
		.msg_iovlen = 1
	};
	uint64_t ts = ctx->cbs->quic_timestamp();

	uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_NONE;
	int64_t stream_id = -1;
	if (datavlen > 0) {
		/* this testcase carries flag in env */
		flags = ctx->env->scenario;
		stream_id = ctx->stream.id;
	}
	ngtcp2_ssize send_datalen = 0;

	ngtcp2_ssize nwrite = ngtcp2_conn_writev_stream(ctx->conn,
		(ngtcp2_path *)ngtcp2_conn_get_path(ctx->conn), &ctx->pi,
		enc_buf, sizeof(enc_buf), &send_datalen, flags, stream_id,
		datav, datavlen, ts);
	if (nwrite <= 0) {
		switch(nwrite) {
		case 0:
			ngtcp2_conn_update_pkt_tx_time(ctx->conn, ts);
			return KNOT_EOK;
		case NGTCP2_ERR_WRITE_MORE:
			assert(0);
			return KNOT_NET_ESEND;
		case NGTCP2_ERR_STREAM_SHUT_WR:
			set_transport_error(ctx,
				ngtcp2_err_infer_quic_transport_error_code(nwrite),
				NULL, 0);
			return KNOT_NET_ESEND;
		default:
			set_transport_error(ctx,
				ngtcp2_err_infer_quic_transport_error_code(nwrite),
				NULL, 0);
			if (ngtcp2_err_is_fatal(nwrite)) {
				return KNOT_NET_ESEND;
			} else {
				return KNOT_EOK;
			}
		}
	}

	msg_iov.iov_len = (size_t)nwrite;

	int ret = ctx->cbs->net_ecn_set(sockfd, family, ctx->pi.ecn);
	if (ret != KNOT_EOK && ret != KNOT_ENOTSUP) {
		return ret;
	}

	if (sendmsg(sockfd, &msg, 0) == -1) {
		set_transport_error(ctx, NGTCP2_INTERNAL_ERROR, NULL, 0);
		return KNOT_NET_ESEND;
	}

	if (send_datalen > 0) {
		return send_datalen;
	}

	return KNOT_EOK;
}

int quic_recv(quic_ctx_t *ctx, int sockfd)
{
	uint8_t enc_buf[MAX_PACKET_SIZE];
	uint8_t msg_ctrl[CMSG_SPACE(sizeof(uint8_t))];
	struct sockaddr_in6 from = { 0 };
	struct iovec msg_iov = {
		.iov_base = enc_buf,
		.iov_len = sizeof(enc_buf)
	};
	struct msghdr msg = {
		.msg_name = &from,
		.msg_namelen = sizeof(from),
		.msg_iov = &msg_iov,
		.msg_iovlen = 1,
		.msg_control = msg_ctrl,
		.msg_controllen = sizeof(msg_ctrl),
		.msg_flags = 0
	};

	ssize_t nwrite = recvmsg(sockfd, &msg, 0);
	if (nwrite <= 0) {
		return knot_map_errno();
	}
	ngtcp2_pkt_info *pi = &ctx->pi;
	ctx->pi.ecn = net_cmsg_ecn(&msg);

	int ret = ngtcp2_conn_read_pkt(ctx->conn,
	                               ngtcp2_conn_get_path(ctx->conn),
	                               pi, enc_buf, nwrite,
	                               ctx->cbs->quic_timestamp());
	if (ngtcp2_err_is_fatal(ret)) {
		set_transport_error(ctx,
			ngtcp2_err_infer_quic_transport_error_code(ret),
			NULL, 0);
		return KNOT_NET_ERECV;
	}
	return KNOT_EOK;
}

int quic_recv_with_ack(quic_ctx_t *ctx, int sockfd)
{
	uint8_t enc_buf[MAX_PACKET_SIZE];
	uint8_t msg_ctrl[CMSG_SPACE(sizeof(uint8_t))];
	struct sockaddr_in6 from = { 0 };
	struct iovec msg_iov = {
		.iov_base = enc_buf,
		.iov_len = sizeof(enc_buf)
	};
	struct msghdr msg = {
		.msg_name = &from,
		.msg_namelen = sizeof(from),
		.msg_iov = &msg_iov,
		.msg_iovlen = 1,
		.msg_control = msg_ctrl,
		.msg_controllen = sizeof(msg_ctrl),
		.msg_flags = 0
	};

	ssize_t nwrite = recvmsg(sockfd, &msg, 0);
	if (nwrite <= 0) {
		return knot_map_errno();
	}
	ngtcp2_pkt_info *pi = &ctx->pi;
	ctx->pi.ecn = net_cmsg_ecn(&msg);

	int ret = ngtcp2_conn_read_pkt(ctx->conn,
	                               ngtcp2_conn_get_path(ctx->conn),
	                               pi, enc_buf, nwrite,
	                               ctx->cbs->quic_timestamp());
	if (ngtcp2_err_is_fatal(ret)) {
		set_transport_error(ctx,
			ngtcp2_err_infer_quic_transport_error_code(ret),
			NULL, 0);
		return KNOT_NET_ERECV;
	}

	// ctx->cbs->quic_send_data(ctx, sockfd, from.sin6_family, NULL, 0);
	return KNOT_EOK;
}

static int quic_respcpy(quic_ctx_t *ctx, uint8_t *buf, const size_t buf_len)
{
	assert(ctx && buf && buf_len > 0);
	if (ctx->stream.in_parsed != NULL) {
		knot_tcp_inbufs_upd_res_t *cur = ctx->stream.in_parsed;
		struct iovec *it = &cur->inbufs[ctx->stream.in_parsed_it];
		if (buf_len < it->iov_len) {
			return KNOT_ENOMEM;
		}
		size_t len = it->iov_len;
		memcpy(buf, it->iov_base, len);
		if (++ctx->stream.in_parsed_it == cur->n_inbufs) {
			ctx->stream.in_parsed_it = 0;
			ctx->stream.in_parsed = cur->next;
			free(cur);
		}
		return len;
	}
	return 0;
}

uint64_t quic_timestamp(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
		return 0;
	}

	return (uint64_t)ts.tv_sec * NGTCP2_SECONDS + (uint64_t)ts.tv_nsec;
}

uint64_t quic_timestamp_mock(void)
{
	return -1;
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
		return 0;
	}

	return (uint64_t)ts.tv_sec * NGTCP2_SECONDS + (uint64_t)ts.tv_nsec;
}

int quic_generate_secret(uint8_t *buf, size_t buflen)
{
	assert(buf != NULL && buflen > 0 && buflen <= 32);
	uint8_t rand[16], hash[32];
	int ret = dnssec_random_buffer(rand, sizeof(rand));
	if (ret != DNSSEC_EOK) {
		return KNOT_ERROR;
	}
	ret = gnutls_hash_fast(GNUTLS_DIG_SHA256, rand, sizeof(rand), hash);
	if (ret != 0) {
		return KNOT_ERROR;
	}
	memcpy(buf, hash, buflen);
	return KNOT_EOK;
}

int verify_certificate(gnutls_session_t session)
{
	quic_ctx_t *ctx = gnutls_session_get_ptr(session);
	return tls_certificate_verification(ctx->tls);
}

ngtcp2_conn *get_conn(ngtcp2_crypto_conn_ref *conn_ref)
{
	return ((quic_ctx_t *)conn_ref->user_data)->conn;
}

int quic_ctx_init(quic_ctx_t *ctx, tls_ctx_t *tls_ctx, const quic_params_t *params)
{
	if (ctx == NULL || tls_ctx == NULL || params == NULL) {
		return KNOT_EINVAL;
	}

	ctx->conn_ref = (ngtcp2_crypto_conn_ref) {
		.get_conn = ctx->cbs->get_conn,
		.user_data = ctx
	};
	ctx->params = *params;
	ctx->tls = tls_ctx;
	ctx->state = CLOSED;
	ctx->stream.id = -1;
	set_application_error(ctx, DOQ_NO_ERROR, NULL, 0);

	if (ctx->cbs->quic_generate_secret(ctx->secret, sizeof(ctx->secret)) != KNOT_EOK) {
		return KNOT_ENOMEM;
	}

	gnutls_certificate_set_verify_function(
		tls_ctx->credentials,
		ctx->cbs->verify_certificate);
	return KNOT_EOK;
}

int get_expiry(quic_ctx_t *ctx)
{
	ngtcp2_tstamp now = ctx->cbs->quic_timestamp();
	ngtcp2_tstamp expiry = ngtcp2_conn_get_expiry(ctx->conn);
	if (expiry == UINT64_MAX) {
		return -1;
	} else if (expiry < now) {
		return 0;
	}
	/* ceil((expiry - now) / NGTCP2_MILLISECONDS) */
	return (expiry - now + NGTCP2_MILLISECONDS - 1) / NGTCP2_MILLISECONDS;
}

static void user_printf(void *user_data, const char *format, ...)
{
	char buf[256];
	va_list args;
	va_start(args, format);
	(void)vsnprintf(buf, sizeof(buf), format, args);
	(void)printf("%s\n", buf);
	va_end(args);
}

int quic_ctx_connect(quic_ctx_t *ctx, int sockfd, struct addrinfo *dst_addr)
{
	if (connect(sockfd, (const struct sockaddr *)(dst_addr->ai_addr),
	            dst_addr->ai_addrlen) != 0)
	{
		return knot_map_errno();
	}

	ngtcp2_cid dcid, scid;
	scid.datalen = NGTCP2_MAX_CIDLEN;
	int ret = dnssec_random_buffer(scid.data, scid.datalen);
	if (ret != DNSSEC_EOK) {
		return ret;
	}
	dcid.datalen = 18;
	ret = dnssec_random_buffer(dcid.data, dcid.datalen);
	if (ret != DNSSEC_EOK) {
		return ret;
	}

	ngtcp2_settings settings;
	ngtcp2_settings_default(&settings);
	settings.initial_ts = ctx->cbs->quic_timestamp();
	settings.handshake_timeout = ctx->tls->wait * NGTCP2_SECONDS;
	settings.log_printf = user_printf;

	ngtcp2_transport_params params;
	ngtcp2_transport_params_default(&params);
	params.initial_max_streams_uni = 0;
	params.initial_max_streams_bidi = 0;
	params.initial_max_stream_data_bidi_local = NGTCP2_MAX_VARINT;
	params.initial_max_data = NGTCP2_MAX_VARINT;
	params.max_ack_delay = 1 * NGTCP2_SECONDS;
	params.max_idle_timeout = ctx->tls->wait * NGTCP2_SECONDS;

	struct sockaddr_in6 src_addr;
	socklen_t src_addr_len = sizeof(src_addr);
	ret = getsockname(sockfd, (struct sockaddr *)&src_addr, &src_addr_len);
	if (ret < 0) {
		return knot_map_errno();
	}
	ngtcp2_path path = {
		.local = {
			.addrlen = src_addr_len,
			.addr = (struct sockaddr *)&src_addr
		},
		.remote = {
			.addrlen = sizeof(*(dst_addr->ai_addr)),
			.addr = (struct sockaddr *)(dst_addr->ai_addr)
		},
		.user_data = NULL
	};

	if (ctx->conn) {
		ngtcp2_conn_del(ctx->conn);
		ctx->conn = NULL;
	}

	const ngtcp2_callbacks quic_client_callbacks = {
		ngtcp2_crypto_client_initial_cb,
		NULL, /* recv_client_initial */
		ngtcp2_crypto_recv_crypto_data_cb,
		NULL, /* handshake_completed */
		NULL, /* recv_version_negotiation */
		ngtcp2_crypto_encrypt_cb,
		ngtcp2_crypto_decrypt_cb,
		ngtcp2_crypto_hp_mask_cb,
		recv_stream_data_cb,
		// ctx->cbs->ngtcp2_recv_stream_data_cb,
		acked_stream_data_offset_cb,
		stream_open_cb,
		stream_close_cb,
		NULL, /* recv_stateless_reset */
		ngtcp2_crypto_recv_retry_cb,
		NULL, /* extend_max_bidi_streams */
		NULL, /* extend_max_local_streams_uni */
		rand_cb,
		get_new_connection_id_cb,
		NULL, /* remove_connection_id */
		ngtcp2_crypto_update_key_cb,
		NULL, /* path_validation */
		NULL, /* select_preferred_address */
		stream_reset_cb,
		NULL, /* extend_max_remote_streams_bidi */
		NULL, /* extend_max_remote_streams_uni */
		NULL, /* extend_max_stream_data */
		NULL, /* dcid_status */
		handshake_confirmed_cb,
		NULL, /* recv_new_token */
		ngtcp2_crypto_delete_crypto_aead_ctx_cb,
		ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
		NULL, /* recv_datagram */
		NULL, /* ack_datagram */
		NULL, /* lost_datagram */
		ngtcp2_crypto_get_path_challenge_data_cb,
		NULL, /* stream_stop_sending */
		ngtcp2_crypto_version_negotiation_cb,
		recv_rx_key_cb,
		NULL  /* recv_tx_key */
	};

	if (ngtcp2_conn_client_new(&ctx->conn, &dcid, &scid, &path,
	                           NGTCP2_PROTO_VER_V1, &quic_client_callbacks,
	                           &settings, &params, NULL, ctx) != 0) {
		return KNOT_NET_ECONNECT;
	}

	gnutls_handshake_set_hook_function(ctx->tls->session,
	                                   GNUTLS_HANDSHAKE_ANY,
	                                   GNUTLS_HOOK_POST, hook_func);
	ret = ngtcp2_crypto_gnutls_configure_client_session(ctx->tls->session);
	if (ret != KNOT_EOK) {
		return KNOT_NET_ECONNECT;
	}
	gnutls_session_set_ptr(ctx->tls->session, ctx);
	ngtcp2_conn_set_tls_native_handle(ctx->conn, ctx->tls->session);

	struct pollfd pfd = {
		.fd = sockfd,
		.events = POLLIN,
		.revents = 0,
	};
	ctx->tls->sockfd = sockfd;

	while (ctx->state != CONNECTED) {
		ret = ctx->cbs->quic_send_data(ctx, sockfd,
				dst_addr->ai_family, NULL, 0);
		if (ret != KNOT_EOK) {
			return ret;
		}

		int timeout = ctx->cbs->get_expiry(ctx);
		ret = poll(&pfd, 1, timeout);
		if (ret == 0) {
			ret = ngtcp2_conn_handle_expiry(ctx->conn,
					ctx->cbs->quic_timestamp());
			if (ret != 0) {
				WARN("QUIC, failed to send");
				return KNOT_ECONNABORTED;
			}
		} else if (ret < 0) {
			return knot_map_errno();
		}

		ret = ctx->cbs->quic_recv(ctx, sockfd);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

int offset_span(ngtcp2_vec **vec, size_t *veclen, size_t sub)
{
	ngtcp2_vec *new_vec = *vec;
	size_t new_veclen = *veclen;

	while (sub) {
		if (new_veclen == 0) {
			return KNOT_EINVAL;
		}
		size_t part = MIN(sub, new_vec->len);
		new_vec->base += part;
		new_vec->len -= part;
		sub -= part;
		const int empty = ((new_vec->len == 0) ? 1 : 0);
		new_vec += empty;
		new_veclen -= empty;
	}
	*vec = new_vec;
	*veclen = new_veclen;

	return KNOT_EOK;
}

static int split_query_vector(const uint8_t *buf, const size_t buf_len, size_t n,
		ngtcp2_vec ***datavs, size_t **sizes, void ***pointers)
{
	assert(n > 0 && buf_len > n);

	size_t split_size = buf_len / n;
	size_t remainder = buf_len % n;

	*datavs = calloc(n, sizeof(ngtcp2_vec *));
	if (!*datavs)
		return KNOT_ENOMEM;
	*sizes = calloc(n, sizeof(size_t));
	if (!*sizes) {
		free(*datavs);
		return KNOT_ENOMEM;
	}

	*pointers = malloc(n * 3 * sizeof(void *));
	if (!*pointers) {
		free(*datavs);
		free(*sizes);
		return KNOT_ENOMEM;
	}
	
	size_t offset = 0;
	int i = 0;
	int pi = 0;
	for (; i < n; i++) {
		(*datavs)[i] = calloc(2, sizeof(ngtcp2_vec));
		if (!(*datavs)[i]) {
			goto loop_fail;
		}
		size_t chunk_size = split_size + ((i == n - 1) ? remainder : 0);
		uint16_t pkt_size = htons(chunk_size);
		(*datavs)[i][0].base = malloc(sizeof(uint16_t));
		if (!(*datavs)[i][0].base)
			goto loop_fail;
		memcpy((*datavs)[i][0].base, &pkt_size, sizeof(uint16_t));
		(*datavs)[i][0].len = sizeof(uint16_t);

		(*datavs)[i][1].base = malloc(chunk_size);
		if (!(*datavs)[i][1].base)
			goto loop_fail;
		memcpy((*datavs)[i][1].base, buf + offset, chunk_size);
		(*datavs)[i][1].len = chunk_size;

		(*pointers)[pi++] = (*datavs)[i];
		(*pointers)[pi++] = (*datavs)[i][0].base;
		(*pointers)[pi++] = (*datavs)[i][1].base;
		(*sizes)[i] = 2;
		offset += chunk_size;
	}
	return pi;

loop_fail:
	for (int k = 0; k < i; k++) {
		if (!(*datavs)[k])
			break;
		if ((*datavs)[k][0].base)
			free((*datavs)[k][0].base);
		if ((*datavs)[k][1].base)
			free((*datavs)[k][1].base);
		free((*datavs)[k]);
	}

	free(*datavs);
	free(*sizes);
	free(*pointers);
	return KNOT_ENOMEM;
}

void split_vector_free(void **p, size_t *sizes, size_t pcount, ngtcp2_vec **datavs)
{
	for (int i = 0; i < pcount; i++) {
		free(p[i]);
	}

	free(sizes);
	free(datavs);
	free(p);
}

int quic_send_dns_query_split(quic_ctx_t *ctx, int sockfd, struct addrinfo *srv,
	const uint8_t *buf, const size_t buf_len)
{
	if (ctx == NULL || buf == NULL) {
		return KNOT_EINVAL;
	}

	if (ctx->state < CONNECTED) {
		return KNOT_ECONN;
	}

	size_t splits = ctx->env->counter;
	ngtcp2_vec **datavs = NULL;
	size_t *sizes = NULL;
	void **pointers = NULL;

	int pcount = split_query_vector(buf, buf_len, splits, &datavs, &sizes, &pointers);
	if (pcount < 0) {
		return pcount;
	}

	// ctx->env->scenario = NGTCP2_WRITE_STREAM_FLAG_NONE;

	struct pollfd pfd = {
		.fd = sockfd,
		.events = POLLIN,
		.revents = 0,
	};

	assert(ctx->stream.id < 0);
	// int ret = quic_open_uni_stream(ctx);
	int ret = quic_open_bidi_stream(ctx);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ctx->stream.out_ack = 0;
	for (int s = 0; s < splits; s++) {
		ctx->stream.out_ack += datavs[s][0].len + datavs[s][1].len;
	}

	int s = 0;
	size_t datavlen = sizes[s];
	/* This is on stack and doesn't pass correctly to send_data */
	ngtcp2_vec *pdatav = datavs[s];
	while (ctx->stream.out_ack > 0) {
		if (s < splits) {
			ret = ctx->cbs->quic_send_data(ctx, sockfd, srv->ai_family, pdatav, sizes[s]);
			if (ret < 0) {
				split_vector_free(pointers, sizes, pcount, datavs);
				WARN("QUIC, failed to send");
				return ret;
			} else if (ret > 0 && s + 1 < splits) {
				if (ret != pdatav[0].len + pdatav[1].len) {
					/* assume this test is able to send
					 * each chunk in one packet for simplicity */
					return KNOT_EINVAL;
				}
				++s;
				datavlen = sizes[s];
				pdatav = datavs[s];
			} else if (ret > 0) {
				++s;
				datavlen = 0;
				pdatav = NULL;
			}
		}

		int timeout = ctx->cbs->get_expiry(ctx);
		if (s + 1 >= splits) {
			ctx->env->scenario = NGTCP2_WRITE_STREAM_FLAG_FIN;
		}
		if (timeout > 0 && datavlen > 0) {
			continue;
		}

		/* Defering connections that spam the server might cause this
		 * poll to fail, possibly leading to this test failing.
		 * Increasing the timeout or temporarily
		 * diabling server side delays might help */
		ret = poll(&pfd, 1, timeout);

		if (ret < 0) {
			WARN("QUIC, failed to send");
			split_vector_free(pointers, sizes, pcount, datavs);
			return knot_map_errno();
		} else if (ret == 0) {
			ret = ngtcp2_conn_handle_expiry(ctx->conn,
					ctx->cbs->quic_timestamp());
			if (ret != 0) {
				WARN("QUIC, failed to send");
				split_vector_free(pointers, sizes, pcount, datavs);
				return KNOT_ECONNABORTED;
			}
			continue;
		}
		ret = ctx->cbs->quic_recv(ctx, sockfd);
		if (ret != KNOT_EOK) {
			WARN("QUIC, failed to send");
			split_vector_free(pointers, sizes, pcount, datavs);
			return ret;
		}
	}

	split_vector_free(pointers, sizes, pcount, datavs);
	return KNOT_EOK;
}

int quic_send_dns_query_sync(quic_ctx_t *ctx, int sockfd,
		struct addrinfo *srv, const uint8_t *buf, const size_t buf_len)
{
	if (ctx == NULL || buf == NULL) {
		return KNOT_EINVAL;
	}

	if (ctx->state < CONNECTED) {
		return KNOT_ECONN;
	}

	int ret;

	size_t splits = ctx->env->counter;
	ngtcp2_vec **datavs = NULL;
	size_t *sizes = NULL;
	void **pointers = NULL;

	int pcount = split_query_vector(buf, buf_len, splits, &datavs, &sizes, &pointers);
	if (pcount < 0) {
		return pcount;
	}

	// ctx->env->scenario = NGTCP2_WRITE_STREAM_FLAG_NONE;

	struct pollfd pfd = {
		.fd = sockfd,
		.events = POLLIN,
		.revents = 0,
	};

	assert(ctx->stream.id < 0);
	// int ret = quic_open_uni_stream(ctx);
	for (int i = 0; i < 10; i++) {
		ret = quic_open_bidi_stream(ctx);
		if (ret != KNOT_EOK) {
			printf("Failed to open %d. stream\n", i);
			return -1;
		}

		assert_int_equal(ctx->stream.id, i * 4);
		ctx->stream.id = -1;
	}
	ctx->stream.id = 0;

	ctx->stream.out_ack = 0;
	for (int s = 0; s < splits; s++) {
		ctx->stream.out_ack += datavs[s][0].len + datavs[s][1].len;
	}

	int s = 0;
	size_t datavlen = sizes[s];
	/* This is on stack and doesn't pass correctly to send_data */
	ngtcp2_vec *pdatav = datavs[s];
	while (ctx->stream.out_ack > 0) {
		if (s < splits) {
			int prev_ret = -1;
			for (int i = 0; i < 10; i++) {
				ctx->stream.id = i * 4;
				ret = ctx->cbs->quic_send_data(ctx, sockfd, srv->ai_family, pdatav, sizes[s]);
				/* Path MTU datagram */
				if (ret == 0) {
					// assert(i == 1);
					--i;
					continue;
				}

				if (prev_ret == -1) {
					prev_ret = ret;
				} else {
					assert_int_equal(prev_ret, ret);
				}
			}
			ctx->stream.id = 0;

			if (ret < 0) {
				split_vector_free(pointers, sizes, pcount, datavs);
				WARN("QUIC, failed to send");
				return ret;
			} else if (ret > 0 && s + 1 < splits) {
				if (ret != pdatav[0].len + pdatav[1].len) {
					/* assume this test is able to send
					 * each chunk in one packet for simplicity */
					return KNOT_EINVAL;
				}
				++s;
				datavlen = sizes[s];
				pdatav = datavs[s];
			} else if (ret > 0) {
				++s;
				datavlen = 0;
				pdatav = NULL;
			}
		}

		int timeout = ctx->cbs->get_expiry(ctx);
		if (s + 1 >= splits) {
			ctx->env->scenario = NGTCP2_WRITE_STREAM_FLAG_FIN;
		}
		if (timeout > 0 && datavlen > 0) {
			continue;
		}

		/* Defering connections that spam the server might cause this
		 * poll to fail, possibly leading to this test failing.
		 * Increasing the timeout or temporarily
		 * diabling server side delays might help */
		ret = poll(&pfd, 1, timeout);

		if (ret < 0) {
			WARN("QUIC, failed to send");
			split_vector_free(pointers, sizes, pcount, datavs);
			return knot_map_errno();
		} else if (ret == 0) {
			ret = ngtcp2_conn_handle_expiry(ctx->conn,
					ctx->cbs->quic_timestamp());
			if (ret != 0) {
				WARN("QUIC, failed to send");
				split_vector_free(pointers, sizes, pcount, datavs);
				return KNOT_ECONNABORTED;
			}
			continue;
		}
		ret = ctx->cbs->quic_recv(ctx, sockfd);
		if (ret != KNOT_EOK) {
			WARN("QUIC, failed to send");
			split_vector_free(pointers, sizes, pcount, datavs);
			return ret;
		}
	}

	split_vector_free(pointers, sizes, pcount, datavs);
	return KNOT_EOK;
}

int quic_send_dns_query(quic_ctx_t *ctx, int sockfd, struct addrinfo *srv,
	const uint8_t *buf, const size_t buf_len)
{
	if (ctx == NULL || buf == NULL) {
		return KNOT_EINVAL;
	}

	if (ctx->state < CONNECTED) {
		return KNOT_ECONN;
	}

	uint16_t query_length = htons(buf_len);
	ngtcp2_vec datav[] = {
		{(uint8_t *)&query_length, sizeof(uint16_t)},
		{(uint8_t *)buf, buf_len}
	};
	size_t datavlen = sizeof(datav) / sizeof(*datav);
	ngtcp2_vec *pdatav = datav;

	struct pollfd pfd = {
		.fd = sockfd,
		.events = POLLIN,
		.revents = 0,
	};

	assert(ctx->stream.id < 0);
	// int ret = quic_open_uni_stream(ctx);
	int ret = quic_open_bidi_stream(ctx);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ctx->stream.out_ack = 0;
	for (ngtcp2_vec *it = datav; it < datav + datavlen; ++it) {
		ctx->stream.out_ack += it->len;
	}

	while (ctx->stream.out_ack > 0) {
		ret = ctx->cbs->quic_send_data(ctx, sockfd, srv->ai_family, pdatav, datavlen);
		if (ret < 0) {
			WARN("QUIC, failed to send");
			return ret;
		} else if (ret > 0) {
			ret = ctx->cbs->offset_span(&pdatav, &datavlen, ret);
			if (ret != KNOT_EOK) {
				return ret;
			}
		}

		int timeout = ctx->cbs->get_expiry(ctx);
		if (timeout > 0 && datavlen > 0) {
			continue;
		}
		ret = poll(&pfd, 1, timeout);
		if (ret < 0) {
			WARN("QUIC, failed to send");
			return knot_map_errno();
		} else if (ret == 0) {
			ret = ngtcp2_conn_handle_expiry(ctx->conn,
					ctx->cbs->quic_timestamp());
			if (ret != 0) {
				ctx->last_err.error_code = ret;
				WARN("QUIC, failed to send");
				return KNOT_ECONNABORTED;
			}
			continue;
		}
		ret = ctx->cbs->quic_recv(ctx, sockfd);
		if (ret != KNOT_EOK) {
			WARN("QUIC, failed to send");
			return ret;
		}
	}

	return KNOT_EOK;
}

int quic_recv_dns_response(quic_ctx_t *ctx, uint8_t *buf, const size_t buf_len,
	struct addrinfo *srv)
{
	if (ctx == NULL || ctx->tls == NULL || buf == NULL) {
		return KNOT_EINVAL;
	}

	int ret = quic_respcpy(ctx, buf, buf_len);
	if (ret != 0) {
		return ret;
	} else if (ctx->stream.id < 0) {
		return KNOT_NET_ERECV;
	}

	int sockfd = ctx->tls->sockfd;

	struct pollfd pfd = {
		.fd = sockfd,
		.events = POLLIN,
		.revents = 0,
	};

	while (1) {
		int timeout = ctx->cbs->get_expiry(ctx);
		ret = poll(&pfd, 1, timeout);
		if (ret < 0) {
			WARN("QUIC, failed to receive reply (%s)",
			     knot_strerror(errno));
			return knot_map_errno();
		} else if (ret == 0) {
			ret = ngtcp2_conn_handle_expiry(ctx->conn,
					ctx->cbs->quic_timestamp());
			if (ret != 0) {
				WARN("QUIC, failed to send");
				return KNOT_ECONNABORTED;
			}
			goto send;
		}

		ret = ctx->cbs->quic_recv(ctx, sockfd);
		if (ret != KNOT_EOK) {
			WARN("QUIC, failed to receive reply (%s)",
			     knot_strerror(ret));
			return ret;
		}
		ret = quic_respcpy(ctx, buf, buf_len);
		if (ret != 0) {
			if (ret < 0) {
				WARN("QUIC, failed to receive reply (%s)",
				     knot_strerror(ret));
			}
			return ret;
		} else if (ctx->stream.id < 0) {
			return KNOT_NET_ERECV;
		}

	send:
		ret = ctx->cbs->quic_send_data(ctx, sockfd, srv->ai_family, NULL, 0);
		if (ret != KNOT_EOK) {
			WARN("QUIC, failed to receive reply (%s)",
			     knot_strerror(ret));
			return ret;
		}
	}

	WARN("QUIC, peer took too long to respond");
	const uint8_t msg[] = "Connection timeout";
	set_application_error(ctx, DOQ_REQUEST_CANCELLED, msg, sizeof(msg) - 1);
	return KNOT_NET_ETIMEOUT;
}

#define quic_ctx_write_close(ctx, dest, dest_len, ts) \
	ngtcp2_conn_write_connection_close((ctx)->conn, (ngtcp2_path *)ngtcp2_conn_get_path((ctx)->conn), \
		&(ctx)->pi, dest, dest_len, &(ctx)->last_err, ts)

void quic_ctx_close(quic_ctx_t *ctx)
{
	if (ctx == NULL || ctx->state == CLOSED) {
		return;
	}

	uint8_t enc_buf[MAX_PACKET_SIZE];
	struct iovec msg_iov = {
		.iov_base = enc_buf,
		.iov_len = 0
	};
	struct msghdr msg = {
		.msg_iov = &msg_iov,
		.msg_iovlen = 1
	};

	ngtcp2_ssize nwrite = quic_ctx_write_close(ctx, enc_buf, sizeof(enc_buf),
	                                           ctx->cbs->quic_timestamp());
	if (nwrite <= 0) {
		return;
	}

	msg_iov.iov_len = nwrite;

	struct sockaddr_in6 si = { 0 };
	socklen_t si_len = sizeof(si);
	if (getsockname(ctx->tls->sockfd, (struct sockaddr *)&si, &si_len) == 0) {
		(void)ctx->cbs->net_ecn_set(ctx->tls->sockfd, si.sin6_family, ctx->pi.ecn);
	}

	(void)sendmsg(ctx->tls->sockfd, &msg, 0);
	ctx->state = CLOSED;
}

void quic_ctx_deinit(quic_ctx_t *ctx)
{
	if (ctx == NULL) {
		return;
	}

	if (ctx->conn) {
		ngtcp2_conn_del(ctx->conn);
		ctx->conn = NULL;
	}

	if (ctx->stream.in_buffer.iov_base != NULL) {
		free(ctx->stream.in_buffer.iov_base);
		ctx->stream.in_buffer.iov_base = NULL;
	}

	while (ctx->stream.in_parsed != NULL) {
		knot_tcp_inbufs_upd_res_t *tofree = ctx->stream.in_parsed;
		ctx->stream.in_parsed = tofree->next;
		free(tofree);
	}
}

void print_quic(const quic_ctx_t *ctx)
{
	if (ctx == NULL || !ctx->params.enable || ctx->tls->session == NULL) {
		return;
	}

	char *msg = gnutls_session_get_desc(ctx->tls->session);
	printf(";; QUIC session (QUICv%d)-%s\n", ngtcp2_conn_get_negotiated_version(ctx->conn), msg);
	gnutls_free(msg);
}

#endif
