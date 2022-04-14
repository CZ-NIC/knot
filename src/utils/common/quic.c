/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#include "contrib/macros.h"
#include "libdnssec/random.h"
#include "libdnssec/error.h"
#include "libknot/errcode.h"
#include "utils/common/params.h"
#include "utils/common/quic.h"

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

#ifdef LIBNGTCP2

#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>

#define QUIC_DEFAULT_VERSION "-VERS-ALL:+VERS-TLS1.3"
#define QUIC_DEFAULT_CIPHERS "-CIPHER-ALL:+AES-128-GCM:+AES-256-GCM:+CHACHA20-POLY1305:+AES-128-CCM"
#define QUIC_DEFAULT_GROUPS  "-GROUP-ALL:+GROUP-SECP256R1:+GROUP-X25519:+GROUP-SECP384R1:+GROUP-SECP521R1"
#define QUIC_PRIORITIES      "%DISABLE_TLS13_COMPAT_MODE:NORMAL:"QUIC_DEFAULT_VERSION":"QUIC_DEFAULT_CIPHERS":"QUIC_DEFAULT_GROUPS

#define ALPN "\03doq\07doq-i03\07doq-i11"
#define ALPN_SIZE 3

uint64_t quic_timestamp(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
		return 0;
	}

	return (uint64_t)ts.tv_sec * NGTCP2_SECONDS + (uint64_t)ts.tv_nsec;
}

size_t quic_parse_alpn(gnutls_datum_t *dest, size_t maxlen, const char *in)
{
	unsigned char *ptr = (unsigned char *)in;
	size_t str_len = strlen(in);
	size_t idx = 0;
	for (; idx < maxlen && str_len > 0; ++idx) {
		const int len = *ptr;
		dest[idx].data = ptr + 1;
		dest[idx].size = len;
		ptr += len + 1;
		str_len -= len + 1;
	}
	return idx;
}

static int hook_func(gnutls_session_t session, unsigned int htype,
                     unsigned when, unsigned int incoming,
                     const gnutls_datum_t *msg)
{
	return 0;
}

// TODO maybe change a bit 'quic_open_bidi_stream' and 'extend_max_bidi_streams' functions
static int quic_open_bidi_stream(quic_ctx_t *ctx)
{
	if (ctx->stream.id != -1) {
		return KNOT_EINVAL;
	}

	ngtcp2_transport_params params;
	// TODO want local or remote *thinking*
	ngtcp2_conn_get_remote_transport_params(ctx->conn, &params);
	if (params.initial_max_streams_bidi < 1) {
		return KNOT_EINVAL;
	}

	int64_t stream_id;
	if (ngtcp2_conn_open_bidi_stream(ctx->conn, &stream_id, NULL) != 0) {
		return KNOT_EINVAL;
	}

	ctx->stream.id = stream_id;

	return KNOT_EOK;
}

static int secret_func(gnutls_session_t session,
        gnutls_record_encryption_level_t gtls_level, const void *rx_secret,
        const void *tx_secret, size_t secretlen)
{
	quic_ctx_t *ctx = (quic_ctx_t *)gnutls_session_get_ptr(session);
	ngtcp2_crypto_level level =
	  ngtcp2_crypto_gnutls_from_gnutls_record_encryption_level(gtls_level);

	if (rx_secret) {
		int ret = ngtcp2_crypto_derive_and_install_rx_key(ctx->conn,
		                NULL, NULL, NULL, level, rx_secret, secretlen);
		if (ret != 0) {
			return -1;
		}

		if (level == NGTCP2_CRYPTO_LEVEL_APPLICATION) {
			quic_open_bidi_stream(ctx);
		}
	}

	if (tx_secret &&
	    ngtcp2_crypto_derive_and_install_tx_key(ctx->conn, NULL, NULL,
	                             NULL, level, tx_secret, secretlen) != 0) {
		return -1;
	}

	return GNUTLS_E_SUCCESS;
}

static int read_func(gnutls_session_t session,
        gnutls_record_encryption_level_t gtls_level,
        gnutls_handshake_description_t htype, const void *data, size_t datalen)
{
	assert(htype != GNUTLS_HANDSHAKE_CHANGE_CIPHER_SPEC);

	quic_ctx_t *ctx = (quic_ctx_t *)gnutls_session_get_ptr(session);
	ngtcp2_crypto_level level =
	  ngtcp2_crypto_gnutls_from_gnutls_record_encryption_level(gtls_level);
	ngtcp2_conn_submit_crypto_data(ctx->conn, level, (const uint8_t *)data,
	                               datalen);

	return GNUTLS_E_SUCCESS;
}

static int alert_read_func(gnutls_session_t session,
        gnutls_record_encryption_level_t gtls_level,
        gnutls_alert_level_t alert_level, gnutls_alert_description_t alert)
{
	(void)gtls_level;
	(void)alert_level;

	quic_ctx_t *ctx = (quic_ctx_t *)gnutls_session_get_ptr(session);
	ctx->last_error = NGTCP2_CRYPTO_ERROR | alert;

	return GNUTLS_E_SUCCESS;
}

static int set_remote_transport_params(ngtcp2_conn *conn, const uint8_t *data,
        size_t datalen)
{
	ngtcp2_transport_params params;
	if (ngtcp2_decode_transport_params(&params,
	        NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS, data,
	        datalen) != 0)	{
		return -1;
	}

	if (ngtcp2_conn_set_remote_transport_params(conn, &params) != 0) {
		return -1;
	}

	return GNUTLS_E_SUCCESS;
}

static int tp_recv_func(gnutls_session_t session, const uint8_t *data,
        size_t datalen)
{
	quic_ctx_t *ctx = (quic_ctx_t *)gnutls_session_get_ptr(session);
	if (set_remote_transport_params(ctx->conn, data, datalen) != 0) {
		return -1;
	}

	return GNUTLS_E_SUCCESS;
}

static int append_local_transport_params(ngtcp2_conn *conn,
        gnutls_buffer_t extdata)
{
	ngtcp2_transport_params params;
	ngtcp2_conn_get_local_transport_params(conn, &params);

	uint8_t buf[64];

	ngtcp2_ssize nwrite = ngtcp2_encode_transport_params(buf, sizeof(buf),
	        NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO, &params);
	if (nwrite < 0) {
		return -1;
	}

	if (gnutls_buffer_append_data(extdata, buf, (size_t)nwrite) != 0) {
		return -1;
	}

	return GNUTLS_E_SUCCESS;
}

static int tp_send_func(gnutls_session_t session, gnutls_buffer_t extdata)
{
	quic_ctx_t *ctx = (quic_ctx_t *)gnutls_session_get_ptr(session);
	if (append_local_transport_params(ctx->conn, extdata) != 0) {
		return -1;
	}

	return GNUTLS_E_SUCCESS;
}

static int get_new_connection_id_cb(ngtcp2_conn *conn, ngtcp2_cid *cid,
        uint8_t *token, size_t cidlen, void *user_data)
{
	(void)conn;
	(void)user_data;
	quic_ctx_t *ctx = (quic_ctx_t *)user_data;

	if (dnssec_random_buffer(cid->data, cidlen) != DNSSEC_EOK) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}
	cid->datalen = cidlen;

	if (ngtcp2_crypto_generate_stateless_reset_token(token, ctx->secret,
	                                      sizeof(ctx->secret), cid) != 0) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

static int recv_stream_data(ngtcp2_conn *conn, uint32_t flags,
        int64_t stream_id, uint64_t offset, const uint8_t *data,
        size_t datalen, void *user_data, void *stream_user_data)
{
	quic_ctx_t *ctx = (quic_ctx_t *)user_data;
	uint8_t *ptr = (uint8_t *)data;
	uint8_t *response_size = (uint8_t *)&ctx->stream.resp_size;
	// TODO test for *slow loris*
	// TODO offset on XFR will be different (stream will not be closed)
	switch(offset) {
	case 0:
		if (datalen == 0) {
			break;
		}
		response_size[0] = *ptr;
		ptr++;
		datalen--;
		/* [[fallthrough]] */
	case 1:
		if (datalen == 0) {
			break;
		}
		response_size[1] = *ptr;
		ptr++;
		datalen--;
		ctx->stream.resp_size = ntohs(ctx->stream.resp_size);
	}
	offset -= MIN(offset, 2);

	// TODO better size control against malicious servers
	if(ctx->stream.nread + datalen > ctx->stream.rx_datalen) {
		datalen = ctx->stream.rx_datalen - ctx->stream.nread;
	}
	memcpy(ctx->stream.rx_data + offset, ptr, datalen);
	ctx->stream.nread += datalen;

	return 0;
}

static int acked_stream_data_offset(ngtcp2_conn *conn, int64_t stream_id,
        uint64_t offset, uint64_t datalen, void *user_data,
        void *stream_user_data)
{
	quic_ctx_t *ctx = (quic_ctx_t *)user_data;
	if (ctx && stream_id == ctx->stream.id) {
		// TODO stream data sent callback
		//ctx->stream.nwrite += offset + datalen;
	}
	return KNOT_EOK;
}

static int stream_close(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
        uint64_t app_error_code, void *user_data, void *stream_user_data)
{
	(void)flags;
	(void)app_error_code;
	(void)stream_user_data;

	quic_ctx_t *ctx = (quic_ctx_t *)user_data;
	if (ctx && stream_id == ctx->stream.id) {
		if (ctx->stream.nread == ctx->stream.resp_size) {
			printf("response OK\n");
		} else {
			printf("response not-OK\n");
		}
		ctx->stream.id = -1;
	}
	return KNOT_EOK;
}

static int extend_max_bidi_streams(ngtcp2_conn *conn, uint64_t max_streams,
        void *user_data)
{
	quic_ctx_t *ctx = (quic_ctx_t *)user_data;
	quic_open_bidi_stream(ctx);
	return 0;
}

static void rand_cb(uint8_t *dest, size_t destlen,
        const ngtcp2_rand_ctx *rand_ctx)
{
	(void)rand_ctx;

	dnssec_random_buffer(dest, destlen);
}

int quic_generate_secret(uint8_t *buf, size_t buflen)
{
	assert(buf != NULL && buflen > 0 && buflen <= 32);
	uint8_t rand[16], hash[32];
	int ret = dnssec_random_buffer(rand, sizeof(rand));
	if (ret != DNSSEC_EOK) {
		return ret;
	}
	ret = gnutls_hash_fast(GNUTLS_DIG_SHA256, rand, sizeof(rand), hash);
	if (ret != 0) {
		return ret;
	}
	memcpy(buf, hash, buflen);
	return KNOT_EOK;
}

int quic_ctx_init(quic_ctx_t *ctx, tls_ctx_t *tls_ctx,
        const quic_params_t *params)
{
	if (ctx == NULL || tls_ctx == NULL || params == NULL) {
		return KNOT_EINVAL;
	}

	ctx->params = *params;
	ctx->tls = tls_ctx;
	ctx->state = OPENING;
	ctx->stream.id = -1;
	if (quic_generate_secret(ctx->secret, sizeof(ctx->secret)) != KNOT_EOK) {
		return KNOT_ERROR;
	}

	return KNOT_EOK;
}

// static void user_qlog(void *user_data, uint32_t flags, const void *data, size_t datalen)
// {
// 	(void)user_data;
// 	FILE *qlog = fopen("/home/jhak/Work/knot-dns/knot.qlog", "a");
// 	if (qlog != NULL) {
// 		//fprintf(qlog, "\n%u: ", flags);
// 		for (size_t i = 0; i < datalen; i++) {
// 			fputc(*(uint8_t *)(data + i), qlog);
// 		}
// 		fclose(qlog);
// 	}
// }

static int handshake_confirmed(ngtcp2_conn *conn, void *user_data)
{
	quic_ctx_t *ctx = (quic_ctx_t *)user_data;
	ctx->state = CONNECTED;
	return 0;
}

int quic_set_enc(int sockfd, uint32_t ecn, int family)
{
	switch (family) {
	case AF_INET:
		if (setsockopt(sockfd, IPPROTO_IP, IP_TOS, &ecn,
		               (socklen_t)sizeof(ecn)) == -1) {
			return knot_map_errno();
		}
		break;
	case AF_INET6:
		if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_TCLASS, &ecn,
		               (socklen_t)sizeof(ecn)) == -1) {
			return knot_map_errno();
		}
		break;
	default:
		return KNOT_EINVAL;	
	}
	return KNOT_EOK;
}

static int quic_send(quic_ctx_t *ctx, int sockfd, const struct addrinfo *dst)
{
	uint8_t enc_buf[MAX_PACKET_SIZE];
	ngtcp2_ssize nwrite = 0;
	uint64_t ts = quic_timestamp();

	struct iovec msg_iov = {
		.iov_base = enc_buf,
		.iov_len = 0
	};
	struct msghdr msg = {
		.msg_iov = &msg_iov,
		.msg_iovlen = 1
	};

	uint8_t *data = ctx->stream.tx_data;
	size_t datalen = ctx->stream.tx_datalen;
	int64_t stream = -1;

	while(1) {
		ngtcp2_vec datavct[2];
		int datacnt = 0;
		ngtcp2_ssize wdatalen;
		uint16_t query_length = htons(datalen); //NOTE: Keep here becouse of var scope
		uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_NONE;
		if (datalen != 0) {
			datavct[0].base = (uint8_t *)&query_length;
			datavct[0].len = sizeof(query_length);
			datavct[1].base = data;
			datavct[1].len = (size_t)datalen;
			datacnt = 2;
			flags = NGTCP2_WRITE_STREAM_FLAG_FIN;
			stream = ctx->stream.id;
		} else {
			datavct[0].base = NULL;
			datavct[0].len = 0;
			stream = -1;
		}
		nwrite = ngtcp2_conn_writev_stream(ctx->conn,
		                (ngtcp2_path *)ngtcp2_conn_get_path(ctx->conn),
				&ctx->pi, enc_buf, sizeof(enc_buf), &wdatalen,
		                flags, stream, datavct, datacnt, ts);
		if (nwrite < 0) {
			// TODO error handling
			ctx->last_error = ngtcp2_err_infer_quic_transport_error_code((int)nwrite);
			return KNOT_NET_ESEND;
		}
		data = NULL;
		datalen = 0;
		stream = -1;

		if (nwrite == 0) {
			ngtcp2_conn_update_pkt_tx_time(ctx->conn, ts);
			break;
		}

		msg_iov.iov_len = (size_t)nwrite;

		int ret = quic_set_enc(sockfd, ctx->pi.ecn, dst->ai_family);
		if (ret != KNOT_EOK) {
			return ret;
		}

		do {
			nwrite = sendmsg(sockfd, &msg, 0);
		} while (nwrite == -1 && errno == EINTR);
	}
	return KNOT_EOK;
}

uint32_t quic_get_ecn(struct msghdr *msg, const int family)
{
	switch (family) {
	case AF_INET:
		for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg); cmsg;
		     cmsg = CMSG_NXTHDR(msg, cmsg)) {
			if (cmsg->cmsg_level == IPPROTO_IP &&
			    cmsg->cmsg_type == IP_TOS && cmsg->cmsg_len) {
				return *(uint8_t *)CMSG_DATA(cmsg);
			}
		}
		break;
	case AF_INET6:
		for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg); cmsg;
		     cmsg = CMSG_NXTHDR(msg, cmsg)) {
			if (cmsg->cmsg_level == IPPROTO_IPV6 &&
			    cmsg->cmsg_type == IPV6_TCLASS && cmsg->cmsg_len) {
				return *(uint8_t *)CMSG_DATA(cmsg);
			}
		}
		break;
	}

	return 0;
}

static ssize_t quic_recv(quic_ctx_t *ctx, int sockfd,
                         const struct addrinfo *dst)
{
	uint8_t enc_buf[MAX_PACKET_SIZE];
	uint8_t msg_ctrl[CMSG_SPACE(sizeof(uint8_t))];
	struct sockaddr_storage from = { 0 };
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
		.msg_controllen = sizeof(msg_ctrl)
	};

	ssize_t nwrite = recvmsg(sockfd, &msg, 0);
	if (nwrite <= 0) {
		return KNOT_NET_ECONNECT;
	}
	ctx->pi.ecn = quic_get_ecn(&msg, dst->ai_family);

	nwrite = ngtcp2_conn_read_pkt(ctx->conn,
	                              ngtcp2_conn_get_path(ctx->conn), &ctx->pi,
	                              enc_buf, nwrite, quic_timestamp());
	return nwrite;
}

int quic_ctx_connect(quic_ctx_t *ctx, int sockfd, const char *remote,
                     struct addrinfo *dst_addr)
{
	if (connect(sockfd, (const struct sockaddr *)(dst_addr->ai_addr),
	            sizeof(struct sockaddr_storage)) != 0) {
		return KNOT_NET_ECONNECT;
	}

	const ngtcp2_callbacks callbacks = {
		ngtcp2_crypto_client_initial_cb,
		NULL, /* recv_client_initial */
		ngtcp2_crypto_recv_crypto_data_cb,
		NULL, /* handshake_completed */
		NULL, /* recv_version_negotiation */
		ngtcp2_crypto_encrypt_cb,
		ngtcp2_crypto_decrypt_cb,
		ngtcp2_crypto_hp_mask_cb,
		recv_stream_data,
		acked_stream_data_offset,
		NULL, /* stream_open */
		stream_close,
		NULL, /* recv_stateless_reset */
		ngtcp2_crypto_recv_retry_cb,
		extend_max_bidi_streams,
		NULL, /* extend_max_local_streams_uni */
		rand_cb,
		get_new_connection_id_cb,
		NULL, /* remove_connection_id */
		ngtcp2_crypto_update_key_cb,
		NULL, /* path_validation */
		NULL, /* select_preferred_address */
		NULL, /* stream_reset */
		NULL, /* extend_max_remote_streams_bidi */
		NULL, /* extend_max_remote_streams_uni */
		NULL, /* extend_max_stream_data */
		NULL, /* dcid_status */
		handshake_confirmed,
		NULL, /* recv_new_token */
		ngtcp2_crypto_delete_crypto_aead_ctx_cb,
		ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
		NULL, /* recv_datagram */
		NULL, /* ack_datagram */
		NULL, /* lost_datagram */
		ngtcp2_crypto_get_path_challenge_data_cb,
		NULL, /* stream_stop_sending */
	};

	ngtcp2_cid dcid, scid;
	scid.datalen = 17;
	if (dnssec_random_buffer(scid.data, scid.datalen) != DNSSEC_EOK) {
		return KNOT_ERROR;
	}
	dcid.datalen = 18;
	if (dnssec_random_buffer(dcid.data, dcid.datalen) != DNSSEC_EOK) {
		return KNOT_ERROR;
	}

	// TODO revisit
	ngtcp2_settings settings;
	ngtcp2_settings_default(&settings);
	settings.initial_ts = quic_timestamp();
	/*
	settings.max_window = 6 * 1024 * 1024;
	settings.max_stream_window = 6 * 1024 * 1024;
	settings.max_udp_payload_size = 1362;
	settings.no_udp_payload_size_shaping = 1;
	*/
	// TODO maybe in "debug mode"
	//settings.qlog.write = user_qlog;

	// TODO revisit
	ngtcp2_transport_params params;
	ngtcp2_transport_params_default(&params);
	params.initial_max_stream_data_bidi_local = 256 * 1024;
	params.initial_max_stream_data_bidi_remote = 256 * 1024;
	params.initial_max_stream_data_uni = 256 * 1024;
	params.initial_max_data = 1024 * 1024;
	params.initial_max_streams_bidi = 1;
	params.initial_max_streams_uni = 3;
	params.active_connection_id_limit = 7;

	// TODO revisit
	struct sockaddr_in6 src_addr;
	socklen_t src_addr_len = sizeof(src_addr);
	getsockname(sockfd, (struct sockaddr *)&src_addr, &src_addr_len);
	ngtcp2_path path = {
		.local = {
			.addrlen = sizeof(src_addr),
			.addr = (struct sockaddr *)&src_addr
		},
		.remote = {
			.addrlen = sizeof(*(dst_addr->ai_addr)),
			.addr = (struct sockaddr *)(dst_addr->ai_addr)
		},
		.user_data = NULL
	};

	if (ngtcp2_conn_client_new(&ctx->conn, &dcid, &scid, &path,
	                           NGTCP2_PROTO_VER_V1, &callbacks, &settings,
	                           &params, NULL, ctx) != 0) {
		return KNOT_NET_ECONNECT;
	}

	int ret = gnutls_priority_set_direct(ctx->tls->session,
	                                     QUIC_PRIORITIES, NULL);
	if (ret != GNUTLS_E_SUCCESS) {
		return KNOT_NET_ECONNECT;
	}

	gnutls_handshake_set_hook_function(ctx->tls->session, GNUTLS_HANDSHAKE_ANY,
	                                   GNUTLS_HOOK_POST, hook_func);
	gnutls_handshake_set_secret_function(ctx->tls->session, secret_func);
	gnutls_handshake_set_read_function(ctx->tls->session, read_func);
	gnutls_alert_set_read_function(ctx->tls->session, alert_read_func);
	if (gnutls_session_ext_register(ctx->tls->session,
	        "QUIC Transport Parameters",
	        NGTCP2_TLSEXT_QUIC_TRANSPORT_PARAMETERS_V1, GNUTLS_EXT_TLS,
	        tp_recv_func, tp_send_func, NULL, NULL, NULL, GNUTLS_EXT_FLAG_TLS |
	        GNUTLS_EXT_FLAG_CLIENT_HELLO | GNUTLS_EXT_FLAG_EE) != 0)
	{
		return KNOT_NET_ECONNECT;
	}
	gnutls_session_set_ptr(ctx->tls->session, ctx);

	gnutls_datum_t alpn[ALPN_SIZE];
	size_t alpn_size = quic_parse_alpn(alpn, sizeof(alpn)/sizeof(*alpn), ALPN);
	if (alpn_size > 0) {
		ret = gnutls_alpn_set_protocols(ctx->tls->session,
		                (const gnutls_datum_t *)&alpn, alpn_size, 0);
		if (ret != GNUTLS_E_SUCCESS) {
			return KNOT_NET_ECONNECT;
		}
	}

	if (remote != NULL) {
		ret = gnutls_server_name_set(ctx->tls->session, GNUTLS_NAME_DNS, remote,
		                             strlen(remote));
		if (ret != GNUTLS_E_SUCCESS) {
			gnutls_deinit(ctx->tls->session);
			return KNOT_NET_ECONNECT;
		}
	}

	ngtcp2_conn_set_tls_native_handle(ctx->conn, ctx->tls->session);
	ctx->tls->sockfd = sockfd;
	// gnutls_transport_set_int(ctx->tls->session, sockfd);
	// gnutls_handshake_set_timeout(ctx->tls->session, 1000 * ctx->tls->wait);

	// Initialize poll descriptor structure.
	struct pollfd pfd = {
		.fd = sockfd,
		.events = POLLIN,
		.revents = 0,
	};

	while(ctx->state != CONNECTED) {
		ngtcp2_ssize nwrite = 0;
		ret = quic_send(ctx, sockfd, dst_addr);

		if (poll(&pfd, 1, -1) < 1) {	// TODO configurable timeout
			continue; // Resend
		}
		nwrite = quic_recv(ctx, sockfd, dst_addr);
		if (nwrite != 0) {
			// TODO errors
			switch (nwrite) {
			case NGTCP2_ERR_REQUIRED_TRANSPORT_PARAM:
			case NGTCP2_ERR_MALFORMED_TRANSPORT_PARAM:
			case NGTCP2_ERR_TRANSPORT_PARAM:
			case NGTCP2_ERR_PROTO:
				ctx->last_error = ngtcp2_err_infer_quic_transport_error_code(nwrite);
			default:
				if (!ctx->last_error) {
					ctx->last_error = ngtcp2_err_infer_quic_transport_error_code(nwrite);
				}
			}
			return KNOT_NET_ECONNECT;
		}
	}

	return KNOT_EOK;
}

int quic_send_dns_query(quic_ctx_t *ctx, int sockfd, struct addrinfo *srv,
        const uint8_t *buf, const size_t buf_len)
{
	if (ctx == NULL || buf == NULL) {
		return KNOT_NET_ESEND;
	}

	ctx->stream.tx_data = (uint8_t *)buf;
	ctx->stream.tx_datalen = buf_len;

	ngtcp2_ssize nwrite = quic_send(ctx, sockfd, srv);

	ctx->stream.tx_data = NULL;
	ctx->stream.tx_datalen = 0;

	return KNOT_EOK;
}

int quic_recv_dns_response(quic_ctx_t *ctx, uint8_t *buf, const size_t buf_len,
        struct addrinfo *srv, int timeout_ms)
{
	if (ctx == NULL || ctx->tls == NULL || buf == NULL) {
		return KNOT_EINVAL;
	}

	//const bool unlimited = timeout_ms < 0;
	int sockfd = ctx->tls->sockfd;
	ngtcp2_ssize nwrite;

	struct pollfd pfd = {
		.fd = sockfd,
		.events = POLLIN,
		.revents = 0,
	};

	ctx->stream.rx_data = buf;
	ctx->stream.rx_datalen = buf_len;
	ctx->stream.nread = 0;

	// TODO Timeout
	while (/*unlimited || timeout_ms > 0*/1) {

		// Wait for datagram data.
		ssize_t ret = poll(&pfd, 1, -1); // TODO Make configurable
		if (ret < 0) {
			return KNOT_NET_ESOCKET;
		}

		ret = quic_recv(ctx, sockfd, srv);
		if (ctx->stream.id < 0) {
			return ctx->stream.nread;
		}

		nwrite = quic_send(ctx, sockfd, srv);
	}

	return KNOT_NET_ETIMEOUT;
}

void quic_ctx_close(quic_ctx_t *ctx)
{
	if (ctx == NULL) {
		return;
	}

	// TODO Not implemented
	// ngtcp2_conn_write_connection_close();
}

void quic_ctx_deinit(quic_ctx_t *ctx)
{
	if (ctx == NULL) {
		return;
	}

	ngtcp2_conn_del(ctx->conn);
}

#endif
