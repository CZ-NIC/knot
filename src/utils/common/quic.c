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

#include <poll.h>
#include <string.h>
#include <time.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>

#include "assert.h"
#include "libdnssec/random.h"
#include "libdnssec/error.h"
#include "libknot/errcode.h"
#include "utils/common/quic.h"

#define QUIC_DEFAULT_CIPHERS "NORMAL:-VERS-ALL:+VERS-TLS1.3:-CIPHER-ALL:+AES-128-GCM:+AES-256-GCM:+CHACHA20-POLY1305:+AES-128-CCM"
#define QUIC_DEFAULT_GROUPS "-GROUP-ALL:+GROUP-SECP256R1:+GROUP-X25519:+GROUP-SECP384R1:+GROUP-SECP521R1"

static uint64_t timestamp(void)
{
	struct timespec tp;
	if (clock_gettime(CLOCK_MONOTONIC, &tp) != 0) {
		assert(0);
	}

	return (uint64_t)tp.tv_sec * NGTCP2_SECONDS + (uint64_t)tp.tv_nsec;
}

static int secret_func(gnutls_session_t session,
                       gnutls_record_encryption_level_t gtls_level,
                       const void *rx_secret, const void *tx_secret,
                       size_t secretlen)
{
	quic_ctx_t *ctx = (quic_ctx_t *)gnutls_session_get_ptr(session);
	ngtcp2_crypto_level level =
	    ngtcp2_crypto_gnutls_from_gnutls_record_encryption_level(gtls_level);

	if (rx_secret &&
	    ngtcp2_crypto_derive_and_install_rx_key(ctx->conn, NULL, NULL, NULL,
	                                            level, rx_secret,
	                                            secretlen) != 0)
	{
		return -1;
	}

	if (ngtcp2_crypto_derive_and_install_tx_key(ctx->conn, NULL, NULL, NULL,
	                                            level, tx_secret,
	                                            secretlen) != 0)
	{
		return -1;
	}

	return 0;
}

static int read_func(gnutls_session_t session,
                     gnutls_record_encryption_level_t gtls_level,
                     gnutls_handshake_description_t htype, const void *data,
                     size_t len)
{
	assert(htype != GNUTLS_HANDSHAKE_CHANGE_CIPHER_SPEC);

	quic_ctx_t *ctx = (quic_ctx_t *)gnutls_session_get_ptr(session);
	ngtcp2_crypto_level level =
	      ngtcp2_crypto_gnutls_from_gnutls_record_encryption_level(gtls_level);
	if (ngtcp2_conn_submit_crypto_data(ctx->conn, level, (const uint8_t *)data,
	                                   len) != 0)
	{
		return -1;
	}

	return 0;
}

static int alert_read_func(gnutls_session_t session,
                           gnutls_record_encryption_level_t gtls_level,
                           gnutls_alert_level_t alert_level,
                           gnutls_alert_description_t alert)
{
	(void)gtls_level;
	(void)alert_level;

	quic_ctx_t *ctx = (quic_ctx_t *)gnutls_session_get_ptr(session);
	ctx->last_error = NGTCP2_CRYPTO_ERROR | alert;

	return 0;
}

static int set_remote_transport_params(ngtcp2_conn *conn, const uint8_t *data,
                                       size_t datalen)
{
	ngtcp2_transport_params params;
	if (ngtcp2_decode_transport_params(&params,
	                         NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS,
	                         data, datalen) != 0)
	{
		return -1;
	}

	if (ngtcp2_conn_set_remote_transport_params(conn, &params) != 0) {
		return -1;
	}

	return 0;
}

static int tp_recv_func(gnutls_session_t session, const uint8_t *data,
                        size_t datalen)
{
	quic_ctx_t *ctx = (quic_ctx_t *)gnutls_session_get_ptr(session);
	if (set_remote_transport_params(ctx->conn, data, datalen) != 0) {
		return -1;
	}

	return 0;
}

static int append_local_transport_params(ngtcp2_conn *conn,
                                         gnutls_buffer_t extdata)
{
	ngtcp2_transport_params params;
	uint8_t buf[64];

	ngtcp2_conn_get_local_transport_params(conn, &params);
	ngtcp2_ssize nwrite = ngtcp2_encode_transport_params(buf, sizeof(buf),
	                                 NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO,
	                                 &params);
	if (nwrite < 0) {
		return -1;
	}

	if (gnutls_buffer_append_data(extdata, buf, (size_t)nwrite) != 0) {
		return -1;
	}

	return 0;
}

static int tp_send_func(gnutls_session_t session, gnutls_buffer_t extdata)
{
	quic_ctx_t *ctx = (quic_ctx_t *)gnutls_session_get_ptr(session);

	if (append_local_transport_params(ctx->conn, extdata) != 0) {
		return -1;
	}

	return 0;
}

static int extend_max_local_streams_bidi(ngtcp2_conn *conn,
                                         uint64_t max_streams, void *user_data)
{
	(void)max_streams;
	int64_t stream_id;
	quic_ctx_t *ctx = user_data;

	if (ctx->stream.stream_id != -1) {
		return 0;
	}

	if (ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL) != 0) {
		return 0;
	}

	ctx->stream.stream_id = stream_id;

	return 0;
}

static void rand_cb(uint8_t *dest, size_t destlen,
                    const ngtcp2_rand_ctx *rand_ctx)
{
	(void)rand_ctx;

	dnssec_random_buffer(dest, destlen);
}

static int get_new_connection_id_cb(ngtcp2_conn *conn, ngtcp2_cid *cid,
                                    uint8_t *token, size_t cidlen,
                                    void *user_data)
{
	(void)conn;
	(void)user_data;

	if (dnssec_random_buffer(cid->data, cidlen) != DNSSEC_EOK) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}
	cid->datalen = cidlen;

	if (dnssec_random_buffer(token, NGTCP2_STATELESS_RESET_TOKENLEN) != DNSSEC_EOK) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

int quic_ctx_init(quic_ctx_t *ctx, tls_ctx_t *tls_ctx, const quic_params_t *params)
{
	if (ctx == NULL || tls_ctx == NULL) {
		return KNOT_EINVAL;
	}
	ctx->tls = tls_ctx;
	ctx->stream.stream_id = -1;
	ctx->params = params;
	return KNOT_EOK;
}

#include <stdio.h>

static int receive_data(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                         uint64_t offset, const uint8_t *data, size_t datalen,
                         void *user_data, void *stream_user_data)
{
	quic_ctx_t *ctx = (quic_ctx_t *)user_data;
	memcpy(ctx->stream.data + ctx->stream.nwrite, data, datalen);
	ctx->stream.nwrite += datalen;
	return KNOT_EOK;
}

int quic_ctx_connect(quic_ctx_t *ctx, int sockfd, const char *remote,
                     struct sockaddr_storage *dst_addr)
{
	//const char ALPN[] = "\x3""doq"; // Use this when draft will become RFC
	const char ALPN[] = "\x2""dq";
	gnutls_datum_t alpn = {
		.data = (uint8_t *)&ALPN[1],
		.size = ALPN[0]
	};
	const char priority[] = "%DISABLE_TLS13_COMPAT_MODE:"QUIC_DEFAULT_CIPHERS":"QUIC_DEFAULT_GROUPS;
	int ret = tls_ctx_connect(ctx->tls, sockfd, remote, false, dst_addr,
	                          &alpn, priority, false);
	if (ret != KNOT_EOK) {
		return ret;
	}

	gnutls_handshake_set_secret_function(ctx->tls->session, secret_func);
	gnutls_handshake_set_read_function(ctx->tls->session, read_func);
	gnutls_alert_set_read_function(ctx->tls->session, alert_read_func);
	ret = gnutls_session_ext_register(ctx->tls->session,
	        "QUIC Transport Parameters",
	        NGTCP2_TLSEXT_QUIC_TRANSPORT_PARAMETERS_V1, GNUTLS_EXT_TLS,
	        tp_recv_func, tp_send_func, NULL, NULL, NULL, GNUTLS_EXT_FLAG_TLS |
	        GNUTLS_EXT_FLAG_CLIENT_HELLO | GNUTLS_EXT_FLAG_EE);
	if (ret != 0) {
		return ret;
	}
	gnutls_session_set_ptr(ctx->tls->session, ctx);

	struct sockaddr_in6 src_addr;
	socklen_t src_addr_len = sizeof(src_addr);
	getsockname(sockfd, (struct sockaddr *)&src_addr, &src_addr_len);
	ngtcp2_path path = {
		.local = {
		 	.addrlen = sizeof(src_addr),
		 	.addr = (struct sockaddr *)&src_addr
		},
		.remote = {
			.addrlen = sizeof(struct sockaddr_storage),
			.addr = (struct sockaddr *)dst_addr
		},
		.user_data = NULL
	};

	const ngtcp2_callbacks callbacks = {
		ngtcp2_crypto_client_initial_cb,
		NULL, /* recv_client_initial */
		ngtcp2_crypto_recv_crypto_data_cb,
		NULL, /* handshake_completed */
		NULL, /* recv_version_negotiation */
		ngtcp2_crypto_encrypt_cb,
		ngtcp2_crypto_decrypt_cb,
		ngtcp2_crypto_hp_mask_cb,
		receive_data,
		NULL, /* acked_stream_data_offset */
		NULL, /* stream_open */
		NULL, /* stream_close */
		NULL, /* recv_stateless_reset */
		ngtcp2_crypto_recv_retry_cb,
		extend_max_local_streams_bidi,
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
		NULL, /* handshake_confirmed */
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
	ngtcp2_settings settings;
	ngtcp2_transport_params params;

	dcid.datalen = NGTCP2_MIN_INITIAL_DCIDLEN;
	if (dnssec_random_buffer(dcid.data, dcid.datalen) != DNSSEC_EOK) {
		return KNOT_ERROR;
	}

	scid.datalen = 8;
	if (dnssec_random_buffer(scid.data, scid.datalen) != DNSSEC_EOK) {
		return KNOT_ERROR;
	}

	ngtcp2_settings_default(&settings);
	settings.initial_ts = timestamp();

	ngtcp2_transport_params_default(&params);
	params.initial_max_streams_bidi = 1;
	params.initial_max_stream_data_bidi_local = 128 * 1024;
	params.initial_max_data = 1024 * 1024;

	if (ngtcp2_conn_client_new(&ctx->conn, &dcid, &scid, &path,
	                           NGTCP2_PROTO_VER_V1, &callbacks, &settings,
	                           &params, NULL, ctx) != 0) {
		return KNOT_ERROR;
	}

	ngtcp2_conn_set_tls_native_handle(ctx->conn, ctx->tls->session);

	return KNOT_EOK;
}

int quic_send_dns_query(quic_ctx_t *ctx, int sockfd, struct addrinfo *srv, const uint8_t *buf, const size_t buf_len)
{
	if (ctx->stream.stream_id != -1) {
		return KNOT_NET_ESEND;
	}

	ctx->stream.data = buf;
	ctx->stream.datalen = buf_len;

	uint8_t enc_buf[1280];
	ngtcp2_vec data[2];
	ngtcp2_pkt_info pi = { 0 };
	uint32_t flags;
	ngtcp2_ssize wdatalen;
	int datacnt = 0;

	//for (;;) {
	while (ctx->stream.nwrite < ctx->stream.datalen) {
		flags = 0;
		bool final = false;
		uint16_t tmp = htons(ctx->stream.datalen - ctx->stream.nwrite);
		if (ctx->stream.stream_id >= 0 && ctx->stream.nwrite < ctx->stream.datalen) {
			/*this*/
			// data[0].base = (uint8_t *)&tmp;
			// data[0].len = sizeof(tmp);
			// data[1].base = (uint8_t *)(ctx->stream.data + ctx->stream.nwrite);
			// data[1].len = ctx->stream.datalen - ctx->stream.nwrite;
			// datacnt = 2;
			/*or*/
			data[0].base = (uint8_t *)(ctx->stream.data + ctx->stream.nwrite);
			data[0].len = ctx->stream.datalen - ctx->stream.nwrite;
			datacnt = 1;
			/*end*/
			final = true;
		} else {
			datacnt = 0;
		}
		flags = 0;
		//flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
		if (final) {
			flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
		}

		struct sockaddr_in6 src_addr;
		socklen_t src_addr_len = sizeof(src_addr);
		getsockname(sockfd, (struct sockaddr *)&src_addr, &src_addr_len);
		ctx->path.local.addr = (struct  sockaddr *)&src_addr;
		ctx->path.local.addrlen = src_addr_len;
		ctx->path.remote.addr = srv->ai_addr;
		ctx->path.remote.addrlen = srv->ai_addrlen;

		ngtcp2_ssize nwrite = ngtcp2_conn_writev_stream(ctx->conn, &ctx->path, &pi,
		        enc_buf, sizeof(enc_buf), &wdatalen, flags, ctx->stream.stream_id, data,
		        datacnt, timestamp());
		if (nwrite <= 0) {
			switch (nwrite) {
			case 0:
				return 0;
			case NGTCP2_ERR_WRITE_MORE:
				ctx->stream.nwrite += (size_t)wdatalen;
				break;
			default:
				ctx->last_error = ngtcp2_err_infer_quic_transport_error_code((int)nwrite);
				//return -1;
			}
		}

		do {
			nwrite = sendto(sockfd, enc_buf, nwrite, MSG_DONTWAIT, srv->ai_addr, srv->ai_addrlen);
		} while (nwrite == -1 && errno == EINTR);

		if (wdatalen > 0) {
			ctx->stream.nwrite += (size_t)wdatalen;
			return KNOT_EOK;
		}
		// if (nwrite == -1) {
		// 	return -1;
		// }

		struct pollfd pfd = {
			.fd = sockfd,
			.events = POLLIN,
			.revents = 0,
		};

		if (poll(&pfd, 1, 1000) != 1) {	
			continue;
		}

		struct sockaddr_storage from = { 0 };
		socklen_t from_len = sizeof(from);

		nwrite = recvfrom(sockfd, enc_buf, sizeof(enc_buf), 0, (struct sockaddr *)&from, &from_len);
		if (nwrite <= 0) {
			return KNOT_NET_ERECV;
		}

		ctx->path.remote.addr = (struct sockaddr *)&from;
		ctx->path.remote.addrlen = from_len;

		nwrite = ngtcp2_conn_read_pkt(ctx->conn, &ctx->path, &pi, enc_buf, nwrite, timestamp());
		if (nwrite != 0) {
			// fprintf(stderr, "ngtcp2_conn_read_pkt: %s\n", ngtcp2_strerror(rv));
			switch (nwrite) {
			case NGTCP2_ERR_REQUIRED_TRANSPORT_PARAM:
			case NGTCP2_ERR_MALFORMED_TRANSPORT_PARAM:
			case NGTCP2_ERR_TRANSPORT_PARAM:
			case NGTCP2_ERR_PROTO:
				ctx->last_error = ngtcp2_err_infer_quic_transport_error_code(nwrite);
				break;
			default:
				if (!ctx->last_error) {
					ctx->last_error = ngtcp2_err_infer_quic_transport_error_code(nwrite);
				}
				break;
			}
			return -1;
		}
	}

	return KNOT_EOK;
}