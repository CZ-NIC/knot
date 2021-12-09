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
#include <string.h>
#include <time.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#include "contrib/macros.h"
#include "libdnssec/random.h"
#include "libdnssec/error.h"
#include "libknot/errcode.h"
#include "libknot/quic/shared.h"
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

static uint64_t quic_timestamp(void)
{
	struct timespec tp;
	if (clock_gettime(CLOCK_MONOTONIC, &tp) != 0) {
		assert(0);
	}

	return (uint64_t)tp.tv_sec * NGTCP2_SECONDS + (uint64_t)tp.tv_nsec;
}

static int hook_func(gnutls_session_t session, unsigned int htype,
                     unsigned when, unsigned int incoming,
                     const gnutls_datum_t *msg)
{
	return 0;
}

static int extend_max_local_streams_bidi(ngtcp2_conn *conn,
        uint64_t max_streams, void *user_data);

static int secret_func(gnutls_session_t session,
        gnutls_record_encryption_level_t gtls_level, const void *rx_secret,
        const void *tx_secret, size_t secretlen)
{
	quic_ctx_t *ctx = (quic_ctx_t *)gnutls_session_get_ptr(session);
	ngtcp2_crypto_level level =
	        ngtcp2_crypto_gnutls_from_gnutls_record_encryption_level(
	                gtls_level
	        );

	// if (rx_secret && ngtcp2_crypto_derive_and_install_rx_key(ctx->conn, NULL,
	//         NULL, NULL, level, rx_secret, secretlen) != 0) {
	// 	return -1;
	// }
	if (rx_secret) {
		if (ngtcp2_crypto_derive_and_install_rx_key(ctx->conn, NULL,
		                NULL, NULL, level, rx_secret, secretlen) != 0)
		{
			return -1;
		}

		// if (level == NGTCP2_CRYPTO_LEVEL_APPLICATION &&
		//                 ctx->stream.stream_id == -1 &&
		//                 extend_max_local_streams_bidi(ctx->conn, 3,
		//                 ctx) != 0) {
		// 	return -1;
		// }
	}

	// if (tx_secret && ngtcp2_crypto_derive_and_install_tx_key(ctx->conn, NULL,
	//         NULL, NULL, level, tx_secret, secretlen) != 0) {
	// 	return -1;
	// }
	if (tx_secret) {
		if (ngtcp2_crypto_derive_and_install_tx_key(ctx->conn, NULL,
		                NULL, NULL, level, tx_secret,
		                secretlen) != 0) {
			return -1;
		}
		// if (level == NGTCP2_CRYPTO_LEVEL_APPLICATION &&
		//                 ctx->stream.stream_id == -1 &&
		//                 extend_max_local_streams_bidi(ctx->conn, 3,
		//                 ctx) != 0) {
		// 	return -1;
		// }
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

static int tp_recv_func(gnutls_session_t session, const uint8_t *data,
        size_t datalen)
{
	ngtcp2_transport_params params;
	quic_ctx_t *ctx = (quic_ctx_t *)gnutls_session_get_ptr(session);

	if ((ngtcp2_decode_transport_params(&params,
	                NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS,
	                data, datalen) != 0) ||
	        (ngtcp2_conn_set_remote_transport_params(ctx->conn,
	                &params) != 0)) {
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
	(void)user_data;
	quic_ctx_t *ctx = (quic_ctx_t *)user_data;

	if (dnssec_random_buffer(cid->data, cidlen) != DNSSEC_EOK) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}
	cid->datalen = cidlen;

	if (ngtcp2_crypto_generate_stateless_reset_token(token, ctx->secret, sizeof(ctx->secret), cid) != 0) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

static int extend_max_local_streams_bidi(ngtcp2_conn *conn,
        uint64_t max_streams, void *user_data)
{
	if (max_streams < 1) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	quic_ctx_t *ctx = user_data;
	if (ctx->stream.stream_id != -1) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	int64_t stream_id;
	if (ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL) != 0) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}
	ctx->stream.stream_id = stream_id;

	return 0;
}

static int recv_stream_data(ngtcp2_conn *conn, uint32_t flags,
        int64_t stream_id, uint64_t offset, const uint8_t *data,
        size_t datalen, void *user_data, void *stream_user_data)
{
	quic_ctx_t *ctx = (quic_ctx_t *)user_data;
	
	if (ctx->stream.rx_data == NULL || ctx->stream.rx_datalen == 0) {
		return 0;
	} else if (ctx && (stream_id == ctx->stream.stream_id) &&
	    (offset + datalen < ctx->stream.rx_datalen)) {

		// TODO need to be tested
		/*
		 * Getting the message size from the first 2 octets with respect to the
		 * message offset.
		 */
		uint16_t resp_size;
		if (offset < sizeof(resp_size)) {
			uint8_t *resp_size_b = (uint8_t *)&resp_size;
			memcpy((void *)&resp_size_b[offset], data,
			       MIN(datalen, sizeof(resp_size) - offset));
		}
		resp_size = ntohs(resp_size);
		ctx->stream.resp_size |= resp_size;
		const size_t offset_threshold = MIN(sizeof(resp_size), offset);
		const size_t off = sizeof(resp_size) - offset_threshold;
		if (datalen - off > 0) {
			resp_size = ntohs(resp_size);
			memcpy(ctx->stream.rx_data + offset - offset_threshold, data + off,
			       datalen - off);
			ctx->stream.nread += offset + datalen;
		}
	} else {
		// TODO Improve problem solving
		assert(0);
	}
	if ((flags & NGTCP2_STREAM_DATA_FLAG_FIN) ||
	    ctx->stream.resp_size == ctx->stream.nread) {
		ctx->stream.stream_id = -1;
	}

	return 0;
}

static int acked_stream_data_offset(ngtcp2_conn *conn, int64_t stream_id,
        uint64_t offset, uint64_t datalen, void *user_data,
        void *stream_user_data)
{
	quic_ctx_t *ctx = (quic_ctx_t *)user_data;
	if (ctx && stream_id == ctx->stream.stream_id) {
		ctx->stream.nwrite += offset + datalen;
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
	if (ctx && stream_id == ctx->stream.stream_id) {
		ctx->stream.stream_id = -1;
	}
	return KNOT_EOK;
}


static int handshake_completed(ngtcp2_conn *conn, void *user_data)
{
	if (false /* early_data_ && !tls_session_.get_early_data_accepted() */) {
		// if (auto rv = ngtcp2_conn_early_data_rejected(conn_); rv != 0) {
			// std::cerr << "ngtcp2_conn_early_data_rejected: " << ngtcp2_strerror(rv) << std::endl;
			return -1;
		// }

		// nghttp3_conn_del(httpconn_);
		// httpconn_ = nullptr;

		// nstreams_done_ = 0;
		// streams_.clear();

		// if (setup_httpconn() != 0) {
		// 	return -1;
		// }
	}

//   if (!config.quiet) {
//     std::cerr << "Negotiated cipher suite is " << tls_session_.get_cipher_name()
//               << std::endl;
//     std::cerr << "Negotiated ALPN is " << tls_session_.get_selected_alpn()
//               << std::endl;
//   }
	quic_ctx_t *ctx = (quic_ctx_t *)user_data;
	if(ctx->stream.stream_id < 0) {
		extend_max_local_streams_bidi(conn, 1, user_data);
	}

	return 0;
}

static int quic_generate_secret(uint8_t *buf, size_t buflen) {
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

int quic_ctx_init(quic_ctx_t *ctx, tls_ctx_t *tls_ctx, const quic_params_t *params)
{
	if (ctx == NULL || tls_ctx == NULL || params == NULL) {
		return KNOT_EINVAL;
	}

	ctx->tls = tls_ctx;
	ctx->stream.stream_id = -1;
	ctx->params = *params;
	if (quic_generate_secret(ctx->secret, sizeof(ctx->secret)) != KNOT_EOK) {
		return KNOT_ERROR;
	}

	return KNOT_EOK;
}

#define ALPN "\02dq"

int quic_ctx_connect(quic_ctx_t *ctx, int sockfd, const char *remote,
        struct addrinfo *dst_addr)
{
	if (connect(sockfd, (struct sockaddr *)(dst_addr->ai_addr), sizeof(struct sockaddr_storage)) != 0) {
		return KNOT_NET_ECONNECT;
	}

	const ngtcp2_callbacks callbacks = {
		ngtcp2_crypto_client_initial_cb,
		NULL, /* recv_client_initial */
		ngtcp2_crypto_recv_crypto_data_cb,
		handshake_completed, /* handshake_completed */
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
		NULL, /* extend_max_local_streams_bidi */
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
	scid.datalen = 17;
	if (dnssec_random_buffer(scid.data, scid.datalen) != DNSSEC_EOK) {
		return KNOT_ERROR;
	}
	dcid.datalen = 18;
	if (dnssec_random_buffer(dcid.data, dcid.datalen) != DNSSEC_EOK) {
		return KNOT_ERROR;
	}

	ngtcp2_settings settings;
	ngtcp2_settings_default(&settings);
	settings.initial_ts = quic_timestamp();
	// settings.max_window = 6 * 1024 * 1024;
	// settings.max_stream_window = 6 * 1024 * 1024;
	// settings.max_udp_payload_size = 1362;
	// settings.no_udp_payload_size_shaping = 1;

	ngtcp2_transport_params params;
	ngtcp2_transport_params_default(&params);
	params.initial_max_streams_bidi = 1;
	params.initial_max_streams_uni = 3;
	//params.initial_max_stream_data_bidi_local = 256 * 1024;
	//params.initial_max_stream_data_bidi_remote = 256 * 1024;
	//params.initial_max_stream_data_uni = 256 * 1024;
	//params.initial_max_data = 1024 * 1024;
	//params.active_connection_id_limit = 7;

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
	ctx->path = path;

	if (ngtcp2_conn_client_new(&ctx->conn, &dcid, &scid, &path,
	                           NGTCP2_PROTO_VER_V1, &callbacks, &settings,
	                           &params, NULL, ctx) != 0) {
		return KNOT_NET_ECONNECT;
	}

	int ret = gnutls_priority_set_direct(ctx->tls->session, QUIC_PRIORITIES, NULL);
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

	gnutls_datum_t alpn[10];
	int parsed = knot_str_to_alpn(alpn, sizeof(alpn)/sizeof(*alpn), KNOT_QUIC_ALPN);
	if (parsed <= 0) {
		return KNOT_NET_ECONNECT;
	}
	ret = gnutls_alpn_set_protocols(ctx->tls->session, alpn, parsed, 0);
	if (ret != GNUTLS_E_SUCCESS) {
		return KNOT_NET_ECONNECT;
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
	// gnutls_transport_set_int(ctx->tls->session, sockfd);
	// gnutls_handshake_set_timeout(ctx->tls->session, 1000 * ctx->tls->wait);

	// Initialize poll descriptor structure.
	struct pollfd pfd = {
		.fd = sockfd,
		.events = POLLIN,
		.revents = 0,
	};

	// Save the socket descriptor.
	ctx->tls->sockfd = sockfd;

	uint8_t enc_buf[65535];
	ngtcp2_pkt_info pi = { 0 };
	ngtcp2_ssize nwrite = 0;
	while(!ngtcp2_conn_get_handshake_completed(ctx->conn)) {
		size_t max_udp_payload_size = ngtcp2_conn_get_path_max_udp_payload_size(ctx->conn);
		uint64_t ts = quic_timestamp();
		for (unsigned packet = 0; packet < KNOT_QUIC_MAX_PACKET_COUNT;) {
			nwrite = ngtcp2_conn_write_pkt(ctx->conn,
			        (ngtcp2_path *)ngtcp2_conn_get_path(ctx->conn),
			        &pi, enc_buf, max_udp_payload_size, ts);
			if (nwrite < 0) {
				ctx->last_error = ngtcp2_err_infer_quic_transport_error_code((int)nwrite);
				assert(0);
				break;
			}

			if (nwrite == 0) {
				ngtcp2_conn_update_pkt_tx_time(ctx->conn, ts);
				break;
			}

			ret = knot_quic_set_ecn(sockfd, dst_addr->ai_family, pi.ecn, NULL);
			if (ret != KNOT_EOK) {
				return ret;
			}
			do {
				// nwrite = sendmsg(sockfd, &msg, 0);
				nwrite = sendto(sockfd, enc_buf, nwrite, MSG_DONTWAIT, path.remote.addr, path.remote.addrlen);
			} while (nwrite == -1 && errno == EINTR);

			if (++packet >= KNOT_QUIC_MAX_PACKET_COUNT) {
				ngtcp2_conn_update_pkt_tx_time(ctx->conn, ts);
				break;
			}
		}

		if (poll(&pfd, 1, -1) != 1) {	// TODO configurable timeout
			continue; // Resend
		}

		struct sockaddr_storage from = { 0 };
		socklen_t from_len = sizeof(from);
		nwrite = recvfrom(sockfd, enc_buf, sizeof(enc_buf), 0, (struct sockaddr *)&from, &from_len);
		if (nwrite < 0) {
			return KNOT_NET_ECONNECT;
		} else if (nwrite == 0) {
			assert(0);
		}

		ctx->path.remote.addr = (struct sockaddr *)&from;
		ctx->path.remote.addrlen = from_len;

		nwrite = ngtcp2_conn_read_pkt(ctx->conn, &ctx->path, &pi, enc_buf,
		                              nwrite, quic_timestamp());
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
			return KNOT_NET_ECONNECT;
		}
	}

	return KNOT_EOK;
}

int quic_send_dns_query(quic_ctx_t *ctx, int sockfd, struct addrinfo *srv, const uint8_t *buf, const size_t buf_len)
{
	if (ctx == NULL || buf == NULL) {
		return KNOT_NET_ESEND;
	}

	//extend_max_local_streams_bidi(ctx->conn, 1, ctx);

	// ctx->stream.tx_data = (uint8_t *)buf;
	// ctx->stream.tx_datalen = buf_len;

	uint8_t enc_buf[65535];
	ngtcp2_vec data[2];
	ngtcp2_ssize wdatalen;
	ngtcp2_pkt_info pi = { 0 };
	uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
	int datacnt = 0;
	uint16_t query_length = htons(buf_len);
	ngtcp2_ssize sent = 0;

	if (ctx->stream.stream_id >= 0) {
		data[0].base = (uint8_t *)&query_length;
		data[0].len = sizeof(query_length);
		data[1].base = (uint8_t *)buf;
		data[1].len = buf_len;
		datacnt = 2;
		flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
		sent = data[0].len + data[1].len;
	} else {
		datacnt = 0;
		assert(0);
	}

	// struct sockaddr_in6 src_addr;
	// socklen_t src_addr_len = sizeof(src_addr);
	// getsockname(sockfd, (struct sockaddr *)&src_addr, &src_addr_len);
	// ctx->path.local.addr = (struct  sockaddr *)&src_addr;
	// ctx->path.local.addrlen = src_addr_len;
	// ctx->path.remote.addr = srv->ai_addr;
	// ctx->path.remote.addrlen = srv->ai_addrlen;

	struct pollfd pfd = {
		.fd = sockfd,
		.events = POLLIN,
		.revents = 0,
	};

	// ngtcp2_ssize nwrite = ngtcp2_conn_writev_stream(ctx->conn, &ctx->path, &pi,
	//         enc_buf, sizeof(enc_buf), &wdatalen, flags, ctx->stream.stream_id, data,
	//         datacnt, quic_timestamp());
	while (1) {
		size_t max_udp_payload_size = ngtcp2_conn_get_path_max_udp_payload_size(ctx->conn);
		uint64_t ts = quic_timestamp();
		for (unsigned packet = 0; packet < KNOT_QUIC_MAX_PACKET_COUNT;) {
			ngtcp2_ssize nwrite = ngtcp2_conn_writev_stream(
			        ctx->conn,
			        (ngtcp2_path *)ngtcp2_conn_get_path(ctx->conn),
			        &pi, enc_buf, max_udp_payload_size, &wdatalen,
			        flags, ctx->stream.stream_id, data, datacnt,
			        ts
			);
			if (nwrite < 0) {
				assert(0);
			} else if (wdatalen >= 0) {
				assert(0);
			}

			if (nwrite == 0) {
				ngtcp2_conn_update_pkt_tx_time(ctx->conn, ts);
				break;
			}

			// TODO
			// if (auto rv = send_packet(*static_cast<Endpoint *>(path.path.user_data),
			//                           path.path.remote, pi.ecn, buf.data(), nwrite);
			// 		rv != NETWORK_ERR_OK) {
			// 	if (rv != NETWORK_ERR_SEND_BLOCKED) {
			// 		last_error_ = quic_err_transport(NGTCP2_ERR_INTERNAL);
			// 		disconnect();
			// 	} else {
			// 		ngtcp2_conn_update_pkt_tx_time(conn_, ts);
			// 	}
			// 	return rv;
			// }

			int ret = knot_quic_set_ecn(sockfd, srv->ai_family, pi.ecn, NULL);
			if (ret != KNOT_EOK) {
				assert(0);
				return ret;
			}
			do {
				nwrite = sendto(sockfd, enc_buf, nwrite, MSG_DONTWAIT, srv->ai_addr,
						srv->ai_addrlen);
			} while (nwrite == -1 && errno == EINTR);

			if (++packet >= KNOT_QUIC_MAX_PACKET_COUNT) {
				ngtcp2_conn_update_pkt_tx_time(ctx->conn, ts);
				break;
			}
		}		

		if (poll(&pfd, 1, -1) < 1) {	// TODO configurable timeout
			continue; // Resend
		}

		struct sockaddr_storage from = { 0 };
		socklen_t from_len = sizeof(from);
		ssize_t nwrite = recvfrom(sockfd, enc_buf, sizeof(enc_buf), 0, (struct sockaddr *)&from, &from_len);
		if (nwrite < 0) {
			return KNOT_NET_ECONNECT;
		} else if (nwrite == 0) {
			assert(0);
		}

		// ctx->path.remote.addr = (struct sockaddr *)&from;
		// ctx->path.remote.addrlen = from_len;

		nwrite = ngtcp2_conn_read_pkt(ctx->conn, &ctx->path, &pi, enc_buf,
		                              nwrite, quic_timestamp());
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
			return KNOT_NET_ECONNECT;
		}
	}
	return KNOT_EOK;
}

int quic_recv_dns_response(quic_ctx_t *ctx, uint8_t *buf, const size_t buf_len, struct addrinfo *srv, int timeout_ms)
{
	if (ctx == NULL || ctx->tls == NULL || buf == NULL) {
		return KNOT_EINVAL;
	}

	const bool unlimited = timeout_ms < 0;
	int sockfd = ctx->tls->sockfd;

	uint8_t encrypted[65500];
	// uint8_t encrypted[65535]; //TODO dont know why, but this fails (smaller array ^^^ helps)
	ngtcp2_ssize nwrite, wdatalen;

	ngtcp2_pkt_info pi = { 0 };
	struct sockaddr_storage from = { 0 };
	struct pollfd pfd = {
		.fd = sockfd,
		.events = POLLIN,
		.revents = 0,
	};

	ctx->stream.rx_data = buf;
	ctx->stream.rx_datalen = buf_len;
	ctx->stream.nread = 0;

	// TODO Timeout
	while (unlimited || timeout_ms > 0) {
		socklen_t from_len = sizeof(from);

		// Wait for datagram data.
		ssize_t ret = poll(&pfd, 1, -1); // TODO Make 200ms resend configurable
		if (ret == 0) {
			goto tx;
		} else if (ret < 0) {
			return KNOT_NET_ESOCKET;
		}

		ret = recvfrom(sockfd, encrypted, sizeof(encrypted), 0,
		               (struct sockaddr *)&from, &from_len);
		if (ret == 0) {
			continue;
		} else if (ret < 0) {
			// WARN("can't receive reply from %s\n", net->remote_str);
			return KNOT_NET_ERECV;
		}

		// TODO compare sockaddr
		// if (from_len > sizeof(from) ||
		//     memcmp(&from, net->srv->ai_addr, from_len) != 0)
		// {
		// 	char *src = NULL;
		// 	get_addr_str(&from, net->socktype, &src);
		// 	WARN("unexpected reply source %s\n", src);
		// 	free(src);
		// 	continue;
		// }

		ret = ngtcp2_conn_read_pkt(ctx->conn, &ctx->path, &pi, encrypted, ret,
		                           quic_timestamp());
		if (ctx->stream.stream_id < 0) {
			return ctx->stream.nread;
		}

		tx:
		wdatalen = 0;
		nwrite = ngtcp2_conn_writev_stream(ctx->conn, &ctx->path, &pi,
		                                   encrypted, sizeof(encrypted),
		                                   &wdatalen, 0, -1, NULL, 0,
		                                   quic_timestamp());
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
			return KNOT_NET_ECONNECT;
		}

		do {
			ret = sendto(sockfd, encrypted, nwrite, 0, srv->ai_addr,
			             srv->ai_addrlen);
		} while (ret == -1 && errno == EINTR);

		if (ret != nwrite) {
			// WARN("can't send query to %s\n", net->remote_str);
			return KNOT_NET_ESEND;
		}
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

	//ngtcp2_conn_del(ctx->conn);
}

#endif