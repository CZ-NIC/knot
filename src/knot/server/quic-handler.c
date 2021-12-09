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
#include <stdio.h>
#include <time.h>
#include <netinet/in.h>
#include <sys/param.h>

#include "knot/server/quic-handler.h"
#include "libdnssec/error.h"
#include "libdnssec/random.h"
#include "libknot/error.h"

#define SERVER_DEFAULT_SCIDLEN 18

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

unsigned int knot_quic_msghdr_ecn(struct msghdr *msg, const int family)
{
	switch (family) {
	case AF_INET:
		for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
			if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TOS && cmsg->cmsg_len) {
				return *(uint8_t *)CMSG_DATA(cmsg);
			}
		}
		break;
	case AF_INET6:
		for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
			if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_TCLASS && cmsg->cmsg_len) {
				return *(uint8_t *)CMSG_DATA(cmsg);
			}
		}
		break;
	}

	return 0;
}

int knot_quic_msghdr_local_addr(struct msghdr *msg, const int family, struct sockaddr_storage *local_addr, size_t *addr_len)
{
	switch (family) {
	case AF_INET:
		for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
			if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
				struct in_pktinfo *pktinfo = (struct in_pktinfo *)CMSG_DATA(cmsg);
				*addr_len = sizeof(struct sockaddr_in);
				struct sockaddr_in *sa = (struct sockaddr_in *)local_addr;
				sa->sin_family = AF_INET;
				sa->sin_addr = pktinfo->ipi_addr;
				return KNOT_EOK;
			}
		}
		return KNOT_EINVAL;
	case AF_INET6:
		for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
			if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO) {
				struct in6_pktinfo *pktinfo = (struct in6_pktinfo *)(CMSG_DATA(cmsg));
				*addr_len = sizeof(struct sockaddr_in6);
				struct sockaddr_in6 *sa = (struct sockaddr_in6 *)local_addr;
				sa->sin6_family = AF_INET6;
				sa->sin6_addr = pktinfo->ipi6_addr;
				return KNOT_EOK;
			}
		}
		return KNOT_EINVAL;
	}
	return KNOT_ENOTSUP;
}

static int stream_opened(ngtcp2_conn *conn, int64_t stream_id, void *user_data)
{
	return 0;
}

static uint64_t knot_quic_cid_hash_raw(const uint8_t *cid, const size_t cidlen)
{
	assert(cid != NULL && cidlen != 0);
	const size_t size = MIN(cidlen, NGTCP2_MAX_CIDLEN); 
	const uint8_t *end = cid + size;
	uint64_t hash = size;
	// Compute optimized
	uint64_t *it1 = NULL;
	for (it1 = (uint64_t *)cid; it1 < (uint64_t *)end && (end - (uint8_t *)it1) >= sizeof(uint64_t); ++it1) {
		hash ^= *it1;
	}
	// Compute rest
	size_t shift = sizeof(uint64_t) - 1;
	for (uint8_t *it2 = (uint8_t *)it1; it2 < end; ++it2) {
		hash ^= ((*it2) << (shift-- * 8));
	}

	return hash;
}

uint64_t knot_quic_cid_hash(const ngtcp2_cid *cid)
{
	assert(cid != NULL);
	return knot_quic_cid_hash_raw(cid->data, cid->datalen);
}

knot_quic_conn_t *knot_quic_conn_alloc(void)
{
	return (knot_quic_conn_t *)calloc(1, sizeof(knot_quic_conn_t));
}

static int knot_handshake_completed_cb(ngtcp2_conn *conn, void *user_data) {
	knot_quic_conn_t *ctx = (knot_quic_conn_t *)user_data;
	printf("Negotiated cipher suite is %s\n", gnutls_cipher_get_name(gnutls_cipher_get(ctx->tls_session)));
	gnutls_datum_t alpn;
	if (gnutls_alpn_get_selected_protocol(ctx->tls_session, &alpn) != 0) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}
	char alpn_str[alpn.size + 1];
	alpn_str[alpn.size] = '\0';
	memcpy(alpn_str, alpn.data, alpn.size);
	printf("Negotiated ALPN is %s\n", alpn_str);

	if (gnutls_session_ticket_send(ctx->tls_session, 1, 0) != GNUTLS_E_SUCCESS) {
		printf("Unable to send session ticket\n");
	}

	uint8_t token[NGTCP2_CRYPTO_MAX_REGULAR_TOKENLEN];
	ngtcp2_path *path = ngtcp2_conn_get_path(ctx->conn);
	uint64_t ts = quic_timestamp();
	ngtcp2_ssize tokenlen = ngtcp2_crypto_generate_regular_token(token,
			ctx->handle->tls_creds.static_secret,
			sizeof(ctx->handle->tls_creds.static_secret),
			path->remote.addr, path->remote.addrlen, ts);
	if (tokenlen < 0) {
		// 	if (!config.quiet) {
		//   std::cerr << "Unable to generate token" << std::endl;
		// }
		assert(0);
		return 0;
	}

	if (ngtcp2_conn_submit_new_token(ctx->conn, token, tokenlen) != 0) {
//     if (!config.quiet) {
//       std::cerr << "ngtcp2_conn_submit_new_token: " << ngtcp2_strerror(rv)
//                 << std::endl;
//     }
		assert(0);
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

static int recv_stream_data(ngtcp2_conn *conn, uint32_t flags,
                            int64_t stream_id, uint64_t offset,
                            const uint8_t *data, size_t datalen,
                            void *user_data, void *stream_user_data)
{
	knot_quic_conn_t *ctx = (knot_quic_conn_t *)user_data;

	//TODO not implemented/tested
	ngtcp2_conn_extend_max_stream_offset(ctx->conn, stream_id, datalen);
	ngtcp2_conn_extend_max_offset(ctx->conn, datalen);
	return 0;
}

static int acked_stream_data_offset_cb(ngtcp2_conn *conn, int64_t stream_id,
                                    uint64_t offset, uint64_t datalen,
                                    void *user_data, void *stream_user_data)
{
	knot_quic_conn_t *ctx = (knot_quic_conn_t *)user_data;
	return 0;
}

static void knot_quic_rand_cb(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx)
{
	(void)rand_ctx;
	dnssec_random_buffer(dest, destlen);
}

static int get_new_connection_id(ngtcp2_conn *conn, ngtcp2_cid *cid,
                                 uint8_t *token, size_t cidlen,
                                 void *user_data)
{
	knot_quic_conn_t *ctx = (knot_quic_conn_t *)user_data;

	if (dnssec_random_buffer(cid->data, cidlen) != DNSSEC_EOK) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	cid->datalen = cidlen;

	if (ngtcp2_crypto_generate_stateless_reset_token(token, ctx->handle->tls_creds.static_secret, sizeof(ctx->handle->tls_creds.static_secret), cid) != 0) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	
	knot_quic_table_store(ctx->handle->conns, cid, ctx);

	return 0;
}

static int secret_func(gnutls_session_t session,
                       gnutls_record_encryption_level_t gtls_level,
                       const void *rx_secret, const void *tx_secret,
                       size_t secretlen)
{
	knot_quic_conn_t *ctx = (knot_quic_conn_t *)gnutls_session_get_ptr(session);
	int level = ngtcp2_crypto_gnutls_from_gnutls_record_encryption_level(gtls_level);
	if (rx_secret && ngtcp2_crypto_derive_and_install_rx_key(ctx->conn, NULL, NULL, NULL, level, rx_secret, secretlen) != 0) {
		return -1;
	}

	if (tx_secret) {
		if (ngtcp2_crypto_derive_and_install_tx_key(ctx->conn, NULL, NULL, NULL, level, tx_secret, secretlen) != 0) {
			return -1;
		}
		// TODO uncomment when `call_application_tx_key_cb != NULL` or remove
		if (level == NGTCP2_CRYPTO_LEVEL_APPLICATION) {
		// && call_application_tx_key_cb(ctx) != 0) {
		// 	return -1;
		}
	}
	return 0;
}

static int read_func(gnutls_session_t session,
                     gnutls_record_encryption_level_t gtls_level,
                     gnutls_handshake_description_t htype, const void *data,
                     size_t data_size)
{
	if (htype == GNUTLS_HANDSHAKE_CHANGE_CIPHER_SPEC) {
		return 0;
	}

	knot_quic_conn_t *ctx = (knot_quic_conn_t *)gnutls_session_get_ptr(session);
	int level = ngtcp2_crypto_gnutls_from_gnutls_record_encryption_level(gtls_level);
	ngtcp2_conn_submit_crypto_data(ctx->conn, level, (const uint8_t *)data,
	                               data_size);
	return 1;
}

static int alert_read_func(gnutls_session_t session,
                           gnutls_record_encryption_level_t level,
                           gnutls_alert_level_t alert_level,
                           gnutls_alert_description_t alert_desc)
{
	knot_quic_conn_t *ctx = (knot_quic_conn_t *)gnutls_session_get_ptr(session);
	// ctx->error = NGTCP2_CRYPTO_ERROR | alert_desc;
	return 0;
}

#define ALPN "\03""doq"

static int client_hello_cb(gnutls_session_t session, unsigned int htype,
                           unsigned when, unsigned int incoming,
			   const gnutls_datum_t *msg)
{
	assert(htype == GNUTLS_HANDSHAKE_CLIENT_HELLO);
	assert(when == GNUTLS_HOOK_POST);
	assert(incoming == 1);

	// check if ALPN extension is present and properly selected h3
	int ret = 0;
	gnutls_datum_t alpn;
	if ((ret = gnutls_alpn_get_selected_protocol(session, &alpn)) != 0) {
		return ret;
	}

	const char *dq = (const char *)&ALPN[1];
	if ((unsigned int)ALPN[0] != alpn.size ||
	    memcmp(dq, alpn.data, alpn.size) != 0) {
		return -1;
	}

	return 0;
}

static int tp_recv_func(gnutls_session_t session, const uint8_t *data,
                        size_t datalen)
{
	ngtcp2_transport_params params;
	knot_quic_conn_t *ctx = (knot_quic_conn_t *)gnutls_session_get_ptr(session);
	ngtcp2_conn *conn = ctx->conn;

	int ret = ngtcp2_decode_transport_params(&params,
	                NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO, data,
	                datalen);
	if (ret != 0) {
//     std::cerr << "ngtcp2_decode_transport_params: " << ngtcp2_strerror(rv)
//               << std::endl;
		return -1;
	}

	ret = ngtcp2_conn_set_remote_transport_params(conn, &params);
	if (ret != 0) {
//     std::cerr << "ngtcp2_conn_set_remote_transport_params: "
//               << ngtcp2_strerror(rv) << std::endl;
		return -1;
	}

	return 0;
}

static int tp_send_func(gnutls_session_t session, gnutls_buffer_t extdata)
{
	ngtcp2_transport_params params;
	uint8_t buf[256];
	knot_quic_conn_t *ctx = (knot_quic_conn_t *)gnutls_session_get_ptr(session);
	ngtcp2_conn *conn = ctx->conn;

	ngtcp2_conn_get_local_transport_params(conn, &params);
	ssize_t nwrite = ngtcp2_encode_transport_params(buf, sizeof(buf),
	                NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS,
	                &params);
	if (nwrite < 0) {
//     std::cerr << "ngtcp2_encode_transport_params: " << ngtcp2_strerror(nwrite)
//               << std::endl;
		return -1;
	}

	int ret = gnutls_buffer_append_data(extdata, buf, nwrite);
	if (ret != 0) {
//     std::cerr << "gnutls_buffer_append_data failed: " << gnutls_strerror(rv)
//               << std::endl;
		return -1;
	}

	return 0;
}

int keylog_callback(gnutls_session_t session, const char *label,
                    const gnutls_datum_t *secret)
{
	return 0;
}



int knot_quic_conn_init(knot_quic_conn_t *conn, const knot_quic_handle_ctx_t *handle, const knot_quic_creds_t *creds, const ngtcp2_path *path, const ngtcp2_cid *dcid, const ngtcp2_cid *scid, const ngtcp2_cid *ocid, const uint32_t version)
{
	conn->handle = (knot_quic_handle_ctx_t *)handle;

	const ngtcp2_callbacks callbacks = {
		NULL, // client_initial
		ngtcp2_crypto_recv_client_initial_cb,
		ngtcp2_crypto_recv_crypto_data_cb,
		knot_handshake_completed_cb,
		NULL, // recv_version_negotiation
		ngtcp2_crypto_encrypt_cb,
		ngtcp2_crypto_decrypt_cb,
		ngtcp2_crypto_hp_mask_cb,
		recv_stream_data,
		acked_stream_data_offset_cb,
		stream_opened,
		NULL, // TODO stream_close,
		NULL, // recv_stateless_reset
		NULL, // recv_retry
		NULL, // extend_max_streams_bidi
		NULL, // extend_max_streams_uni
		knot_quic_rand_cb,
		get_new_connection_id,
		NULL, // TODO remove_connection_id,
		ngtcp2_crypto_update_key_cb,
		NULL, // TODO path_validation,
		NULL, // select_preferred_addr
		NULL, // TODO ::stream_reset,
		NULL, // TODO ::extend_max_remote_streams_bidi,
		NULL, // extend_max_remote_streams_uni
		NULL, // TODO ::extend_max_stream_data,
		NULL, // dcid_status
		NULL, // handshake_confirmed
		NULL, // recv_new_token
		ngtcp2_crypto_delete_crypto_aead_ctx_cb,
		ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
		NULL, // recv_datagram
		NULL, // ack_datagram
		NULL, // lost_datagram
		ngtcp2_crypto_get_path_challenge_data_cb,
		NULL // TODO stream_stop_sending,
	};

	conn->scid.datalen = SERVER_DEFAULT_SCIDLEN;
	if (dnssec_random_buffer(conn->scid.data, conn->scid.datalen) != DNSSEC_EOK) {
		return KNOT_ERROR;
	}

	ngtcp2_settings settings;
	ngtcp2_settings_default(&settings);
	settings.initial_ts = quic_timestamp();
	//settings.max_udp_payload_size = 1472;

	ngtcp2_transport_params params;
	ngtcp2_transport_params_default(&params);
	// params.initial_max_stream_data_bidi_local = config.max_stream_data_bidi_local;
	// params.initial_max_stream_data_bidi_remote = config.max_stream_data_bidi_remote;
	// params.initial_max_stream_data_uni = config.max_stream_data_uni;
	// params.initial_max_data = config.max_data;
	params.initial_max_streams_bidi = 100;
	params.initial_max_streams_uni = 3;
	// params.max_idle_timeout = config.timeout;
	// params.stateless_reset_token_present = 1;
	// params.active_connection_id_limit = 7;
	if (ocid) {
		params.original_dcid = *ocid;
		params.retry_scid = *scid;
		params.retry_scid_present = 1;
	} else {
		params.original_dcid = *scid;
	}

	if (dnssec_random_buffer(params.stateless_reset_token, NGTCP2_STATELESS_RESET_TOKENLEN) != DNSSEC_EOK) {
		// TODO std::cerr << "Could not generate stateless reset token" << std::endl;
		return KNOT_ERROR;
	}

	// if (config.preferred_ipv4_addr.len || config.preferred_ipv6_addr.len) {
	// 	params.preferred_address_present = 1;
	// 	if (config.preferred_ipv4_addr.len) {
	// 		auto &dest = params.preferred_address.ipv4_addr;
	// 		const auto &addr = config.preferred_ipv4_addr;
	// 		assert(sizeof(dest) == sizeof(addr.su.in.sin_addr));
	// 		memcpy(&dest, &addr.su.in.sin_addr, sizeof(dest));
	// 		params.preferred_address.ipv4_port = htons(addr.su.in.sin_port);
	// 		params.preferred_address.ipv4_present = 1;
	// 	}
	// 	if (config.preferred_ipv6_addr.len) {
	// 		auto &dest = params.preferred_address.ipv6_addr;
	// 		const auto &addr = config.preferred_ipv6_addr;
	// 		assert(sizeof(dest) == sizeof(addr.su.in6.sin6_addr));
	// 		memcpy(&dest, &addr.su.in6.sin6_addr, sizeof(dest));
	// 		params.preferred_address.ipv6_port = htons(addr.su.in6.sin6_port);
	// 		params.preferred_address.ipv6_present = 1;
	// 	}

	// 	auto &token = params.preferred_address.stateless_reset_token;
	// 	if (util::generate_secure_random(token, sizeof(token)) != 0) {
	// 		std::cerr << "Could not generate preferred address stateless reset token"
	// 		          << std::endl;
	// 		return -1;
	// 	}

	// 	params.preferred_address.cid.datalen = NGTCP2_SV_SCIDLEN;
	// 	if (util::generate_secure_random(params.preferred_address.cid.data,
	// 	                                 params.preferred_address.cid.datalen) != 0) {
	// 		std::cerr << "Could not generate preferred address connection ID"
	// 		          << std::endl;
	// 		return -1;
	// 	}
	// }

	if (ngtcp2_conn_server_new(&conn->conn, dcid, &conn->scid, path, version,
	                           &callbacks, &settings, &params, NULL, conn) != 0) {
		// 	//std::cerr << "ngtcp2_conn_server_new: " << ngtcp2_strerror(rv) << std::endl;
		// 	return -1;
		assert(0);
		return KNOT_ERROR;
	}

	if (gnutls_init(&conn->tls_session, GNUTLS_SERVER |
	                GNUTLS_ENABLE_EARLY_DATA | GNUTLS_NO_AUTO_SEND_TICKET |
	                GNUTLS_NO_END_OF_EARLY_DATA) != GNUTLS_E_SUCCESS) {
		return KNOT_ERROR;
	}

	if (gnutls_priority_set_direct(conn->tls_session, QUIC_PRIORITIES,
	                               NULL) != GNUTLS_E_SUCCESS) {
		return KNOT_ERROR;
	}

	if (gnutls_session_ticket_enable_server(conn->tls_session,
	                &creds->tls_ticket_key) != GNUTLS_E_SUCCESS) {
		return KNOT_ERROR;
	}

	gnutls_handshake_set_secret_function(conn->tls_session, secret_func);
	gnutls_handshake_set_read_function(conn->tls_session, read_func);
	gnutls_alert_set_read_function(conn->tls_session, alert_read_func);
	gnutls_handshake_set_hook_function(conn->tls_session,
	                                   GNUTLS_HANDSHAKE_CLIENT_HELLO,
	                                   GNUTLS_HOOK_POST, client_hello_cb);

	if (gnutls_session_ext_register(conn->tls_session,
	                "QUIC Transport Parameters",
	                NGTCP2_TLSEXT_QUIC_TRANSPORT_PARAMETERS_V1,
	                GNUTLS_EXT_TLS, tp_recv_func, tp_send_func, NULL, NULL,
	                NULL, GNUTLS_EXT_FLAG_TLS |
	                GNUTLS_EXT_FLAG_CLIENT_HELLO | GNUTLS_EXT_FLAG_EE
			) != 0) {
//     std::cerr << "gnutls_session_ext_register failed: " << gnutls_strerror(rv)
//               << std::endl;
		assert(0);
		return -1;
	}

	gnutls_anti_replay_enable(conn->tls_session, creds->tls_anti_replay);
	gnutls_record_set_max_early_data_size(conn->tls_session, 0xffffffffu);

	gnutls_session_set_ptr(conn->tls_session, conn);

	if (gnutls_credentials_set(conn->tls_session, GNUTLS_CRD_CERTIFICATE,
	                           creds->tls_cert) != GNUTLS_E_SUCCESS) {
		// std::cerr << "gnutls_credentials_set failed: " << gnutls_strerror(rv)
		// << std::endl;
		return -1;
	}

	gnutls_datum_t alpn = {
		.data = (uint8_t *)(&ALPN[1]),
		.size = ALPN[0],
	};
	gnutls_alpn_set_protocols(conn->tls_session, &alpn, 1, 0);

	gnutls_session_set_keylog_function(conn->tls_session, keylog_callback);
	ngtcp2_conn_set_tls_native_handle(conn->conn, conn->tls_session);

	return KNOT_EOK;
}

knot_quic_conn_t *knot_quic_conn_new(const knot_quic_handle_ctx_t *handle, const knot_quic_creds_t *creds, const ngtcp2_path *path, const ngtcp2_cid *dcid, const ngtcp2_cid *scid, const ngtcp2_cid *ocid, const uint32_t version)
{
	knot_quic_conn_t *conn = knot_quic_conn_alloc();
	if (conn == NULL) {
		return NULL;
	}

	if (knot_quic_conn_init(conn, handle, creds, path, dcid, scid, ocid, version) != KNOT_EOK) {
		free(conn);
		return NULL;
	}

	return conn;
}

//int knot_quic_conn_on_read(struct quic_recvfrom *rq, knot_quic_conn_t *conn, ngtcp2_pkt_info *pi, uint8_t *data, size_t datalen)
int knot_quic_conn_on_read(knot_quic_conn_t *conn, ngtcp2_pkt_info *pi,
                           uint8_t *data, size_t datalen)
{
	int ret = ngtcp2_conn_read_pkt(conn->conn, ngtcp2_conn_get_path(conn->conn), pi, data, datalen, quic_timestamp());
	if (ret != 0) {
		//std::cerr << "ngtcp2_conn_read_pkt: " << ngtcp2_strerror(rv) << std::endl;
		switch (ret) {
			case NGTCP2_ERR_DRAINING:
			// start_draining_period();
			// return NETWORK_ERR_CLOSE_WAIT;
			assert(0);
			return -1;
		case NGTCP2_ERR_RETRY:
			// return NETWORK_ERR_RETRY;
			assert(0);
			return -2;
		case NGTCP2_ERR_REQUIRED_TRANSPORT_PARAM:
		case NGTCP2_ERR_MALFORMED_TRANSPORT_PARAM:
		case NGTCP2_ERR_TRANSPORT_PARAM:
			// If ret indicates transport_parameters related error, we should
			// send TRANSPORT_PARAMETER_ERROR even if last_error_.code is
			// already set.  This is because OpenSSL might set Alert.
			//last_error_ = quic_err_transport(rv);
			assert(0);
			break;
		case NGTCP2_ERR_DROP_CONN:
			// return NETWORK_ERR_DROP_CONN;
			assert(0);
			return -3;
		default:
			// if (!last_error_.code) {
			// 	last_error_ = quic_err_transport(rv);
			// }
			assert(0);
		}
		// return handle_error();
		return -4;
	}
	return KNOT_EOK;
}

int knot_quic_conn_on_write(knot_quic_conn_t *conn, struct iovec *out)
{
	if (ngtcp2_conn_is_in_closing_period(conn->conn) ||
	    ngtcp2_conn_is_in_draining_period(conn->conn)) {
		return KNOT_EOK;
	}

	ngtcp2_pkt_info pi;
	size_t max_udp_payload_size =
	                ngtcp2_conn_get_path_max_udp_payload_size(conn->conn);
	uint64_t left = ngtcp2_conn_get_max_data_left(conn->conn);
	// size_t nwrite = ngtcp2_conn_writev_stream(conn->conn,
	//                 ngtcp2_conn_get_path(conn->conn), &pi, out->iov_base,
	//                 max_udp_payload_size, &(out->iov_len),
	//                 NGTCP2_WRITE_STREAM_FLAG_FIN, -1, NULL, 0,
	//                 quic_timestamp());
	assert(max_udp_payload_size <= out->iov_len);
	out->iov_len = ngtcp2_conn_write_pkt(conn->conn,
	                ngtcp2_conn_get_path(conn->conn), &pi, out->iov_base,
	                max_udp_payload_size, quic_timestamp());
	// if (nwrite <= 0) {

	// }
	// out->iov_len = nwrite;
	return KNOT_EOK;
}

knot_quic_table_t *knot_quic_table_new(size_t size)
{
	knot_quic_table_t *table = calloc(1, sizeof(*table) +
	                                  size * sizeof(table->conns[0]));
	if (table == NULL) {
		return NULL;
	}

	// mm_ctx_mempool(&table->mem, MM_DEFAULT_BLKSIZE);
	// if (table->mem.ctx == NULL) {
	// 	free(table);
	// 	return NULL;
	// }
	table->size = size;

	return table;
}

// uint32_t generate_reserved_version(const sockaddr *sa, socklen_t salen,
//                                    uint32_t version) {
//   uint32_t h = 0x811C9DC5u;
//   const uint8_t *p = (const uint8_t *)sa;
//   const uint8_t *ep = p + salen;
//   for (; p != ep; ++p) {
//     h ^= *p;
//     h *= 0x01000193u;
//   }
//   version = htonl(version);
//   p = (const uint8_t *)&version;
//   ep = p + sizeof(version);
//   for (; p != ep; ++p) {
//     h ^= *p;
//     h *= 0x01000193u;
//   }
//   h &= 0xf0f0f0f0u;
//   h |= 0x0a0a0a0au;
//   return h;
// }

int knot_quic_send_version_negotiation(struct quic_recvfrom *rq)//uint32_t version,
//                 const uint8_t *dcid, size_t dcidlen,
//                 const uint8_t *scid, size_t scidlen, Endpoint *ep,
//                 const Address *local_addr, const sockaddr *sa, socklen_t salen)
{
// 	uint8_t buf[NGTCP2_MAX_UDP_PAYLOAD_SIZE];
// 	uint32_t sv[16];

// 	assert((sizeof(sv)/sizeof(*sv)) >= 2 + (NGTCP2_PROTO_VER_DRAFT_MAX - NGTCP2_PROTO_VER_DRAFT_MIN + 1));

// 	sv[0] = generate_reserved_version(sa, salen, version);
// 	sv[1] = NGTCP2_PROTO_VER_V1;

// 	size_t svlen = 2;
// 	for (uint32_t v = NGTCP2_PROTO_VER_DRAFT_MIN; v <= NGTCP2_PROTO_VER_DRAFT_MAX; ++v) {
// 		sv[svlen++] = v;
// 	}

// 	ngtcp2_ssize nwrite = ngtcp2_pkt_write_version_negotiation(buf.wpos(), buf.left(), std::uniform_int_distribution<uint8_t>(0, std::numeric_limits<uint8_t>::max())(randgen), dcid, dcidlen, scid, scidlen, sv.data(), svlen);
// 	if (nwrite < 0) {
// 	// std::cerr << "ngtcp2_pkt_write_version_negotiation: "
//     //           << ngtcp2_strerror(nwrite) << std::endl;
// 		return -1;
// 	}

// 	buf.push(nwrite);

// 	ngtcp2_addr laddr{local_addr.len, const_cast<sockaddr *>(&local_addr.su.sa)};
// 	ngtcp2_addr raddr{salen, const_cast<sockaddr *>(sa)};

// 	if (send_packet(ep, laddr, raddr, /* ecn = */ 0, buf.rpos(), buf.size(), 0) != NETWORK_ERR_OK) {
// 		return -1;
// 	}

	return 0;
}

int knot_quic_table_store(knot_quic_table_t *table, const ngtcp2_cid *cid, knot_quic_conn_t *el)
{
	uint64_t hash = knot_quic_cid_hash(cid) % table->size;
	knot_quic_table_pair_t *find = malloc(sizeof(knot_quic_table_pair_t));
	if (find == NULL) {
		return KNOT_ENOMEM;
	}

	find->key = *cid;
	find->value = el;
	find->next = table->conns[hash];
	table->conns[hash] = find;

	return KNOT_EOK;
}

knot_quic_conn_t *knot_quic_table_find(knot_quic_table_t *table, const ngtcp2_cid *dcid)
{
	return knot_quic_table_find_dcid(table, dcid->data, dcid->datalen);
}

static inline int knot_quic_cid_eq(const uint8_t *lhs, const size_t lhs_len,
                                   const uint8_t *rhs, const size_t rhs_len)
{
	return (lhs_len == rhs_len) && (memcmp(lhs, rhs, lhs_len) == 0);
}

knot_quic_conn_t *knot_quic_table_find_dcid(knot_quic_table_t *table, const uint8_t *cid, const size_t cidlen)
{
	uint64_t hash = knot_quic_cid_hash_raw(cid, cidlen) % table->size;
	knot_quic_table_pair_t *el = table->conns[hash];
	while (el != NULL) {
		if (knot_quic_cid_eq(el->key.data, el->key.datalen, cid, cidlen) != 0) {
			return el->value;
		}
		el = el->next;
	}
	return NULL;
}
