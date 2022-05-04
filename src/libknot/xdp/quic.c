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

#include <assert.h>
#include <gnutls/gnutls.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "contrib/macros.h"
#include "contrib/sockaddr.h"
#include "contrib/ucw/lists.h"
#include "libknot/endian.h"
#include "libdnssec/error.h"
#include "libdnssec/random.h"
#include "libknot/attribute.h"
#include "libknot/endian.h"
#include "libknot/error.h"
#include "libknot/wire.h"
#include "libknot/xdp/quic.h"

#define SERVER_DEFAULT_SCIDLEN 18

#define QUIC_DEFAULT_VERSION "-VERS-ALL:+VERS-TLS1.3"
#define QUIC_DEFAULT_CIPHERS "-CIPHER-ALL:+AES-128-GCM:+AES-256-GCM:+CHACHA20-POLY1305:+AES-128-CCM"
#define QUIC_DEFAULT_GROUPS  "-GROUP-ALL:+GROUP-SECP256R1:+GROUP-X25519:+GROUP-SECP384R1:+GROUP-SECP521R1"
#define QUIC_PRIORITIES      "%DISABLE_TLS13_COMPAT_MODE:NORMAL:"QUIC_DEFAULT_VERSION":"QUIC_DEFAULT_CIPHERS":"QUIC_DEFAULT_GROUPS

#define TLS_CALLBACK_ERR     (-1)

// TODO it would be good if this is provided by libngtcp2
#define NGTCP2_CS_POST_HANDSHAKE 6 // ngtcp2_conn.h
int ngtcp2_conn_is_handshake_completed(ngtcp2_conn *conn) {
	return *(int *)conn /* conn->state */ == NGTCP2_CS_POST_HANDSHAKE;
}

static int tls_anti_replay_db_add_func(void *dbf, time_t exp_time,
                                       const gnutls_datum_t *key,
                                       const gnutls_datum_t *data)
{
	return 0;
}

static void tls_session_ticket_key_free(gnutls_datum_t *ticket) {
	gnutls_memset(ticket->data, 0, ticket->size);
	gnutls_free(ticket->data);
}

int knot_xquic_init_creds(knot_xquic_creds_t *creds)
{
	int ret = dnssec_random_buffer(creds->static_secret, sizeof(creds->static_secret));
	if (ret != DNSSEC_EOK) {
		return knot_error_from_libdnssec(ret);
	}

	ret = gnutls_anti_replay_init(&creds->tls_anti_replay);
	if (ret != GNUTLS_E_SUCCESS) {
		return KNOT_ERROR;
	}
	gnutls_anti_replay_set_add_function(creds->tls_anti_replay, tls_anti_replay_db_add_func);
	gnutls_anti_replay_set_ptr(creds->tls_anti_replay, NULL);

	ret = gnutls_certificate_allocate_credentials(&creds->tls_cert);
	if (ret != GNUTLS_E_SUCCESS) {
		gnutls_anti_replay_deinit(creds->tls_anti_replay);
		return KNOT_ENOMEM;
	}

	ret = gnutls_certificate_set_x509_system_trust(creds->tls_cert);
	if (ret < 0) {
		knot_xquic_free_creds(creds);
		return KNOT_ERROR;
	}

	const char *cert_file = "/home/peltan/mnt/MyCertificate.crt";
	const char *key_file = "/home/peltan/mnt/MyKey.key"; // FIXME :)

	ret = gnutls_certificate_set_x509_key_file(creds->tls_cert, cert_file, key_file, GNUTLS_X509_FMT_PEM);
	if (ret != GNUTLS_E_SUCCESS) {
		knot_xquic_free_creds(creds);
		return KNOT_ERROR;
	}

	ret = gnutls_session_ticket_key_generate(&creds->tls_ticket_key);
	if (ret != GNUTLS_E_SUCCESS) {
		knot_xquic_free_creds(creds);
		return KNOT_ERROR;
	}

	return KNOT_EOK;

}

void knot_xquic_free_creds(knot_xquic_creds_t *creds)
{
	gnutls_certificate_free_credentials(creds->tls_cert);
	if (creds->tls_ticket_key.data != NULL) {
		tls_session_ticket_key_free(&creds->tls_ticket_key);
	}
	gnutls_anti_replay_deinit(creds->tls_anti_replay);
}

static void print_cid(const ngtcp2_cid *cid, const char *name)
{
	if (cid->datalen == 0) {
		printf("%s 0 [zero cid] ", name);
	} else {
		printf("%s %zu [ %02x %02x %02x %02x ... ] ", name, cid->datalen, cid->data[0], cid->data[1], cid->data[2], cid->data[3]);
	}
}

static int tls_secret_func(gnutls_session_t session,
                           gnutls_record_encryption_level_t gtls_level,
                           const void *rx_secret, const void *tx_secret,
                           size_t secretlen)
{
	knot_xquic_conn_t *ctx = (knot_xquic_conn_t *)gnutls_session_get_ptr(session);
	int level = ngtcp2_crypto_gnutls_from_gnutls_record_encryption_level(gtls_level);
	if (rx_secret != NULL) {
		int ret = ngtcp2_crypto_derive_and_install_rx_key(ctx->conn, NULL, NULL, NULL, level, rx_secret, secretlen);
		if (ret != 0) {
			return TLS_CALLBACK_ERR;
		}
	}

	if (tx_secret != NULL) {
		int ret = ngtcp2_crypto_derive_and_install_tx_key(ctx->conn, NULL, NULL, NULL, level, tx_secret, secretlen);
		if (ret != 0) {
			return TLS_CALLBACK_ERR;
		}
	}
	return 0;
}

static int tls_read_func(gnutls_session_t session,
                         gnutls_record_encryption_level_t gtls_level,
                         gnutls_handshake_description_t htype, const void *data,
                         size_t data_size)
{
	printf("TLS READ FUN %d\n", htype);
	if (htype == GNUTLS_HANDSHAKE_CHANGE_CIPHER_SPEC) {
		return 0;
	}

	knot_xquic_conn_t *ctx = (knot_xquic_conn_t *)gnutls_session_get_ptr(session);
	int level = ngtcp2_crypto_gnutls_from_gnutls_record_encryption_level(gtls_level);
	ngtcp2_conn_submit_crypto_data(ctx->conn, level, (const uint8_t *)data, data_size);
	return GNUTLS_E_SUCCESS; // TODO: 1 instead ??!
}

static int tls_alert_read_func(gnutls_session_t session,
                               gnutls_record_encryption_level_t level,
                               gnutls_alert_level_t alert_level,
                               gnutls_alert_description_t alert_desc)
{
	knot_xquic_conn_t *ctx = (knot_xquic_conn_t *)gnutls_session_get_ptr(session);
	(void)ctx;
	printf("TLS alert! %d\n", alert_desc);
	// ctx->error = NGTCP2_CRYPTO_ERROR | alert_desc;
	return 0;
}

#define ALPN "\03""doq"
#define ALPN_TMP "\07""doq-i11"

static int tls_client_hello_cb(gnutls_session_t session, unsigned int htype,
                               unsigned when, unsigned int incoming,
                               const gnutls_datum_t *msg)
{
	assert(htype == GNUTLS_HANDSHAKE_CLIENT_HELLO);
	assert(when == GNUTLS_HOOK_POST);

	if (!incoming) {
		return 0;
	}

	gnutls_datum_t alpn;
	int ret = gnutls_alpn_get_selected_protocol(session, &alpn);
	if (ret != 0) {
		return ret;
	}

	const char *dq = (const char *)&ALPN[1];
	if (((unsigned int)ALPN[0] != alpn.size ||
	     memcmp(dq, alpn.data, alpn.size) != 0) &&
	   ((unsigned int)ALPN_TMP[0] != alpn.size ||
	     memcmp((const char *)&ALPN_TMP[1], alpn.data, alpn.size) != 0)) {
		return TLS_CALLBACK_ERR;
	}

	return 0;
}

static int tls_tp_recv_func(gnutls_session_t session, const uint8_t *data,
                            size_t datalen)
{
	ngtcp2_transport_params params;
	knot_xquic_conn_t *ctx = (knot_xquic_conn_t *)gnutls_session_get_ptr(session);
	ngtcp2_conn *conn = ctx->conn;
	bool server = ngtcp2_conn_is_server(conn);
	ngtcp2_transport_params_type ptype = server ? NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO : NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS;

	int ret = ngtcp2_decode_transport_params(&params, ptype, data, datalen);
	if (ret != 0) {
		return TLS_CALLBACK_ERR;
	}

	ret = ngtcp2_conn_set_remote_transport_params(conn, &params);
	if (ret != 0) {
		return TLS_CALLBACK_ERR;
	}

	return 0;
}

static int tls_tp_send_func(gnutls_session_t session, gnutls_buffer_t extdata)
{
	ngtcp2_transport_params params;
	uint8_t buf[256];
	knot_xquic_conn_t *ctx = (knot_xquic_conn_t *)gnutls_session_get_ptr(session);
	ngtcp2_conn *conn = ctx->conn;
	bool server = ngtcp2_conn_is_server(conn);
	ngtcp2_transport_params_type ptype = server ? NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS : NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO;

	ngtcp2_conn_get_local_transport_params(conn, &params);
	ssize_t nwrite = ngtcp2_encode_transport_params(buf, sizeof(buf), ptype, &params);
	if (nwrite < 0) {
		return TLS_CALLBACK_ERR;
	}

	int ret = gnutls_buffer_append_data(extdata, buf, nwrite);
	if (ret != 0) {
		return TLS_CALLBACK_ERR;
	}

	return 0;
}

static int tls_keylog_callback(gnutls_session_t session, const char *label,
                               const gnutls_datum_t *secret)
{
	return 0;
}

static int tls_init_conn_session(knot_xquic_conn_t *conn, bool server)
{
	if (gnutls_init(&conn->tls_session, (server ? GNUTLS_SERVER : GNUTLS_CLIENT) |
	                GNUTLS_ENABLE_EARLY_DATA | GNUTLS_NO_AUTO_SEND_TICKET |
	                GNUTLS_NO_END_OF_EARLY_DATA) != GNUTLS_E_SUCCESS) {
		return TLS_CALLBACK_ERR;
	}

	if (gnutls_priority_set_direct(conn->tls_session, QUIC_PRIORITIES,
	                               NULL) != GNUTLS_E_SUCCESS) {
		return TLS_CALLBACK_ERR;
	}

	if (server && gnutls_session_ticket_enable_server(conn->tls_session,
	                &conn->xquic_table->creds->tls_ticket_key) != GNUTLS_E_SUCCESS) {
		return TLS_CALLBACK_ERR;
	}

	gnutls_handshake_set_secret_function(conn->tls_session, tls_secret_func);
	gnutls_handshake_set_read_function(conn->tls_session, tls_read_func);
	gnutls_alert_set_read_function(conn->tls_session, tls_alert_read_func);
	gnutls_handshake_set_hook_function(conn->tls_session,
	                                   //GNUTLS_HANDSHAKE_ANY,
					   GNUTLS_HANDSHAKE_CLIENT_HELLO,
	                                   GNUTLS_HOOK_POST, tls_client_hello_cb);
	if (gnutls_session_ext_register(conn->tls_session,
	                "QUIC Transport Parameters",
	                NGTCP2_TLSEXT_QUIC_TRANSPORT_PARAMETERS_V1,
	                GNUTLS_EXT_TLS, tls_tp_recv_func, tls_tp_send_func, NULL, NULL,
	                NULL, GNUTLS_EXT_FLAG_TLS |
	                GNUTLS_EXT_FLAG_CLIENT_HELLO | GNUTLS_EXT_FLAG_EE
			) != 0) {
//     std::cerr << "gnutls_session_ext_register failed: " << gnutls_strerror(rv)
//               << std::endl;
		assert(0);
		return TLS_CALLBACK_ERR;
	}

	gnutls_anti_replay_enable(conn->tls_session, conn->xquic_table->creds->tls_anti_replay);
	gnutls_record_set_max_early_data_size(conn->tls_session, 0xffffffffu);

	gnutls_session_set_ptr(conn->tls_session, conn);

	if (gnutls_credentials_set(conn->tls_session, GNUTLS_CRD_CERTIFICATE,
	                           conn->xquic_table->creds->tls_cert) != GNUTLS_E_SUCCESS) {
		// std::cerr << "gnutls_credentials_set failed: " << gnutls_strerror(rv)
		// << std::endl;
		return TLS_CALLBACK_ERR;
	}

	gnutls_datum_t alpn[2] = {
		{
			.data = (uint8_t *)(&ALPN[1]),
			.size = ALPN[0],
		},
		{
			.data = (uint8_t *)(&ALPN_TMP[1]),
			.size = ALPN_TMP[0],
		}
	};
	gnutls_alpn_set_protocols(conn->tls_session, alpn, 1, 0);

	gnutls_session_set_keylog_function(conn->tls_session, tls_keylog_callback);
	ngtcp2_conn_set_tls_native_handle(conn->conn, conn->tls_session);

	return KNOT_EOK;
}

static uint64_t get_timestamp(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
		assert(0);
	}

	return (uint64_t)ts.tv_sec * NGTCP2_SECONDS + (uint64_t)ts.tv_nsec;
}

bool xquic_conn_timeout(knot_xquic_conn_t *conn)
{
	return get_timestamp() > ngtcp2_conn_get_idle_expiry(conn->conn);
}

static void knot_quic_rand_cb(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx)
{
	(void)rand_ctx;
	dnssec_random_buffer(dest, destlen);
}

static void init_random_cid(ngtcp2_cid *cid, size_t len)
{
	if (len == 0) {
		len = SERVER_DEFAULT_SCIDLEN;
	}

	if (dnssec_random_buffer(cid->data, len) != DNSSEC_EOK) {
		cid->datalen = 0;
	} else {
		cid->datalen = len;
	}
}

static int get_new_connection_id(ngtcp2_conn *conn, ngtcp2_cid *cid,
                                 uint8_t *token, size_t cidlen,
                                 void *user_data)
{
	knot_xquic_conn_t *ctx = (knot_xquic_conn_t *)user_data;
	assert(ctx->conn == conn);

	if (init_random_cid(cid, cidlen), cid->datalen == 0) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}
	knot_xquic_conn_t **addto = xquic_table_insert(ctx, cid, ctx->xquic_table);
	(void)addto;

	if (ngtcp2_crypto_generate_stateless_reset_token(token, (uint8_t *)ctx->xquic_table->hash_secret, sizeof(ctx->xquic_table->hash_secret), cid) != 0) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

static int remove_connection_id(ngtcp2_conn *conn, const ngtcp2_cid *cid,
                                void *user_data)
{
	knot_xquic_conn_t *ctx = (knot_xquic_conn_t *)user_data;
	assert(ctx->conn == conn);

	knot_xquic_conn_t **torem = xquic_table_lookup(cid, ctx->xquic_table);
	if (torem != NULL) {
		assert(*torem == ctx);
		xquic_table_rem2(torem, ctx->xquic_table);
	}

	return 0;
}

static int knot_handshake_completed_cb(ngtcp2_conn *conn, void *user_data) {
	knot_xquic_conn_t *ctx = (knot_xquic_conn_t *)user_data;
	assert(ctx->conn == conn);

	gnutls_datum_t alpn;
	if (gnutls_alpn_get_selected_protocol(ctx->tls_session, &alpn) != 0) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}
	char alpn_str[alpn.size + 1];
	alpn_str[alpn.size] = '\0';
	memcpy(alpn_str, alpn.data, alpn.size);

	if (gnutls_session_ticket_send(ctx->tls_session, 1, 0) != GNUTLS_E_SUCCESS) {
		printf("Unable to send session ticket\n"); // FIXME
		return TLS_CALLBACK_ERR;
	}

	uint8_t token[NGTCP2_CRYPTO_MAX_REGULAR_TOKENLEN];
	ngtcp2_path path = *ngtcp2_conn_get_path(ctx->conn);
	uint64_t ts = get_timestamp();
	ngtcp2_ssize tokenlen = ngtcp2_crypto_generate_regular_token(token,
			(uint8_t *)ctx->xquic_table->hash_secret,
			sizeof(ctx->xquic_table->hash_secret),
			path.remote.addr, path.remote.addrlen, ts);
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
	knot_xquic_conn_t *ctx = (knot_xquic_conn_t *)user_data;

	printf("RECV stream data %zu [ %02x %02x ... ] (size %d) flags %u\n", datalen, datalen > 0 ? data[0] : 0, datalen > 1 ? data[1] : 0, (int)be16toh(*(uint16_t *)data), flags);

	int ret = knot_xquic_stream_recv_data(ctx, stream_id, data, datalen, (flags & NGTCP2_STREAM_DATA_FLAG_FIN));

	return ret == KNOT_EOK ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
}

static int acked_stream_data_offset_cb(ngtcp2_conn *conn, int64_t stream_id,
                                    uint64_t offset, uint64_t datalen,
                                    void *user_data, void *stream_user_data)
{
	knot_xquic_conn_t *ctx = (knot_xquic_conn_t *)user_data;

	knot_xquic_stream_ack_data(ctx, stream_id, offset + datalen);

	return 0;
}

static int stream_opened(ngtcp2_conn *conn, int64_t stream_id, void *user_data)
{
	printf("STREAM %ld opened...\n", stream_id);
	return 0;
}

static int stream_closed(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
			 uint64_t app_error_code, void *user_data, void *stream_user_data)
{
	printf("STREAM %ld closed %s\n", stream_id, (flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET) ? "with errors" : "without errors");
	return 0;
}

static int recv_stateless_rst(ngtcp2_conn *conn, const ngtcp2_pkt_stateless_reset *sr, void *user_data)
{
	printf("STATELESS RST\n");
	return 0;
}

static int recv_stream_rst(ngtcp2_conn *conn, int64_t stream_id, uint64_t final_size,
                           uint64_t app_error_code, void *user_data, void *stream_user_data)
{
	printf("STREAM RST %ld\n", stream_id);
	return 0;
}

static void user_printf(void *user_data, const char *format, ...)
{
	printf("--- ");
	(void)user_data;
	va_list args;
	va_start(args, format);
	vprintf(format, args);
	va_end(args);
	printf("\n");
}

static void user_qlog(void *user_data, uint32_t flags, const void *data, size_t datalen)
{
	knot_xquic_conn_t *xconn = user_data;
	char fqlog[39] = { 0 };
	uint64_t cid_int = (xconn->ocid->datalen >= sizeof(cid_int) ? knot_wire_read_u64(xconn->ocid->data) : 0);
	sprintf(fqlog, "/home/peltan/mnt/%016lx.qlog", cid_int);

	FILE *qlog = fopen(fqlog, "a");
	if (qlog != NULL) {
		//fprintf(qlog, "\n%u: ", flags);
		for (size_t i = 0; i < datalen; i++) {
			fputc(*(uint8_t *)(data + i), qlog);
		}
		fclose(qlog);
	}
}

static int conn_new(ngtcp2_conn **pconn, const ngtcp2_path *path, const ngtcp2_cid *scid,
                    const ngtcp2_cid *dcid, const ngtcp2_cid *odcid, uint32_t version,
                    uint64_t now, void *user_data, bool server)
{
	// I. CALLBACKS
	const ngtcp2_callbacks callbacks = {
		ngtcp2_crypto_client_initial_cb,
		ngtcp2_crypto_recv_client_initial_cb,
		ngtcp2_crypto_recv_crypto_data_cb,
		knot_handshake_completed_cb,
		NULL, // recv_version_negotiation FIXME
		ngtcp2_crypto_encrypt_cb,
		ngtcp2_crypto_decrypt_cb,
		ngtcp2_crypto_hp_mask_cb,
		recv_stream_data,
		acked_stream_data_offset_cb,
		stream_opened,
		stream_closed,
		recv_stateless_rst,
		ngtcp2_crypto_recv_retry_cb,
		NULL, // extend_max_streams_bidi
		NULL, // extend_max_streams_uni
		knot_quic_rand_cb,
		get_new_connection_id,
		remove_connection_id,
		ngtcp2_crypto_update_key_cb,
		NULL, // TODO path_validation,
		NULL, // select_preferred_addr
		recv_stream_rst, // TODO ::stream_reset,
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

	// II. SETTINGS
	ngtcp2_settings settings;
	ngtcp2_settings_default(&settings);
	settings.initial_ts = now;
	settings.log_printf = user_printf;
	//TODO pass token
	settings.token.base = NULL;
	settings.token.len = 0;
	//TODO UDP payload configuration
	if (0 /*configured max UDP payload*/) {
		//settings.max_udp_payload_size = 0; //TODO from configuration
		settings.no_udp_payload_size_shaping = 1;
	} else {
		settings.max_udp_payload_size = 1472;
		settings.assume_symmetric_path = 1;
	}
	settings.qlog.odcid = *odcid;
	settings.qlog.write = user_qlog;
	// TODO handshake_timeout ?

	// III. PARAMS
	ngtcp2_transport_params params;
	ngtcp2_transport_params_default(&params);

	params.initial_max_data = 786432;
	params.initial_max_stream_data_bidi_local = 524288;
	params.initial_max_stream_data_bidi_remote = 524288;
	params.initial_max_stream_data_uni = 524288;

	// params.initial_max_stream_data_bidi_local = config.max_stream_data_bidi_local;
	// params.initial_max_stream_data_bidi_remote = config.max_stream_data_bidi_remote;
	// params.initial_max_stream_data_uni = config.max_stream_data_uni;
	// params.initial_max_data = config.max_data;
	params.initial_max_streams_bidi = 100;
	params.initial_max_streams_uni = 3;
	params.max_idle_timeout = 5000000000L; // FIXME allow idle timeout configuration
	// params.stateless_reset_token_present = 1;
	// params.active_connection_id_limit = 7;
	if (odcid) {
		params.original_dcid = *odcid;
		// params.retry_scid = *scid;
		// params.retry_scid_present = 1; // NO!
	} else {
		params.original_dcid = *scid;
	}
	if (dnssec_random_buffer(params.stateless_reset_token, NGTCP2_STATELESS_RESET_TOKENLEN) != DNSSEC_EOK) {
		// TODO std::cerr << "Could not generate stateless reset token" << std::endl;
		return KNOT_ERROR;
	}

	if (server) {
		return ngtcp2_conn_server_new(pconn, dcid, scid, path, version, &callbacks, &settings, &params, NULL, user_data);
	} else {
		return ngtcp2_conn_client_new(pconn, dcid, scid, path, version, &callbacks, &settings, &params, NULL, user_data);
	}
}

_public_
int knot_xquic_client(knot_xquic_table_t *table, struct sockaddr_storage *dest,
                      struct sockaddr_storage *via, knot_xquic_conn_t **out_conn)
{
	ngtcp2_cid scid = { 0 }, dcid = { 0 };
	uint64_t now = get_timestamp();

	init_random_cid(&scid, 0);
	init_random_cid(&dcid, 0);

	knot_xquic_conn_t **pxconn = xquic_table_add(NULL, &dcid, table); // TODO scid ??
	if (pxconn == NULL) {
		return ENOMEM;
	}

	ngtcp2_path path;
	path.remote.addr = (struct sockaddr *)dest;
	path.remote.addrlen = sockaddr_len(dest);
	path.local.addr = (struct sockaddr *)via;
	path.local.addrlen = sockaddr_len(via);

	int ret = conn_new(&(*pxconn)->conn, &path, &dcid, &scid, &dcid /* ??? */, NGTCP2_PROTO_VER_V1, now, *pxconn, false);
	if (ret == KNOT_EOK) {
		ret = tls_init_conn_session(*pxconn, false);
	}
	if (ret == KNOT_EOK) {
		ret = gnutls_server_name_set((*pxconn)->tls_session, GNUTLS_NAME_DNS, "tcpserver", strlen("tcpserver")); // FIXME
	}
	if (ret != KNOT_EOK) {
		xquic_table_rem(*pxconn, table);
		return ret;
	}

	*out_conn = *pxconn;
	return KNOT_EOK;
}

static int handle_packet(knot_xdp_msg_t *msg, knot_xquic_table_t *table, knot_xquic_conn_t **out_conn, int64_t *out_stream)
{
	uint32_t pversion = 0;
	ngtcp2_cid scid = { 0 }, dcid = { 0 };
	const uint8_t *scid_data, *dcid_data;
	uint64_t now = get_timestamp();
	int ret = ngtcp2_pkt_decode_version_cid(&pversion, &dcid_data, &dcid.datalen, &scid_data, &scid.datalen,
	                                        msg->payload.iov_base, msg->payload.iov_len, 8 /* FIXME this is only suitable for AIOquic! SERVER_DEFAULT_SCIDLEN */);
	if (ret == NGTCP2_NO_ERROR) {
		memcpy(dcid.data, dcid_data, dcid.datalen);
		memcpy(scid.data, scid_data, scid.datalen);
	}
	printf("dcid data %p scid data %p msg payload %p\n", dcid.data, scid.data, msg->payload.iov_base);
	print_cid(&scid, "packet_scid:");
	print_cid(&dcid, "packet_dcid:");
	printf("(%s)\n", ngtcp2_strerror(ret));
	if (ret == NGTCP2_ERR_VERSION_NEGOTIATION) {
		// TODO
		assert(0);
		return KNOT_EOK;
	} else if (ret < 0) {
		return ret;
	}

	knot_xquic_conn_t **pxconn = xquic_table_lookup(&dcid, table), *xconn = *pxconn;

	if (pversion == 0 /* short header */ && xconn == NULL) {
		// TODO
		assert(0);
		return KNOT_EOK;
	}

	ngtcp2_path path;
	path.remote.addr = (struct sockaddr *)&msg->ip_from;
	path.remote.addrlen = sockaddr_len((struct sockaddr_storage *)&msg->ip_from);
	path.local.addr = (struct sockaddr *)&msg->ip_to;
	path.local.addrlen = sockaddr_len((struct sockaddr_storage *)&msg->ip_to);

	if (xconn == NULL) {
		// new conn

		ret = ngtcp2_accept(NULL, msg->payload.iov_base, msg->payload.iov_len); // FIXME
		printf("accept (%s)\n", ngtcp2_strerror(ret));

		xconn = *xquic_table_add(NULL, &dcid, table);
		if (xconn == NULL) { // FIXME returned NULL is &xconn
			return ENOMEM;
		}

		ret = conn_new(&xconn->conn, &path, &dcid, &scid, &dcid, pversion, now, xconn, true);
		printf("csn (%s)\n", knot_strerror(ret));

		if (ret < 0) {
			// TODO delete xconn and fail
			assert(0);
			return KNOT_EOK;
		}

		ret = tls_init_conn_session(xconn, true);
		printf("TLS (%s)\n", knot_strerror(ret));

		if (ret != KNOT_EOK) {
			printf("conn TLS error (%s)\n", knot_strerror(ret));
		}
	}

	ngtcp2_pkt_info pi = { .ecn = NGTCP2_ECN_NOT_ECT, }; // TODO: explicit congestion notification

	xconn->last_stream = -1;

	ret = ngtcp2_conn_read_pkt(xconn->conn, &path, &pi, msg->payload.iov_base, msg->payload.iov_len, now);
	printf("read pkt %p %p %p len %zu (%s)\n", xconn, xconn->conn, xconn->tls_session, msg->payload.iov_len, ngtcp2_strerror(ret));

	if (ret == KNOT_EOK) {
		*out_conn = xconn;
		*out_stream = xconn->last_stream;
		memcpy(xconn->last_eth_rem, msg->eth_from, sizeof(msg->eth_from));
		memcpy(xconn->last_eth_loc, msg->eth_to, sizeof(msg->eth_to));
		xquic_conn_mark_used(xconn, table);
	} else if (ngtcp2_err_is_fatal(ret)) {
		printf("ERR FATAL\n");
		xquic_table_rem(xconn, table);
		// FIXME
	} else if (ret == NGTCP2_ERR_DRAINING) { // received CONNECTION_CLOSE from the counterpart
		printf("DRAINING\n");
		xquic_table_rem(xconn, table);
		printf("remaining conns: %zu pointers: %zu\n", table->usage, table->pointers);
	}

	return ret;
}

_public_
int knot_xquic_recv(knot_xquic_conn_t **relays, int64_t *streams,
                    knot_xdp_msg_t *msgs, uint32_t count,
                    knot_xquic_table_t *quic_table)
{
	memset(relays, 0, count * sizeof(*relays));

	for (uint32_t i = 0; i < count; i++) {
		knot_xdp_msg_t *msg = &msgs[i];
		const uint8_t *payl = msg->payload.iov_base;
		if ((msg->flags & KNOT_XDP_MSG_TCP) ||
		    msg->payload.iov_len < 4 ||
		    (payl[2] != 0 && payl[3] == 0)) { // not QUIC
			continue;
		}

		int ret = handle_packet(msg, quic_table, &relays[i], &streams[i]);
		(void)ret;
	}

	return KNOT_EOK;
}

static int send_stream(knot_xdp_socket_t *sock, knot_xquic_conn_t *relay, int64_t stream_id,
		       uint8_t *data, size_t len, bool fin, ngtcp2_ssize *sent)
{
	assert(stream_id >= 0 || (data == NULL && len == 0));

	bool ipv6 = false; // FIXME

	uint32_t xdp_sent = 0;
	knot_xdp_msg_t msg = { 0 };
	int ret = knot_xdp_send_alloc(sock, ipv6 ? KNOT_XDP_MSG_IPV6 : 0, &msg);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ngtcp2_path path = { 0 }; // FIXME path not needed here ??
	path.local.addr = (struct sockaddr *)&msg.ip_from;
	path.remote.addr = (struct sockaddr *)&msg.ip_to;

	uint32_t fl = ((stream_id >= 0 && fin) ? NGTCP2_WRITE_STREAM_FLAG_FIN : NGTCP2_WRITE_STREAM_FLAG_NONE);
	ngtcp2_vec vec = { .base = data, .len = len };

	ret = ngtcp2_conn_writev_stream(relay->conn, &path, NULL, msg.payload.iov_base, msg.payload.iov_len,
	                                sent, fl, stream_id, &vec, (stream_id >= 0 ? 1 : 0), get_timestamp());
	printf("WRITEV %d ... %zu %p state %d\n", ret, msg.payload.iov_len, relay->conn, *(int *)relay->conn);
	if (ret <= 0) {
		knot_xdp_send_free(sock, &msg, 1);
		return ret;
	}

	msg.payload.iov_len = ret;
	memcpy(msg.eth_from, relay->last_eth_loc, sizeof(msg.eth_from));
	memcpy(msg.eth_to, relay->last_eth_rem, sizeof(msg.eth_to));
	ret = knot_xdp_send(sock, &msg, 1, &xdp_sent);
	if (ret == KNOT_EOK) {
		assert(xdp_sent == 1);
		return 1;
	}
	return ret;
}

_public_
int knot_xquic_send(knot_xdp_socket_t *sock, knot_xquic_conn_t *relay, unsigned max_msgs)
{
	if (relay == NULL || relay->conn == NULL) {
		return KNOT_EOK;
	}

	unsigned sent_msgs = 0, stream_msgs = 0;
	int ret = 1;
	for (int64_t si = 0; si < relay->streams_count && sent_msgs < max_msgs &&
	     ngtcp2_conn_is_handshake_completed(relay->conn); /* NO INCREMENT */) {
		int64_t stream_id = 4 * (relay->streams_first + si);

		ngtcp2_ssize sent = 0;
		size_t uf = relay->streams[si].unsent_offset;
		knot_xquic_obuf_t *uo = relay->streams[si].unsent_obuf;
		if (uo == NULL) {
			si++;
			continue;
		}

		bool fin = (((node_t *)uo->node.next)->next == NULL);
		ret = send_stream(sock, relay, stream_id, uo->buf + uf, uo->len - uf, fin, &sent);
		printf("UO %p len %zu off %zu fin %d ret %d\n", uo, uo->len, uf, fin, ret);
		if (ret < 0) {
			return ret;
		}

		sent_msgs++;
		stream_msgs++;
		knot_xquic_stream_mark_sent(relay, stream_id, sent);

		if (stream_msgs >= max_msgs / relay->streams_count) {
			stream_msgs = 0;
			si++; // if this stream is sending too much, give chance to other streams
		}
	}

	while (ret == 1) {
		ngtcp2_ssize unused = 0;
		ret = send_stream(sock, relay, -1, NULL, 0, false, &unused);
	}

	return ret;
}
