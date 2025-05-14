/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <assert.h>
#include <fcntl.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/x509.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>

#include "libknot/quic/quic.h"

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

#define SERVER_DEFAULT_SCIDLEN 18
#define QUIC_REGULAR_TOKEN_TIMEOUT (24 * 3600 * 1000000000LLU)

#define QUIC_SEND_VERSION_NEGOTIATION    NGTCP2_ERR_VERSION_NEGOTIATION
#define QUIC_SEND_RETRY                  NGTCP2_ERR_RETRY
#define QUIC_SEND_STATELESS_RESET        (-NGTCP2_STATELESS_RESET_TOKENLEN)
#define QUIC_SEND_CONN_CLOSE             (-KNOT_QUIC_HANDLE_RET_CLOSE)
#define QUIC_SEND_EXCESSIVE_LOAD         (-KNOT_QUIC_ERR_EXCESSIVE_LOAD)

#define TLS_CALLBACK_ERR     (-1)

typedef struct knot_tls_session {
	node_t n;
	gnutls_datum_t tls_session;
	size_t quic_params_len;
	uint8_t quic_params[sizeof(ngtcp2_transport_params)];
} knot_tls_session_t;

static unsigned addr_len(const struct sockaddr_in6 *ss)
{
	return (ss->sin6_family ==  AF_INET6 ?
	        sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in));
}

_public_
bool knot_quic_session_available(knot_quic_conn_t *conn)
{
	return conn != NULL && !(conn->flags & KNOT_QUIC_CONN_SESSION_TAKEN) &&
	       (gnutls_session_get_flags(conn->tls_session) & GNUTLS_SFLAGS_SESSION_TICKET);
}

_public_
struct knot_tls_session *knot_quic_session_save(knot_quic_conn_t *conn)
{
	if (!knot_quic_session_available(conn)) {
		return NULL;
	}

	knot_tls_session_t *session = malloc(sizeof(*session));
	if (session == NULL) {
		return NULL;
	}

	int ret = gnutls_session_get_data2(conn->tls_session, &session->tls_session);
	if (ret != GNUTLS_E_SUCCESS) {
		free(session);
		return NULL;
	}
	conn->flags |= KNOT_QUIC_CONN_SESSION_TAKEN;

	ngtcp2_ssize ret2 =
		ngtcp2_conn_encode_0rtt_transport_params(conn->conn, session->quic_params,
		                                         sizeof(session->quic_params));
	if (ret2 < 0) {
		free(session);
		return NULL;
	}
	session->quic_params_len = ret2;

	return session;
}

_public_
int knot_quic_session_load(knot_quic_conn_t *conn, struct knot_tls_session *session)
{
	if (session == NULL || (conn != NULL && session->quic_params_len == 0)) {
		return KNOT_EINVAL;
	}

	int ret = KNOT_EOK;
	if (conn == NULL) { // Just cleanup the session.
		goto session_free;
	}

	ret = gnutls_session_set_data(conn->tls_session, session->tls_session.data,
	                              session->tls_session.size);
	if (ret != GNUTLS_E_SUCCESS) {
		ret = KNOT_ERROR;
		goto session_free;
	}

	ret = ngtcp2_conn_decode_and_set_0rtt_transport_params(conn->conn, session->quic_params,
	                                                       session->quic_params_len);
	if (ret != 0) {
		ret = KNOT_ERROR;
	}

session_free:
	gnutls_free(session->tls_session.data);
	free(session);
	return ret;
}

static ngtcp2_conn *get_conn(ngtcp2_crypto_conn_ref *conn_ref)
{
	return ((knot_quic_conn_t *)conn_ref->user_data)->conn;
}

static int tls_init_conn_session(knot_quic_conn_t *conn, bool server)
{
	int ret = knot_tls_session(&conn->tls_session, conn->quic_table->creds,
	                           conn->quic_table->priority,
	                           (server ? KNOT_TLS_SERVER : KNOT_TLS_CLIENT) |
	                           KNOT_TLS_QUIC | KNOT_TLS_DNS | KNOT_TLS_EARLY_DATA);
	if (ret != KNOT_EOK) {
		return TLS_CALLBACK_ERR;
	}

	if (server) {
		ret = ngtcp2_crypto_gnutls_configure_server_session(conn->tls_session);
	} else {
		ret = ngtcp2_crypto_gnutls_configure_client_session(conn->tls_session);
	}
	if (ret != NGTCP2_NO_ERROR) {
		return TLS_CALLBACK_ERR;
	}

	conn->conn_ref = (nc_conn_ref_placeholder_t) {
		.get_conn = get_conn,
		.user_data = conn
	};

	_Static_assert(sizeof(nc_conn_ref_placeholder_t) == sizeof(ngtcp2_crypto_conn_ref),
	               "invalid placeholder for conn_ref");
	gnutls_session_set_ptr(conn->tls_session, &conn->conn_ref);

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

uint64_t quic_conn_get_timeout(knot_quic_conn_t *conn)
{
	return ngtcp2_conn_get_expiry(conn->conn);
}

bool quic_conn_timeout(knot_quic_conn_t *conn, uint64_t *now)
{
	if (*now == 0) {
		*now = get_timestamp();
	}
	return *now > quic_conn_get_timeout(conn);
}

_public_
int64_t knot_quic_conn_next_timeout(knot_quic_conn_t *conn)
{
	return (((int64_t)quic_conn_get_timeout(conn) - (int64_t)get_timestamp()) / 1000000L);
}

_public_
int knot_quic_hanle_expiry(knot_quic_conn_t *conn)
{
	return ngtcp2_conn_handle_expiry(conn->conn, get_timestamp()) == NGTCP2_NO_ERROR ? KNOT_EOK : KNOT_ECONN;
}

_public_
uint32_t knot_quic_conn_rtt(knot_quic_conn_t *conn)
{
	ngtcp2_conn_info info = { 0 };
	ngtcp2_conn_get_conn_info(conn->conn, &info);
	return info.smoothed_rtt / 1000; // nanosec --> usec
}

_public_
uint16_t knot_quic_conn_local_port(knot_quic_conn_t *conn)
{
	const ngtcp2_path *path = ngtcp2_conn_get_path(conn->conn);
	return ((const struct sockaddr_in6 *)path->local.addr)->sin6_port;
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

static bool init_unique_cid(ngtcp2_cid *cid, size_t len, knot_quic_table_t *table)
{
	do {
		if (init_random_cid(cid, len), cid->datalen == 0) {
			return false;
		}
	} while (quic_table_lookup(cid, table) != NULL);
	return true;
}

static int get_new_connection_id(ngtcp2_conn *conn, ngtcp2_cid *cid,
                                 uint8_t *token, size_t cidlen,
                                 void *user_data)
{
	knot_quic_conn_t *ctx = (knot_quic_conn_t *)user_data;
	assert(ctx->conn == conn);

	if (!init_unique_cid(cid, cidlen, ctx->quic_table)) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	knot_quic_cid_t **addto = quic_table_insert(ctx, cid, ctx->quic_table);
	(void)addto;

	if (token != NULL &&
	    ngtcp2_crypto_generate_stateless_reset_token(
	            token, (uint8_t *)ctx->quic_table->hash_secret,
	            sizeof(ctx->quic_table->hash_secret), cid) != 0) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

static int remove_connection_id(ngtcp2_conn *conn, const ngtcp2_cid *cid,
                                void *user_data)
{
	knot_quic_conn_t *ctx = (knot_quic_conn_t *)user_data;
	assert(ctx->conn == conn);

	knot_quic_cid_t **torem = quic_table_lookup2(cid, ctx->quic_table);
	if (torem != NULL) {
		assert((*torem)->conn == ctx);
		quic_table_rem2(torem, ctx->quic_table);
	}

	return 0;
}

static int handshake_completed_cb(ngtcp2_conn *conn, void *user_data)
{
	knot_quic_conn_t *ctx = (knot_quic_conn_t *)user_data;
	assert(ctx->conn == conn);

	assert(!(ctx->flags & KNOT_QUIC_CONN_HANDSHAKE_DONE));
	ctx->flags |= KNOT_QUIC_CONN_HANDSHAKE_DONE;

	if (!ngtcp2_conn_is_server(conn)) {
		return knot_tls_pin_check(ctx->tls_session, ctx->quic_table->creds) == KNOT_EOK
		       && knot_tls_cert_check_creds(ctx->tls_session, ctx->quic_table->creds) == KNOT_EOK
			       ? 0
			       : NGTCP2_ERR_CALLBACK_FAILURE;
	}

	if (gnutls_session_ticket_send(ctx->tls_session, 1, 0) != GNUTLS_E_SUCCESS) {
		return TLS_CALLBACK_ERR;
	}

	uint8_t token[NGTCP2_CRYPTO_MAX_REGULAR_TOKENLEN];
	ngtcp2_path path = *ngtcp2_conn_get_path(ctx->conn);
	uint64_t ts = get_timestamp();
	ngtcp2_ssize tokenlen = ngtcp2_crypto_generate_regular_token(token,
			(uint8_t *)ctx->quic_table->hash_secret,
			sizeof(ctx->quic_table->hash_secret),
			path.remote.addr, path.remote.addrlen, ts);
	if (tokenlen < 0) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	if (ngtcp2_conn_submit_new_token(ctx->conn, token, tokenlen) != 0) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

static int recv_stream_data(ngtcp2_conn *conn, uint32_t flags,
                            int64_t stream_id, uint64_t offset,
                            const uint8_t *data, size_t datalen,
                            void *user_data, void *stream_user_data)
{
	(void)(stream_user_data); // always NULL
	(void)(offset); // QUIC shall ensure that data arrive in-order

	knot_quic_conn_t *ctx = (knot_quic_conn_t *)user_data;
	assert(ctx->conn == conn);

	int ret = knot_quic_stream_recv_data(ctx, stream_id, data, datalen,
	                                     (flags & NGTCP2_STREAM_DATA_FLAG_FIN));

	return ret == KNOT_EOK ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
}

static int acked_stream_data_offset_cb(ngtcp2_conn *conn, int64_t stream_id,
                                    uint64_t offset, uint64_t datalen,
                                    void *user_data, void *stream_user_data)
{
	knot_quic_conn_t *ctx = (knot_quic_conn_t *)user_data;

	bool keep = !ngtcp2_conn_is_server(conn); // kxdpgun: await incomming reply after query sent&acked

	knot_quic_stream_ack_data(ctx, stream_id, offset + datalen, keep);

	return 0;
}

static int stream_closed(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
			 uint64_t app_error_code, void *user_data, void *stream_user_data)
{
	knot_quic_conn_t *ctx = (knot_quic_conn_t *)user_data;
	assert(ctx->conn == conn);

	// NOTE possible error is stored in (flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET)

	bool keep = !ngtcp2_conn_is_server(conn); // kxdpgun: process incomming reply after recvd&closed
	if (!keep) {
		knot_quic_conn_stream_free(ctx, stream_id);
	}
	return 0;
}

static int recv_stateless_rst(ngtcp2_conn *conn, const ngtcp2_pkt_stateless_reset *sr,
                              void *user_data)
{
	// NOTE server can't receive stateless resets, only client

	// ngtcp2 verified stateless reset token already
	(void)(sr);

	knot_quic_conn_t *ctx = (knot_quic_conn_t *)user_data;
	assert(ctx->conn == conn);

	knot_quic_table_rem(ctx, ctx->quic_table);
	knot_quic_cleanup(&ctx, 1);

	return 0;
}

static int recv_stream_rst(ngtcp2_conn *conn, int64_t stream_id, uint64_t final_size,
                           uint64_t app_error_code, void *user_data, void *stream_user_data)
{
	(void)final_size;
	return stream_closed(conn, NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET,
	                     stream_id, app_error_code, user_data, stream_user_data);
}

static void user_printf(void *user_data, const char *format, ...)
{
	knot_quic_conn_t *ctx = (knot_quic_conn_t *)user_data;
	if (ctx->quic_table->log_cb != NULL) {
		char buf[256];
		va_list args;
		va_start(args, format);
		vsnprintf(buf, sizeof(buf), format, args);
		va_end(args);
		ctx->quic_table->log_cb(buf);
	}
}

static void hex_encode(const uint8_t  *in, const uint32_t in_len, char *out)
{
	static const char hex[] = "0123456789abcdef";

	for (uint32_t i = 0; i < in_len; i++) {
		out[2 * i]     = hex[in[i] / 16];
		out[2 * i + 1] = hex[in[i] % 16];
	}
}

static void user_qlog(void *user_data, uint32_t flags, const void *data, size_t datalen)
{
	knot_quic_conn_t *ctx = (knot_quic_conn_t *)user_data;
	if (ctx->quic_table->qlog_dir != NULL) {
		if (ctx->qlog_fd < 0) {
			const ngtcp2_cid *cid = ngtcp2_conn_get_client_initial_dcid(ctx->conn);
			if (cid->datalen == 0) {
				cid = ngtcp2_conn_get_dcid(ctx->conn);
			}
			unsigned qlog_dir_len = strlen(ctx->quic_table->qlog_dir);
			unsigned qlog_name_len = qlog_dir_len + 2 * cid->datalen + 7;
			char qlog_name[qlog_name_len];
			memcpy(qlog_name, ctx->quic_table->qlog_dir, qlog_dir_len);
			qlog_name[qlog_dir_len] = '/';
			hex_encode(cid->data, cid->datalen, qlog_name + qlog_dir_len + 1);
			memcpy(qlog_name + qlog_name_len - 6, ".qlog", 6);

			ctx->qlog_fd = open(qlog_name, O_CREAT | O_WRONLY | O_APPEND, 0666);
		}
		if (ctx->qlog_fd >= 0) { // othewise silently skip
			_unused_ ssize_t unused = write(ctx->qlog_fd, data, datalen);
			if (flags & NGTCP2_QLOG_WRITE_FLAG_FIN) {
				close(ctx->qlog_fd);
				ctx->qlog_fd = -1;
			}
		}
	}
}

static int conn_new(ngtcp2_conn **pconn, const ngtcp2_path *path, const ngtcp2_cid *scid,
                    const ngtcp2_cid *dcid, const ngtcp2_cid *odcid, uint32_t version,
                    uint64_t now, uint64_t idle_timeout_ns,
                    knot_quic_conn_t *qconn, bool server, bool retry_sent)
{
	knot_quic_table_t *qtable = qconn->quic_table;

	// I. CALLBACKS
	const ngtcp2_callbacks callbacks = {
		ngtcp2_crypto_client_initial_cb,
		ngtcp2_crypto_recv_client_initial_cb,
		ngtcp2_crypto_recv_crypto_data_cb,
		handshake_completed_cb,
		NULL, // recv_version_negotiation not needed on server, nor kxdpgun
		ngtcp2_crypto_encrypt_cb,
		ngtcp2_crypto_decrypt_cb,
		ngtcp2_crypto_hp_mask_cb,
		recv_stream_data,
		acked_stream_data_offset_cb,
		NULL, // stream_opened
		stream_closed,
		recv_stateless_rst,
		ngtcp2_crypto_recv_retry_cb,
		NULL, // extend_max_streams_bidi
		NULL, // extend_max_streams_uni
		knot_quic_rand_cb,
		get_new_connection_id,
		remove_connection_id,
		ngtcp2_crypto_update_key_cb,
		NULL, // path_validation,
		NULL, // select_preferred_addr
		recv_stream_rst,
		NULL, // extend_max_remote_streams_bidi, might be useful to some allocation optimizations?
		NULL, // extend_max_remote_streams_uni
		NULL, // extend_max_stream_data,
		NULL, // dcid_status
		NULL, // handshake_confirmed
		NULL, // recv_new_token
		ngtcp2_crypto_delete_crypto_aead_ctx_cb,
		ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
		NULL, // recv_datagram
		NULL, // ack_datagram
		NULL, // lost_datagram
		ngtcp2_crypto_get_path_challenge_data_cb,
		NULL, // stream_stop_sending
		ngtcp2_crypto_version_negotiation_cb,
		NULL, // recv_rx_key
		NULL  // recv_tx_key
	};

	// II. SETTINGS
	ngtcp2_settings settings;
	ngtcp2_settings_default(&settings);
	settings.initial_ts = now;
	if (qtable->log_cb != NULL) {
		settings.log_printf = user_printf;
	}
	if (qtable->qlog_dir != NULL) {
		settings.qlog_write = user_qlog;
	}
	if (qtable->udp_payload_limit != 0) {
		settings.max_tx_udp_payload_size = qtable->udp_payload_limit;
	}

	settings.handshake_timeout = idle_timeout_ns; // NOTE setting handshake timeout to idle_timeout for simplicity
	settings.no_pmtud = true;

	// III. PARAMS
	ngtcp2_transport_params params;
	ngtcp2_transport_params_default(&params);

	params.disable_active_migration = true;
	params.initial_max_streams_uni = 0;
	params.initial_max_streams_bidi = 1024;
	params.initial_max_stream_data_bidi_local = NGTCP2_MAX_VARINT;
	params.initial_max_stream_data_bidi_remote = 102400;
	params.initial_max_data = NGTCP2_MAX_VARINT;

	params.max_idle_timeout = idle_timeout_ns;
	// params.stateless_reset_token_present = 1;
	// params.active_connection_id_limit = 7;
	if (odcid != NULL) {
		params.original_dcid = *odcid;
		params.original_dcid_present = true;
	}

	if (retry_sent) {
		assert(scid);
		params.retry_scid_present = 1;
		params.retry_scid = *scid;
	}
	if (dnssec_random_buffer(params.stateless_reset_token, NGTCP2_STATELESS_RESET_TOKENLEN) != DNSSEC_EOK) {
		return KNOT_ERROR;
	}

	if (server) {
		return ngtcp2_conn_server_new(pconn, dcid, scid, path, version, &callbacks,
		                              &settings, &params, NULL, qconn);
	} else {
		return ngtcp2_conn_client_new(pconn, dcid, scid, path, version, &callbacks,
		                              &settings, &params, NULL, qconn);
	}
}

_public_
int knot_quic_client(knot_quic_table_t *table, struct sockaddr_in6 *dest,
                     struct sockaddr_in6 *via, const char *server_name,
                     knot_quic_conn_t **out_conn)
{
	ngtcp2_cid scid = { 0 }, dcid = { 0 };
	uint64_t now = get_timestamp();

	if (table == NULL || dest == NULL || via == NULL || out_conn == NULL) {
		return KNOT_EINVAL;
	}

	init_random_cid(&scid, 0);
	init_random_cid(&dcid, 0);

	knot_quic_conn_t *conn = quic_table_add(NULL, &dcid, table);
	if (conn == NULL) {
		return ENOMEM;
	}

	ngtcp2_path path;
	path.remote.addr = (struct sockaddr *)dest;
	path.remote.addrlen = addr_len((const struct sockaddr_in6 *)dest);
	path.local.addr = (struct sockaddr *)via;
	path.local.addrlen = addr_len((const struct sockaddr_in6 *)via);

	int ret = conn_new(&conn->conn, &path, &dcid, &scid, NULL, NGTCP2_PROTO_VER_V1, now,
	                   5000000000L, conn, false, false);
	if (ret == KNOT_EOK) {
		ret = tls_init_conn_session(conn, false);
	}
	if (ret == KNOT_EOK && server_name != NULL) {
		ret = gnutls_server_name_set(conn->tls_session, GNUTLS_NAME_DNS,
		                             server_name, strlen(server_name));
	}
	if (ret != KNOT_EOK) {
		knot_quic_table_rem(conn, table);
		knot_quic_cleanup(&conn, 1);
		return ret;
	}

	*out_conn = conn;
	return KNOT_EOK;
}

_public_
int knot_quic_handle(knot_quic_table_t *table, knot_quic_reply_t *reply,
                     uint64_t idle_timeout, knot_quic_conn_t **out_conn)
{
	if (out_conn != NULL) {
		*out_conn = NULL;
	}
	if (table == NULL || reply == NULL || out_conn == NULL) {
		return KNOT_EINVAL;
	}

	ngtcp2_version_cid decoded_cids = { 0 };
	ngtcp2_cid scid = { 0 }, dcid = { 0 }, odcid = { 0 };
	if (reply->in_payload->iov_len < 1) {
		reply->handle_ret = KNOT_EOK;
		return KNOT_EOK;
	}
	int ret = ngtcp2_pkt_decode_version_cid(&decoded_cids,
	                                        reply->in_payload->iov_base,
	                                        reply->in_payload->iov_len,
	                                        SERVER_DEFAULT_SCIDLEN);
	if (ret == NGTCP2_ERR_VERSION_NEGOTIATION) {
		ret = -QUIC_SEND_VERSION_NEGOTIATION;
		goto finish;
	} else if (ret != NGTCP2_NO_ERROR) {
		goto finish;
	}
	ngtcp2_cid_init(&dcid, decoded_cids.dcid, decoded_cids.dcidlen);
	ngtcp2_cid_init(&scid, decoded_cids.scid, decoded_cids.scidlen);

	knot_quic_conn_t *conn = quic_table_lookup(&dcid, table);

	if (decoded_cids.version == 0 /* short header */ && conn == NULL) {
		ret = KNOT_EOK; // NOOP
		goto finish;
	}

	if (conn == NULL && (table->flags & KNOT_QUIC_TABLE_CLIENT_ONLY)) {
		return KNOT_EOK;
	}

	if (conn != NULL && (conn->flags & KNOT_QUIC_CONN_BLOCKED)) {
		return KNOT_EOK;
	}

	uint64_t now = get_timestamp(); // the timestamps needs to be collected AFTER the check for blocked conn

	ngtcp2_path path;
	path.remote.addr = (struct sockaddr *)reply->ip_rem;
	path.remote.addrlen = addr_len((struct sockaddr_in6 *)reply->ip_rem);
	path.local.addr = (struct sockaddr *)reply->ip_loc;
	path.local.addrlen = addr_len((struct sockaddr_in6 *)reply->ip_loc);

	if (conn == NULL) {
		// new conn

		ngtcp2_pkt_hd header = { 0 };
		ret = ngtcp2_accept(&header, reply->in_payload->iov_base,
		                    reply->in_payload->iov_len);
		if (ret == NGTCP2_ERR_RETRY) {
			ret = -QUIC_SEND_RETRY;
			goto finish;
		} else if (ret != NGTCP2_NO_ERROR) { // discard packet
			ret = KNOT_EOK;
			goto finish;
		}

		assert(header.type == NGTCP2_PKT_INITIAL);
		if (header.tokenlen == 0 && quic_require_retry(table)) {
			ret = -QUIC_SEND_RETRY;
			goto finish;
		}

		if (header.tokenlen > 0) {
			if (header.token[0] == NGTCP2_CRYPTO_TOKEN_MAGIC_RETRY) {
				ret = ngtcp2_crypto_verify_retry_token(
					&odcid, header.token, header.tokenlen,
					(const uint8_t *)table->hash_secret,
					sizeof(table->hash_secret), header.version,
					(const struct sockaddr *)reply->ip_rem,
					addr_len((struct sockaddr_in6 *)reply->ip_rem),
					&dcid, idle_timeout, now // NOTE setting retry token validity to idle_timeout for simplicity
				);
			} else {
				ret = ngtcp2_crypto_verify_regular_token(
					header.token, header.tokenlen,
					(const uint8_t *)table->hash_secret,
					sizeof(table->hash_secret),
					(const struct sockaddr *)reply->ip_rem,
					addr_len((struct sockaddr_in6 *)reply->ip_rem),
					QUIC_REGULAR_TOKEN_TIMEOUT, now
				);
			}
			if (ret != 0) {
				ret = KNOT_EOK;
				goto finish;
			}
		} else {
			memcpy(&odcid, &dcid, sizeof(odcid));
		}

		// server chooses his CID to his liking
		if (!init_unique_cid(&dcid, 0, table)) {
			ret = KNOT_ERROR;
			goto finish;
		}

		conn = quic_table_add(NULL, &dcid, table);
		if (conn == NULL) {
			ret = KNOT_ENOMEM;
			goto finish;
		}

		ret = conn_new(&conn->conn, &path, &dcid, &scid, &odcid, decoded_cids.version,
		               now, idle_timeout, conn, true, header.tokenlen > 0);
		if (ret >= 0) {
			ret = tls_init_conn_session(conn, true);
		}
		if (ret < 0) {
			knot_quic_table_rem(conn, table);
			*out_conn = conn; // we need knot_quic_cleanup() by the caller afterwards
			goto finish;
		}
	}

	ngtcp2_pkt_info pi = { .ecn = reply->ecn, };

	ret = ngtcp2_conn_read_pkt(conn->conn, &path, &pi, reply->in_payload->iov_base,
	                           reply->in_payload->iov_len, now);

	*out_conn = conn;
	if (ret == NGTCP2_ERR_DRAINING) { // received CONNECTION_CLOSE from the counterpart
		knot_quic_table_rem(conn, table);
		ret = KNOT_EOK;
		goto finish;
	} else if (ngtcp2_err_is_fatal(ret)) { // connection doomed
		if (ret == NGTCP2_ERR_CALLBACK_FAILURE) {
			ret = KNOT_EBADCERT;
		} else {
			ret = KNOT_ECONN;
		}
		knot_quic_table_rem(conn, table);
		goto finish;
	} else if (ret != NGTCP2_NO_ERROR) { // non-fatal error, discard packet
		ret = KNOT_EOK;
		goto finish;
	}

	quic_conn_mark_used(conn, table);

	ret = KNOT_EOK;
finish:
	reply->handle_ret = ret;
	return ret;
}

static bool stream_exists(knot_quic_conn_t *conn, int64_t stream_id)
{
	// TRICK, we never use stream_user_data
	return (ngtcp2_conn_set_stream_user_data(conn->conn, stream_id, NULL) == NGTCP2_NO_ERROR);
}

static int send_stream(knot_quic_table_t *quic_table, knot_quic_reply_t *rpl,
                       knot_quic_conn_t *relay, int64_t stream_id,
                       uint8_t *data, size_t len, bool fin, ngtcp2_ssize *sent)
{
	(void)quic_table;
	assert(stream_id >= 0 || (data == NULL && len == 0));

	while (stream_id >= 0 && !stream_exists(relay, stream_id)) {
		int64_t opened = 0;
		int ret = ngtcp2_conn_open_bidi_stream(relay->conn, &opened, NULL);
		if (ret != KNOT_EOK) {
			return ret;
		}
		assert((bool)(opened == stream_id) == stream_exists(relay, stream_id));
	}

	int ret = rpl->alloc_reply(rpl);
	if (ret != KNOT_EOK) {
		return ret;
	}

	uint32_t fl = ((stream_id >= 0 && fin) ? NGTCP2_WRITE_STREAM_FLAG_FIN :
	                                         NGTCP2_WRITE_STREAM_FLAG_NONE);
	ngtcp2_vec vec = { .base = data, .len = len };
	ngtcp2_pkt_info pi = { 0 };

	struct sockaddr_storage path_loc = { 0 }, path_rem = { 0 };
	ngtcp2_path path = { .local  = { .addr = (struct sockaddr *)&path_loc, .addrlen = sizeof(path_loc) },
	                     .remote = { .addr = (struct sockaddr *)&path_rem, .addrlen = sizeof(path_rem) },
	                     .user_data = NULL };
	bool find_path = (rpl->ip_rem == NULL);
	assert(find_path == (bool)(rpl->ip_loc == NULL));

	ret = ngtcp2_conn_writev_stream(relay->conn, find_path ? &path : NULL, &pi,
	                                rpl->out_payload->iov_base, rpl->out_payload->iov_len,
	                                sent, fl, stream_id, &vec,
	                                (stream_id >= 0 ? 1 : 0), get_timestamp());
	if (ret <= 0) {
		rpl->free_reply(rpl);
		return ret;
	}
	if (*sent < 0) {
		*sent = 0;
	}

	rpl->out_payload->iov_len = ret;
	rpl->ecn = pi.ecn;
	if (find_path) {
		rpl->ip_loc = &path_loc;
		rpl->ip_rem = &path_rem;
	}
	ret = rpl->send_reply(rpl);
	if (find_path) {
		rpl->ip_loc = NULL;
		rpl->ip_rem = NULL;
	}
	if (ret == KNOT_EOK) {
		return 1;
	}
	return ret;
}

static int send_special(knot_quic_table_t *quic_table, knot_quic_reply_t *rpl,
			knot_quic_conn_t *relay /* only for connection close */)
{
	int ret = rpl->alloc_reply(rpl);
	if (ret != KNOT_EOK) {
		return ret;
	}

	uint64_t now = get_timestamp();
	ngtcp2_version_cid decoded_cids = { 0 };
	ngtcp2_cid scid = { 0 }, dcid = { 0 };
	int dvc_ret = NGTCP2_ERR_FATAL;

	if ((rpl->handle_ret == -QUIC_SEND_VERSION_NEGOTIATION ||
	     rpl->handle_ret == -QUIC_SEND_RETRY) &&
	    rpl->in_payload != NULL && rpl->in_payload->iov_len > 0) {
		dvc_ret = ngtcp2_pkt_decode_version_cid(
			&decoded_cids, rpl->in_payload->iov_base,
			rpl->in_payload->iov_len, SERVER_DEFAULT_SCIDLEN);
	}

	uint8_t rnd = 0;
	dnssec_random_buffer(&rnd, sizeof(rnd));
	uint32_t supported_quic[1] = { NGTCP2_PROTO_VER_V1 };
	ngtcp2_cid new_dcid;
	uint8_t retry_token[NGTCP2_CRYPTO_MAX_RETRY_TOKENLEN];
	uint8_t stateless_reset_token[NGTCP2_STATELESS_RESET_TOKENLEN];
	uint8_t sreset_rand[NGTCP2_MIN_STATELESS_RESET_RANDLEN];
	dnssec_random_buffer(sreset_rand, sizeof(sreset_rand));
	ngtcp2_ccerr ccerr;
	ngtcp2_ccerr_default(&ccerr);
	ngtcp2_pkt_info pi = { 0 };

	struct sockaddr_storage path_loc = { 0 }, path_rem = { 0 };
	ngtcp2_path path = { .local  = { .addr = (struct sockaddr *)&path_loc, .addrlen = sizeof(path_loc) },
	                     .remote = { .addr = (struct sockaddr *)&path_rem, .addrlen = sizeof(path_rem) },
	                     .user_data = NULL };
	bool find_path = (rpl->ip_rem == NULL);
	assert(find_path == (bool)(rpl->ip_loc == NULL));
	assert(!find_path || rpl->handle_ret == -QUIC_SEND_EXCESSIVE_LOAD);

	switch (rpl->handle_ret) {
	case -QUIC_SEND_VERSION_NEGOTIATION:
		if (dvc_ret != NGTCP2_ERR_VERSION_NEGOTIATION) {
			rpl->free_reply(rpl);
			return KNOT_ERROR;
		}
		ret = ngtcp2_pkt_write_version_negotiation(
			rpl->out_payload->iov_base, rpl->out_payload->iov_len,
			rnd, decoded_cids.scid, decoded_cids.scidlen, decoded_cids.dcid,
			decoded_cids.dcidlen, supported_quic,
			sizeof(supported_quic) / sizeof(*supported_quic)
		);
		break;
	case -QUIC_SEND_RETRY:
		ngtcp2_cid_init(&dcid, decoded_cids.dcid, decoded_cids.dcidlen);
		ngtcp2_cid_init(&scid, decoded_cids.scid, decoded_cids.scidlen);

		init_random_cid(&new_dcid, 0);

		ret = ngtcp2_crypto_generate_retry_token(
			retry_token, (const uint8_t *)quic_table->hash_secret,
			sizeof(quic_table->hash_secret), decoded_cids.version,
			(const struct sockaddr *)rpl->ip_rem, sockaddr_len(rpl->ip_rem),
			&new_dcid, &dcid, now
		);

		if (ret >= 0) {
			ret = ngtcp2_crypto_write_retry(
				rpl->out_payload->iov_base, rpl->out_payload->iov_len,
				decoded_cids.version, &scid, &new_dcid, &dcid,
				retry_token, ret
			);
		}
		break;
	case -QUIC_SEND_STATELESS_RESET:
		ret = ngtcp2_pkt_write_stateless_reset(
			rpl->out_payload->iov_base, rpl->out_payload->iov_len,
			stateless_reset_token, sreset_rand, sizeof(sreset_rand)
		);
		break;
	case -QUIC_SEND_CONN_CLOSE:
		ret = ngtcp2_conn_write_connection_close(
			relay->conn, NULL, &pi, rpl->out_payload->iov_base,
			rpl->out_payload->iov_len, &ccerr, now
		);
		break;
	case -QUIC_SEND_EXCESSIVE_LOAD:
		ccerr.type = NGTCP2_CCERR_TYPE_APPLICATION;
		ccerr.error_code = KNOT_QUIC_ERR_EXCESSIVE_LOAD;
		ret = ngtcp2_conn_write_connection_close(
			relay->conn, find_path ? &path : NULL, &pi, rpl->out_payload->iov_base,
			rpl->out_payload->iov_len, &ccerr, now
		);
		break;
	default:
		ret = KNOT_EINVAL;
		break;
	}

	if (ret < 0) {
		rpl->free_reply(rpl);
	} else {
		rpl->out_payload->iov_len = ret;
		rpl->ecn = pi.ecn;
		if (find_path) {
			rpl->ip_loc = &path_loc;
			rpl->ip_rem = &path_rem;
		}
		ret = rpl->send_reply(rpl);
		if (find_path) {
			rpl->ip_loc = NULL;
			rpl->ip_rem = NULL;
		}
	}
	return ret;
}

_public_
int knot_quic_send(knot_quic_table_t *quic_table, knot_quic_conn_t *conn,
                   knot_quic_reply_t *reply, unsigned max_msgs,
                   knot_quic_send_flag_t flags)
{
	if (quic_table == NULL || conn == NULL || reply == NULL) {
		return KNOT_EINVAL;
	} else if (reply->handle_ret < 0) {
		return reply->handle_ret;
	} else if ((conn->flags & KNOT_QUIC_CONN_BLOCKED) && !(flags & KNOT_QUIC_SEND_IGNORE_BLOCKED)) {
		return KNOT_EOK;
	} else if (reply->handle_ret > 0) {
		return send_special(quic_table, reply, conn);
	} else if (conn == NULL) {
		return KNOT_EINVAL;
	} else if (conn->conn == NULL) {
		return KNOT_EOK;
	}

	if (!(conn->flags & KNOT_QUIC_CONN_HANDSHAKE_DONE)) {
		max_msgs = 1;
	}

	unsigned sent_msgs = 0, stream_msgs = 0, ignore_last = ((flags & KNOT_QUIC_SEND_IGNORE_LASTBYTE) ? 1 : 0);
	int ret = 1;
	for (int64_t si = 0; si < conn->streams_count && sent_msgs < max_msgs; /* NO INCREMENT */) {
		int64_t stream_id = 4 * (conn->streams_first + si);

		ngtcp2_ssize sent = 0;
		size_t uf = conn->streams[si].unsent_offset;
		knot_quic_obuf_t *uo = conn->streams[si].unsent_obuf;
		if (uo == NULL) {
			si++;
			continue;
		}

		bool fin = (((node_t *)uo->node.next)->next == NULL) && ignore_last == 0;
		ret = send_stream(quic_table, reply, conn, stream_id,
		                  uo->buf + uf, uo->len - uf - ignore_last,
		                  fin, &sent);
		if (ret < 0) {
			return ret;
		}

		sent_msgs++;
		stream_msgs++;
		if (sent > 0 && ignore_last > 0) {
			sent++;
		}
		if (sent > 0) {
			knot_quic_stream_mark_sent(conn, stream_id, sent);
		}

		if (stream_msgs >= max_msgs / conn->streams_count) {
			stream_msgs = 0;
			si++; // if this stream is sending too much, give chance to other streams
		}
	}

	while (ret == 1) {
		ngtcp2_ssize unused = 0;
		ret = send_stream(quic_table, reply, conn, -1, NULL, 0, false, &unused);
	}

	return ret;
}
