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
#include "contrib/string.h"
#include "contrib/ucw/lists.h"
#include "libknot/endian.h"
#include "libdnssec/error.h"
#include "libdnssec/random.h"
#include "libknot/attribute.h"
#include "libknot/endian.h"
#include "libknot/error.h"
#include "libknot/wire.h"

#define SERVER_DEFAULT_SCIDLEN 18

#define QUIC_DEFAULT_VERSION "-VERS-ALL:+VERS-TLS1.3"
#define QUIC_DEFAULT_GROUPS  "-GROUP-ALL:+GROUP-X25519:+GROUP-SECP256R1:+GROUP-SECP384R1:+GROUP-SECP521R1"
#define QUIC_PRIORITIES      "%DISABLE_TLS13_COMPAT_MODE:NORMAL:"QUIC_DEFAULT_VERSION":"QUIC_DEFAULT_GROUPS

#define XQUIC_SEND_VERSION_NEGOTIATION    NGTCP2_ERR_VERSION_NEGOTIATION
#define XQUIC_SEND_RETRY                  NGTCP2_ERR_RETRY
#define XQUIC_SEND_STATELESS_RESET        (-NGTCP2_STATELESS_RESET_TOKENLEN)

#define TLS_CALLBACK_ERR     (-1)

const gnutls_datum_t doq_alpn = {
	(unsigned char *)"doq", 3
};

typedef struct knot_quic_creds {
	gnutls_certificate_credentials_t tls_cert;
	gnutls_anti_replay_t tls_anti_replay;
	gnutls_datum_t tls_ticket_key;
	uint8_t *peer_pin;
	uint8_t peer_pin_len;
} knot_xquic_creds_t;

typedef struct knot_quic_session {
	node_t n;
	gnutls_datum_t tls_session;
	ngtcp2_transport_params quic_params;
} knot_xquic_session_t;

static unsigned addr_len(const struct sockaddr_in6 *ss)
{
	return (ss->sin6_family ==  AF_INET6 ?
	        sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in));
}

_public_
struct knot_quic_session *knot_xquic_session_save(knot_xquic_conn_t *conn)
{
	const ngtcp2_transport_params *tmp = ngtcp2_conn_get_remote_transport_params(conn->conn);
	if (tmp == NULL) {
		return NULL;
	}

	knot_xquic_session_t *session = calloc(1, sizeof(*session));
	if (session == NULL) {
		return NULL;
	}

	int ret = gnutls_session_get_data2(conn->tls_session, &session->tls_session);
	if (ret != GNUTLS_E_SUCCESS) {
		free(session);
		return NULL;
	}

	memcpy(&session->quic_params, tmp, sizeof(session->quic_params));

	return session;
}

_public_
int knot_xquic_session_load(knot_xquic_conn_t *conn, struct knot_quic_session *session)
{
	if (session == NULL) {
		return KNOT_EINVAL;
	}

	int ret = KNOT_EOK;
	if (conn == NULL) {
		goto session_free;
	}

	ret = gnutls_session_set_data(conn->tls_session, session->tls_session.data,
	                              session->tls_session.size);
	if (ret != KNOT_EOK) {
		goto session_free;
	}

	ngtcp2_conn_set_early_remote_transport_params(conn->conn, &session->quic_params);

session_free:
	gnutls_free(session->tls_session.data);
	free(session);
	return ret;
}

static int tls_anti_replay_db_add_func(void *dbf, time_t exp_time,
                                       const gnutls_datum_t *key,
                                       const gnutls_datum_t *data)
{
	return 0;
}

static void tls_session_ticket_key_free(gnutls_datum_t *ticket)
{
	gnutls_memset(ticket->data, 0, ticket->size);
	gnutls_free(ticket->data);
}

static int self_key(gnutls_x509_privkey_t *privkey, const char *key_file)
{
	gnutls_datum_t data = { 0 };

	int ret = gnutls_x509_privkey_init(privkey);
	if (ret != GNUTLS_E_SUCCESS) {
		return ret;
	}

	int fd = open(key_file, O_RDONLY);
	if (fd != -1) {
		struct stat stat;
		if (fstat(fd, &stat) != 0 ||
		    (data.data = gnutls_malloc(stat.st_size)) == NULL ||
		    read(fd, data.data, stat.st_size) != stat.st_size) {
			ret = GNUTLS_E_KEYFILE_ERROR;
			goto finish;
		}

		data.size = stat.st_size;
		ret = gnutls_x509_privkey_import_pkcs8(*privkey, &data, GNUTLS_X509_FMT_PEM,
		                                       NULL, GNUTLS_PKCS_PLAIN);
		if (ret != GNUTLS_E_SUCCESS) {
			goto finish;
		}
	} else {
		ret = gnutls_x509_privkey_generate(*privkey, GNUTLS_PK_EDDSA_ED25519,
		                                   GNUTLS_CURVE_TO_BITS(GNUTLS_ECC_CURVE_ED25519), 0);
		if (ret != GNUTLS_E_SUCCESS) {
			goto finish;
		}

		ret = gnutls_x509_privkey_export2_pkcs8(*privkey, GNUTLS_X509_FMT_PEM, NULL,
		                                        GNUTLS_PKCS_PLAIN, &data);
		if (ret != GNUTLS_E_SUCCESS ||
		    (fd = open(key_file, O_WRONLY | O_CREAT, 0600)) == -1 ||
		    write(fd, data.data, data.size) != data.size) {
			ret = GNUTLS_E_KEYFILE_ERROR;
			goto finish;
		}
	}

finish:
	close(fd);
	gnutls_free(data.data);
	if (ret != GNUTLS_E_SUCCESS) {
		gnutls_x509_privkey_deinit(*privkey);
		*privkey = NULL;
	}
	return ret;
}

static int self_signed_cert(gnutls_certificate_credentials_t tls_cert,
                            const char *key_file)
{
	gnutls_x509_privkey_t privkey = NULL;
	gnutls_x509_crt_t cert = NULL;

	char *hostname = sockaddr_hostname();
	if (hostname == NULL) {
		return GNUTLS_E_MEMORY_ERROR;
	}

	int ret;
	uint8_t serial[16];
	gnutls_rnd(GNUTLS_RND_NONCE, serial, sizeof(serial));
	// Clear the left-most bit to be a positive number (two's complement form).
	serial[0] &= 0x7F;

#define CHK(cmd) if ((ret = (cmd)) != GNUTLS_E_SUCCESS) { goto finish; }
#define NOW_DAYS(days) (time(NULL) + 24 * 3600 * (days))

	CHK(self_key(&privkey, key_file));

	CHK(gnutls_x509_crt_init(&cert));
	CHK(gnutls_x509_crt_set_version(cert, 3));
	CHK(gnutls_x509_crt_set_serial(cert, serial, sizeof(serial)));
	CHK(gnutls_x509_crt_set_activation_time(cert, NOW_DAYS(-1)));
	CHK(gnutls_x509_crt_set_expiration_time(cert, NOW_DAYS(10 * 365)));
	CHK(gnutls_x509_crt_set_dn_by_oid(cert, GNUTLS_OID_X520_COMMON_NAME, 0,
	                                  hostname, strlen(hostname)));
	CHK(gnutls_x509_crt_set_key(cert, privkey));
	CHK(gnutls_x509_crt_sign2(cert, cert, privkey, GNUTLS_DIG_SHA512, 0));

	ret = gnutls_certificate_set_x509_key(tls_cert, &cert, 1, privkey);

finish:
	free(hostname);
	gnutls_x509_crt_deinit(cert);
	gnutls_x509_privkey_deinit(privkey);

	return ret;
}

_public_
struct knot_quic_creds *knot_xquic_init_creds(bool server,
                                              const char *cert_file,
                                              const char *key_file,
                                              const uint8_t *peer_pin,
                                              uint8_t peer_pin_len)
{
	knot_xquic_creds_t *creds = calloc(1, sizeof(*creds));
	if (creds == NULL) {
		return NULL;
	}

	int ret = gnutls_certificate_allocate_credentials(&creds->tls_cert);
	if (ret != GNUTLS_E_SUCCESS) {
		goto fail;
	}

	if (server) {
		ret = gnutls_anti_replay_init(&creds->tls_anti_replay);
		if (ret != GNUTLS_E_SUCCESS) {
			goto fail;
		}
		gnutls_anti_replay_set_add_function(creds->tls_anti_replay, tls_anti_replay_db_add_func);
		gnutls_anti_replay_set_ptr(creds->tls_anti_replay, NULL);

		if (cert_file != NULL) {
			ret = gnutls_certificate_set_x509_key_file(creds->tls_cert,
			                                           cert_file, key_file,
			                                           GNUTLS_X509_FMT_PEM);
		} else {
			ret = self_signed_cert(creds->tls_cert, key_file);
		}
		if (ret != GNUTLS_E_SUCCESS) {
			goto fail;
		}

		ret = gnutls_session_ticket_key_generate(&creds->tls_ticket_key);
		if (ret != GNUTLS_E_SUCCESS) {
			goto fail;
		}
	} else {
		if (peer_pin_len > 0) {
			creds->peer_pin = malloc(peer_pin_len);
			if (creds->peer_pin == NULL || peer_pin == NULL) {
				goto fail;
			}
			memcpy(creds->peer_pin, peer_pin, peer_pin_len);
			creds->peer_pin_len = peer_pin_len;
		}
	}

	return creds;

fail:
	knot_xquic_free_creds(creds);
	return NULL;
}

_public_
int knot_xquic_creds_cert(struct knot_quic_creds *creds, struct gnutls_x509_crt_int **cert)
{
	if (creds == NULL || cert == NULL) {
		return KNOT_EINVAL;
	}

	gnutls_x509_crt_t *certs;
	unsigned cert_count;
	int ret = gnutls_certificate_get_x509_crt(creds->tls_cert, 0, &certs, &cert_count);
	if (ret == GNUTLS_E_SUCCESS) {
		if (cert_count == 0) {
			gnutls_x509_crt_deinit(*certs);
			return KNOT_ENOENT;
		}
		*cert = *certs;
		free(certs);
	}
	return ret;
}

_public_
void knot_xquic_free_creds(struct knot_quic_creds *creds)
{
	if (creds == NULL) {
		return;
	}

	gnutls_certificate_free_credentials(creds->tls_cert);
	gnutls_anti_replay_deinit(creds->tls_anti_replay);
	if (creds->tls_ticket_key.data != NULL) {
		tls_session_ticket_key_free(&creds->tls_ticket_key);
	}
	free(creds->peer_pin);
	free(creds);
}

static ngtcp2_conn *get_conn(ngtcp2_crypto_conn_ref *conn_ref)
{
	return ((knot_xquic_conn_t *)conn_ref->user_data)->conn;
}

static int tls_init_conn_session(knot_xquic_conn_t *conn, bool server)
{
	if (gnutls_init(&conn->tls_session, (server ? GNUTLS_SERVER : GNUTLS_CLIENT) |
	                GNUTLS_ENABLE_EARLY_DATA | GNUTLS_NO_AUTO_SEND_TICKET |
	                GNUTLS_NO_END_OF_EARLY_DATA) != GNUTLS_E_SUCCESS) {
		return TLS_CALLBACK_ERR;
	}

	gnutls_certificate_send_x509_rdn_sequence(conn->tls_session, 1);
	gnutls_certificate_server_set_request(conn->tls_session, GNUTLS_CERT_REQUEST);

	if (gnutls_priority_set_direct(conn->tls_session, QUIC_PRIORITIES,
	                               NULL) != GNUTLS_E_SUCCESS) {
		return TLS_CALLBACK_ERR;
	}

	if (server && gnutls_session_ticket_enable_server(conn->tls_session,
	                &conn->xquic_table->creds->tls_ticket_key) != GNUTLS_E_SUCCESS) {
		return TLS_CALLBACK_ERR;
	}

	int ret = ngtcp2_crypto_gnutls_configure_server_session(conn->tls_session);
	if (ret != 0) {
		return TLS_CALLBACK_ERR;
	}

	gnutls_record_set_max_early_data_size(conn->tls_session, 0xffffffffu);

	conn->conn_ref = (nc_conn_ref_placeholder_t) {
		.get_conn = get_conn,
		.user_data = conn
	};

	_Static_assert(sizeof(nc_conn_ref_placeholder_t) == sizeof(ngtcp2_crypto_conn_ref), "invalid placeholder for conn_ref");
	gnutls_session_set_ptr(conn->tls_session, &conn->conn_ref);

	if (server) {
		gnutls_anti_replay_enable(conn->tls_session, conn->xquic_table->creds->tls_anti_replay);

	}
	if (gnutls_credentials_set(conn->tls_session, GNUTLS_CRD_CERTIFICATE,
	                           conn->xquic_table->creds->tls_cert) != GNUTLS_E_SUCCESS) {
		return TLS_CALLBACK_ERR;
	}

	gnutls_alpn_set_protocols(conn->tls_session, &doq_alpn, 1, GNUTLS_ALPN_MANDATORY);

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

uint64_t xquic_conn_get_timeout(knot_xquic_conn_t *conn)
{
	// This effectively obtains the locally configured conn timeout.
	// It would be possible to obey negotitated idle timeout by employing remote params,
	// but this would differ per-connection and the whole idea of maintaining
	// to-be-timeouted connections in simple linear list requires that
	// the idle timeout is homogeneous among conns.
	// Anyway, we also violate RFC9000/10.1 (Probe Timeout) for the same reason.
	// TODO for the future: refactor conn table to use some tree/heap
	// for to-be-timeouted conns, and use ngtcp2_conn_get_expiry() and
	// ngtcp2_conn_handle_expiry() appropriately.
	const ngtcp2_transport_params *params = ngtcp2_conn_get_local_transport_params(conn->conn);

	return conn->last_ts + params->max_idle_timeout;
}

bool xquic_conn_timeout(knot_xquic_conn_t *conn, uint64_t *now)
{
	if (*now == 0) {
		*now = get_timestamp();
	}
	return *now > xquic_conn_get_timeout(conn);
}

_public_
uint32_t knot_xquic_conn_rtt(knot_xquic_conn_t *conn)
{
	ngtcp2_conn_stat stat = { 0 };
	ngtcp2_conn_get_conn_stat(conn->conn, &stat);
	return stat.smoothed_rtt / 1000; // nanosec --> usec
}

_public_
void knot_quic_conn_pin(knot_xquic_conn_t *conn, uint8_t *pin, size_t *pin_size, bool local)
{
	if (conn == NULL) {
		goto error;
	}

	const gnutls_datum_t *data;
	if (local) {
		data = gnutls_certificate_get_ours(conn->tls_session);
	} else {
		unsigned count = 0;
		data = gnutls_certificate_get_peers(conn->tls_session, &count);
		if (count == 0) {
			goto error;
		}
	}

	gnutls_x509_crt_t cert;
	int ret = gnutls_x509_crt_init(&cert);
	if (ret != GNUTLS_E_SUCCESS) {
		goto error;
	}

	ret = gnutls_x509_crt_import(cert, &data[0], GNUTLS_X509_FMT_DER);
	if (ret != GNUTLS_E_SUCCESS) {
		gnutls_x509_crt_deinit(cert);
		goto error;
	}

	ret = gnutls_x509_crt_get_key_id(cert, GNUTLS_KEYID_USE_SHA256, pin, pin_size);
	if (ret != GNUTLS_E_SUCCESS) {
		gnutls_x509_crt_deinit(cert);
		goto error;
	}

	gnutls_x509_crt_deinit(cert);
error:
	if (pin_size != NULL) {
		*pin_size = 0;
	}
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

static bool init_unique_cid(ngtcp2_cid *cid, size_t len, knot_xquic_table_t *table)
{
	do {
		if (init_random_cid(cid, len), cid->datalen == 0) {
			return false;
		}
	} while (xquic_table_lookup(cid, table) != NULL);
	return true;
}

static int get_new_connection_id(ngtcp2_conn *conn, ngtcp2_cid *cid,
                                 uint8_t *token, size_t cidlen,
                                 void *user_data)
{
	knot_xquic_conn_t *ctx = (knot_xquic_conn_t *)user_data;
	assert(ctx->conn == conn);

	if (!init_unique_cid(cid, cidlen, ctx->xquic_table)) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	knot_xquic_cid_t **addto = xquic_table_insert(ctx, cid, ctx->xquic_table);
	(void)addto;

	if (token != NULL &&
	    ngtcp2_crypto_generate_stateless_reset_token(
	            token, (uint8_t *)ctx->xquic_table->hash_secret,
	            sizeof(ctx->xquic_table->hash_secret), cid) != 0) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

static int remove_connection_id(ngtcp2_conn *conn, const ngtcp2_cid *cid,
                                void *user_data)
{
	knot_xquic_conn_t *ctx = (knot_xquic_conn_t *)user_data;
	assert(ctx->conn == conn);

	knot_xquic_cid_t **torem = xquic_table_lookup2(cid, ctx->xquic_table);
	if (torem != NULL) {
		assert((*torem)->conn == ctx);
		xquic_table_rem2(torem, ctx->xquic_table);
	}

	return 0;
}

static int handshake_completed_cb(ngtcp2_conn *conn, void *user_data)
{
	knot_xquic_conn_t *ctx = (knot_xquic_conn_t *)user_data;
	assert(ctx->conn == conn);

	assert(!ctx->handshake_done);
	ctx->handshake_done = true;

	if (!ngtcp2_conn_is_server(conn)) {
		knot_xquic_creds_t *creds = ctx->xquic_table->creds;
		if (creds->peer_pin_len == 0) {
			return 0;
		}
		uint8_t pin[KNOT_QUIC_PIN_LEN];
		size_t pin_size = sizeof(pin);
		knot_quic_conn_pin(ctx, pin, &pin_size, false);
		if (pin_size != creds->peer_pin_len ||
		    const_time_memcmp(pin, creds->peer_pin, pin_size) != 0) {
			return NGTCP2_ERR_CALLBACK_FAILURE;
		}
		return 0;
	}

	if (gnutls_session_ticket_send(ctx->tls_session, 1, 0) != GNUTLS_E_SUCCESS) {
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

	knot_xquic_conn_t *ctx = (knot_xquic_conn_t *)user_data;
	assert(ctx->conn == conn);

	int ret = knot_xquic_stream_recv_data(ctx, stream_id, data, datalen,
	                                      (flags & NGTCP2_STREAM_DATA_FLAG_FIN));

	return ret == KNOT_EOK ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
}

static int acked_stream_data_offset_cb(ngtcp2_conn *conn, int64_t stream_id,
                                    uint64_t offset, uint64_t datalen,
                                    void *user_data, void *stream_user_data)
{
	knot_xquic_conn_t *ctx = (knot_xquic_conn_t *)user_data;

	bool keep = !ngtcp2_conn_is_server(conn); // kxdpgun: await incomming reply after query sent&acked

	knot_xquic_stream_ack_data(ctx, stream_id, offset + datalen, keep);

	return 0;
}

static int stream_closed(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
			 uint64_t app_error_code, void *user_data, void *stream_user_data)
{
	knot_xquic_conn_t *ctx = (knot_xquic_conn_t *)user_data;
	assert(ctx->conn == conn);

	// NOTE possible error is stored in (flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET)

	bool keep = !ngtcp2_conn_is_server(conn); // kxdpgun: process incomming reply after recvd&closed
	if (!keep) {
		xquic_stream_free(ctx, stream_id);
	}
	return 0;
}

static int recv_stateless_rst(ngtcp2_conn *conn, const ngtcp2_pkt_stateless_reset *sr,
                              void *user_data)
{
	// NOTE server can't receive stateless resets, only client

	// ngtcp2 verified stateless reset token already
	(void)(sr);

	knot_xquic_conn_t *ctx = (knot_xquic_conn_t *)user_data;
	assert(ctx->conn == conn);

	knot_xquic_table_rem(ctx, ctx->xquic_table);

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
	knot_xquic_conn_t *ctx = (knot_xquic_conn_t *)user_data;
	if (ctx->xquic_table->log_cb != NULL) {
		char buf[256];
		va_list args;
		va_start(args, format);
		vsnprintf(buf, sizeof(buf), format, args);
		va_end(args);
		ctx->xquic_table->log_cb(buf);
	}
}

static int conn_new(ngtcp2_conn **pconn, const ngtcp2_path *path, const ngtcp2_cid *scid,
                    const ngtcp2_cid *dcid, const ngtcp2_cid *odcid, uint32_t version,
                    uint64_t now, size_t udp_pl, uint64_t idle_timeout_ns,
                    void *user_data, bool server, bool retry_sent)
{
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
	settings.log_printf = user_printf;
	settings.max_tx_udp_payload_size = udp_pl;
	settings.qlog.odcid = *odcid;
	settings.handshake_timeout = idle_timeout_ns; // NOTE setting handshake timeout to idle_timeout for simplicity
	settings.no_pmtud = true;

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
	params.max_idle_timeout = idle_timeout_ns;
	// params.stateless_reset_token_present = 1;
	// params.active_connection_id_limit = 7;
	if (odcid) {
		params.original_dcid = *odcid;
	} else {
		params.original_dcid = *scid;
	}
	if (retry_sent) {
		params.retry_scid_present = 1;
		params.retry_scid = *scid;
	}
	if (dnssec_random_buffer(params.stateless_reset_token, NGTCP2_STATELESS_RESET_TOKENLEN) != DNSSEC_EOK) {
		return KNOT_ERROR;
	}

	if (server) {
		return ngtcp2_conn_server_new(pconn, dcid, scid, path, version, &callbacks,
		                              &settings, &params, NULL, user_data);
	} else {
		return ngtcp2_conn_client_new(pconn, dcid, scid, path, version, &callbacks,
		                              &settings, &params, NULL, user_data);
	}
}

_public_
int knot_xquic_client(knot_xquic_table_t *table, struct sockaddr_in6 *dest,
                      struct sockaddr_in6 *via, const char *server_name,
                      knot_xquic_conn_t **out_conn)
{
	ngtcp2_cid scid = { 0 }, dcid = { 0 };
	uint64_t now = get_timestamp();

	init_random_cid(&scid, 0);
	init_random_cid(&dcid, 0);

	knot_xquic_conn_t *xconn = xquic_table_add(NULL, &dcid, table);
	if (xconn == NULL) {
		return ENOMEM;
	}
	xquic_conn_mark_used(xconn, table, now);

	ngtcp2_path path;
	path.remote.addr = (struct sockaddr *)dest;
	path.remote.addrlen = addr_len((const struct sockaddr_in6 *)dest);
	path.local.addr = (struct sockaddr *)via;
	path.local.addrlen = addr_len((const struct sockaddr_in6 *)via);

	int ret = conn_new(&xconn->conn, &path, &dcid, &scid, &dcid, NGTCP2_PROTO_VER_V1, now,
	                   table->udp_payload_limit, 5000000000L, xconn, false, false);
	if (ret == KNOT_EOK) {
		ret = tls_init_conn_session(xconn, false);
	}
	if (ret == KNOT_EOK && server_name != NULL) {
		ret = gnutls_server_name_set(xconn->tls_session, GNUTLS_NAME_DNS,
		                             server_name, strlen(server_name));
	}
	if (ret != KNOT_EOK) {
		knot_xquic_table_rem(xconn, table);
		return ret;
	}

	*out_conn = xconn;
	return KNOT_EOK;
}

_public_
int knot_quic_handle(knot_xquic_table_t *table, knot_quic_reply_t *reply,
                     uint64_t idle_timeout, knot_xquic_conn_t **out_conn)
{
	*out_conn = NULL;

	ngtcp2_version_cid decoded_cids = { 0 };
	ngtcp2_cid scid = { 0 }, dcid = { 0 }, odcid = { 0 };
	uint64_t now = get_timestamp();
	int ret = ngtcp2_pkt_decode_version_cid(&decoded_cids,
	                                        reply->in_payload->iov_base,
	                                        reply->in_payload->iov_len,
	                                        SERVER_DEFAULT_SCIDLEN);
	if (ret == NGTCP2_ERR_VERSION_NEGOTIATION) {
		ret = -XQUIC_SEND_VERSION_NEGOTIATION;
		goto finish;
	} else if (ret != NGTCP2_NO_ERROR) {
		goto finish;
	}
	ngtcp2_cid_init(&dcid, decoded_cids.dcid, decoded_cids.dcidlen);
	ngtcp2_cid_init(&scid, decoded_cids.scid, decoded_cids.scidlen);

	knot_xquic_conn_t *xconn = xquic_table_lookup(&dcid, table);

	if (decoded_cids.version == 0 /* short header */ && xconn == NULL) {
		ret = KNOT_EOK; // NOOP
		goto finish;
	}

	ngtcp2_path path;
	path.remote.addr = (struct sockaddr *)reply->ip_rem;
	path.remote.addrlen = addr_len((struct sockaddr_in6 *)reply->ip_rem);
	path.local.addr = (struct sockaddr *)reply->ip_loc;
	path.local.addrlen = addr_len((struct sockaddr_in6 *)reply->ip_loc);

	if (xconn == NULL) {
		// new conn

		ngtcp2_pkt_hd header = { 0 };
		ret = ngtcp2_accept(&header, reply->in_payload->iov_base,
		                    reply->in_payload->iov_len);
		if (ret == NGTCP2_ERR_RETRY) {
			ret = -XQUIC_SEND_RETRY;
			goto finish;
		} else if (ret != NGTCP2_NO_ERROR) { // discard packet
			ret = KNOT_EOK;
			goto finish;
		}

		assert(header.type == NGTCP2_PKT_INITIAL);
		if (header.tokenlen == 0 && xquic_require_retry(table)) {
			ret = -XQUIC_SEND_RETRY;
			goto finish;
		}

		if (header.tokenlen > 0) {
			ret = ngtcp2_crypto_verify_retry_token(
				&odcid, header.token, header.tokenlen,
				(const uint8_t *)table->hash_secret,
				sizeof(table->hash_secret), header.version,
				(const struct sockaddr *)reply->ip_rem,
				addr_len((struct sockaddr_in6 *)reply->ip_rem),
				&dcid, idle_timeout, now // NOTE setting retry token validity to idle_timeout for simplicity
			);
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

		xconn = xquic_table_add(NULL, &dcid, table);
		if (xconn == NULL) {
			ret = KNOT_ENOMEM;
			goto finish;
		}
		xquic_conn_mark_used(xconn, table, now);

		ret = conn_new(&xconn->conn, &path, &dcid, &scid, &odcid, decoded_cids.version,
		               now, table->udp_payload_limit, idle_timeout, xconn, true,
		               header.tokenlen > 0);
		if (ret >= 0) {
			ret = tls_init_conn_session(xconn, true);
		}
		if (ret < 0) {
			knot_xquic_table_rem(xconn, table);
			goto finish;
		}
	}

	ngtcp2_pkt_info pi = { .ecn = NGTCP2_ECN_NOT_ECT, };

	ret = ngtcp2_conn_read_pkt(xconn->conn, &path, &pi, reply->in_payload->iov_base,
	                           reply->in_payload->iov_len, now);

	*out_conn = xconn;
	if (ret == NGTCP2_ERR_DRAINING // received CONNECTION_CLOSE from the counterpart
	    || ngtcp2_err_is_fatal(ret)) { // connection doomed
		knot_xquic_table_rem(xconn, table);
		ret = KNOT_ECONN;
		goto finish;
	} else if (ret != NGTCP2_NO_ERROR) { // non-fatal error, discard packet
		ret = KNOT_EOK;
		goto finish;
	}

	xquic_conn_mark_used(xconn, table, now);

	ret = KNOT_EOK;
finish:
	reply->handle_ret = ret;
	return ret;
}

static bool stream_exists(knot_xquic_conn_t *xconn, int64_t stream_id)
{
	// TRICK, we never use stream_user_data
	return (ngtcp2_conn_set_stream_user_data(xconn->conn, stream_id, NULL) == NGTCP2_NO_ERROR);
}

static int send_stream(knot_xquic_table_t *quic_table, knot_quic_reply_t *rpl,
                       knot_xquic_conn_t *relay, int64_t stream_id,
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

	ret = ngtcp2_conn_writev_stream(relay->conn, NULL, NULL, rpl->out_payload->iov_base,
	                                rpl->out_payload->iov_len, sent, fl, stream_id,
	                                &vec, (stream_id >= 0 ? 1 : 0), get_timestamp());
	if (ret <= 0) {
		rpl->free_reply(rpl);
		return ret;
	}
	if (*sent < 0) {
		*sent = 0;
	}

	rpl->out_payload->iov_len = ret;
	ret = rpl->send_reply(rpl);
	if (ret == KNOT_EOK) {
		return 1;
	}
	return ret;
}

static int send_special(knot_xquic_table_t *quic_table, knot_quic_reply_t *rpl)
{
	int ret = rpl->alloc_reply(rpl);
	if (ret != KNOT_EOK) {
		return ret;
	}

	uint64_t now = get_timestamp();
	ngtcp2_version_cid decoded_cids = { 0 };
	ngtcp2_cid scid = { 0 }, dcid = { 0 };

	int dvc_ret = ngtcp2_pkt_decode_version_cid(&decoded_cids,
	                                            rpl->in_payload->iov_base,
	                                            rpl->in_payload->iov_len,
	                                            SERVER_DEFAULT_SCIDLEN);

	uint8_t rnd = 0;
	dnssec_random_buffer(&rnd, sizeof(rnd));
	uint32_t supported_quic[1] = { NGTCP2_PROTO_VER_V1 };
	ngtcp2_cid new_dcid;
	uint8_t retry_token[NGTCP2_CRYPTO_MAX_RETRY_TOKENLEN];
	uint8_t stateless_reset_token[NGTCP2_STATELESS_RESET_TOKENLEN];
	uint8_t sreset_rand[NGTCP2_MIN_STATELESS_RESET_RANDLEN];
	dnssec_random_buffer(sreset_rand, sizeof(sreset_rand));

	switch (rpl->handle_ret) {
	case -XQUIC_SEND_VERSION_NEGOTIATION:
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
	case -XQUIC_SEND_RETRY:
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
	case -XQUIC_SEND_STATELESS_RESET:
		ret = ngtcp2_pkt_write_stateless_reset(
			rpl->out_payload->iov_base, rpl->out_payload->iov_len,
			stateless_reset_token, sreset_rand, sizeof(sreset_rand)
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
		ret = rpl->send_reply(rpl);
	}
	return ret;
}

_public_
int knot_quic_send(knot_xquic_table_t *quic_table, knot_xquic_conn_t *conn,
                   knot_quic_reply_t *reply, unsigned max_msgs, bool ignore_lastbyte)
{
	if (reply->handle_ret < 0) {
		return reply->handle_ret;
	} else if (reply->handle_ret > 0) {
		return send_special(quic_table, reply);
	} else if (conn == NULL) {
		return KNOT_EINVAL;
	} else if (conn->conn == NULL) {
		return KNOT_EOK;
	}

	unsigned sent_msgs = 0, stream_msgs = 0;
	int ret = 1;
	for (int64_t si = 0; si < conn->streams_count && sent_msgs < max_msgs; /* NO INCREMENT */) {
		int64_t stream_id = 4 * (conn->streams_first + si);

		ngtcp2_ssize sent = 0;
		size_t uf = conn->streams[si].unsent_offset;
		knot_xquic_obuf_t *uo = conn->streams[si].unsent_obuf;
		if (uo == NULL) {
			si++;
			continue;
		}

		bool fin = (((node_t *)uo->node.next)->next == NULL) && !ignore_lastbyte;
		ret = send_stream(quic_table, reply, conn, stream_id,
		                  uo->buf + uf, uo->len - uf - (ignore_lastbyte ? 1 : 0),
		                  fin, &sent);
		if (ret < 0) {
			return ret;
		}

		sent_msgs++;
		stream_msgs++;
		if (sent > 0 && ignore_lastbyte) {
			sent++;
		}
		if (sent > 0) {
			knot_xquic_stream_mark_sent(conn, stream_id, sent);
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
