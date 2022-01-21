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
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "contrib/macros.h"
#include "contrib/sockaddr.h"
#include "libdnssec/error.h"
#include "libdnssec/random.h"
#include "libknot/attribute.h"
#include "libknot/error.h"
#include "libknot/xdp/quic.h"

#define SERVER_DEFAULT_SCIDLEN 18

static uint64_t get_timestamp(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	uint64_t res = (uint64_t)t.tv_sec * 1000000;
	res += (uint64_t)t.tv_nsec / 1000;
	return res; // overflow does not matter since we are working with differences
}

static void knot_quic_rand_cb(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx)
{
	(void)rand_ctx;
	dnssec_random_buffer(dest, destlen);
}

static bool cid_eq(const ngtcp2_cid *a, const ngtcp2_cid *b)
{
	return a->datalen == b->datalen &&
	       memcmp(a->data, b->data, a->datalen) == 0;
}

static uint64_t cid2hash(const ngtcp2_cid *cid)
{
	uint64_t hash = 0;
	memcpy(&hash, cid->data, MIN(sizeof(hash), cid->datalen));
	return hash;
}

static knot_xquic_conn_t **xquic_table_add(ngtcp2_conn *conn, const ngtcp2_cid *cid, knot_xquic_table_t *table)
{
	knot_xquic_conn_t *xconn = calloc(1, sizeof(*xconn));
	if (xconn == NULL) {
		return NULL;
	}

	xconn->conn = conn;
	xconn->cid.datalen = cid->datalen;
	memcpy(xconn->cid.data, cid->data, cid->datalen);

	uint64_t hash = cid2hash(cid);

	knot_xquic_conn_t **addto = table->conns + (hash % table->size);
	xconn->next = *addto;
	*addto = xconn;
	table->usage++;

	return addto;
}

static knot_xquic_conn_t **xquic_table_lookup(const ngtcp2_cid *cid, knot_xquic_table_t *table)
{
	uint64_t hash = cid2hash(cid);

	knot_xquic_conn_t **res = table->conns + (hash % table->size);
	while (*res != NULL) {
		if (cid_eq(&(*res)->cid, cid)) {
			break;
		}
		res = &(*res)->next;
	}
	return res;
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

	if (init_random_cid(cid, cidlen), cid->datalen == 0) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	if (ngtcp2_crypto_generate_stateless_reset_token(token, (uint8_t *)ctx->xquic_table->hash_secret, sizeof(ctx->xquic_table->hash_secret), cid) != 0) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	if (xquic_table_add(conn, cid, ctx->xquic_table) != KNOT_EOK) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

static int knot_handshake_completed_cb(ngtcp2_conn *conn, void *user_data) {
	knot_xquic_conn_t *ctx = (knot_xquic_conn_t *)user_data;
	// printf("Negotiated cipher suite is %s\n", gnutls_cipher_get_name(gnutls_cipher_get(ctx->tls_session)));
	// gnutls_datum_t alpn;
	// if (gnutls_alpn_get_selected_protocol(ctx->tls_session, &alpn) != 0) {
	// 	return NGTCP2_ERR_CALLBACK_FAILURE;
	// }
	// char alpn_str[alpn.size + 1];
	// alpn_str[alpn.size] = '\0';
	// memcpy(alpn_str, alpn.data, alpn.size);
	// printf("Negotiated ALPN is %s\n", alpn_str);

/*	if (gnutls_session_ticket_send(ctx->tls_session, 1, 0) != GNUTLS_E_SUCCESS) {
		printf("Unable to send session ticket\n");
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
	} */

	return 0;
}

static int recv_stream_data(ngtcp2_conn *conn, uint32_t flags,
                            int64_t stream_id, uint64_t offset,
                            const uint8_t *data, size_t datalen,
                            void *user_data, void *stream_user_data)
{	
	knot_xquic_conn_t *ctx = (knot_xquic_conn_t *)user_data;

	if (!(flags & NGTCP2_STREAM_DATA_FLAG_FIN)) {
		ctx->rx_query.iov_len = 0;
		return 0; // TODO handle fragmented DNS queries?
	}
	if (datalen < sizeof(uint16_t) || *(uint16_t *)data != datalen - sizeof(uint16_t)) {
		ctx->rx_query.iov_len = 0;
		return 0; // TODO handle weirdly fragmented queries?
	}

	ctx->stream_id = stream_id;
	ctx->rx_query.iov_base = (void *)data + sizeof(uint16_t);
	ctx->rx_query.iov_len = datalen - sizeof(uint16_t);
	return 0;
}

static int acked_stream_data_offset_cb(ngtcp2_conn *conn, int64_t stream_id,
                                    uint64_t offset, uint64_t datalen,
                                    void *user_data, void *stream_user_data)
{
	knot_xquic_conn_t *ctx = (knot_xquic_conn_t *)user_data;
	(void)ctx;
	return 0;
}

static int stream_opened(ngtcp2_conn *conn, int64_t stream_id, void *user_data)
{
	printf("stream %ld opened...\n", stream_id);
	return 0;
}

static void user_printf(void *user_data, const char *format, ...)
{
	(void)user_data;
	va_list args;
	va_start(args, format);
	vprintf(format, args);
	va_end(args);
}

static void user_qlog(void *user_data, uint32_t flags, const void *data, size_t datalen)
{
	(void)user_data;
	FILE *qlog = fopen("/tmp/qlog", "a");
	if (qlog != NULL) {
		fprintf(qlog, "\n%u: ", flags);
		for (size_t i = 0; i < datalen; i++) {
			fputc(*(uint8_t *)(data + i), qlog);
		}
		fclose(qlog);
	}
}

static int conn_server_new(ngtcp2_conn **pconn, const ngtcp2_path *path, const ngtcp2_cid *scid,
                           const ngtcp2_cid *dcid, const ngtcp2_cid *ocid, uint32_t version,
                           uint64_t now, void *user_data)
{
	// I. CALLBACKS
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
	settings.qlog.odcid = *ocid;
	settings.qlog.write = user_qlog;

	// III. PARAMS
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

	return ngtcp2_conn_server_new(pconn, dcid, scid, path, version, &callbacks, &settings, &params, NULL, user_data);
}

static int handle_packet(knot_xdp_msg_t *msg, knot_xquic_table_t *table, knot_xquic_conn_t **out_conn)
{
	uint32_t pversion = 0;
	ngtcp2_cid scid = { 0 }, dcid = { 0 };
	uint64_t now = get_timestamp();
	int ret = ngtcp2_pkt_decode_version_cid(&pversion, (const uint8_t **)&dcid.data, &dcid.datalen,
	                                        (const uint8_t **)&scid.data, &scid.datalen,
	                                        msg->payload.iov_base, msg->payload.iov_len, SERVER_DEFAULT_SCIDLEN);
	if (ret == NGTCP2_ERR_VERSION_NEGOTIATION) {
		// TODO
		assert(0);
		return KNOT_EOK;
	} else if (ret < 0) {
		return ret;
	}

	knot_xquic_conn_t *xconn = *xquic_table_lookup(&dcid, table);

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

		xconn = *xquic_table_add(NULL, &dcid, table);
		if (xconn == NULL) {
			return ENOMEM;
		}
		xconn->xquic_table = table; // FIXME ?

		ret = conn_server_new(&xconn->conn, &path, &scid, &dcid, NULL /* FIXME */, pversion, now, xconn);
		if (ret < 0) {
			// TODO delete xconn and fail
			assert(0);
			return KNOT_EOK;
		}


	}

	ngtcp2_pkt_info pi = { .ecn = NGTCP2_ECN_NOT_ECT, }; // TODO: explicit congestion notification

	ret = ngtcp2_conn_read_pkt(xconn->conn, &path, &pi, msg->payload.iov_base, msg->payload.iov_len, now);

	if (ret == KNOT_EOK) {
		*out_conn = xconn;
		memcpy(xconn->last_eth_rem, msg->eth_from, sizeof(msg->eth_from));
		memcpy(xconn->last_eth_loc, msg->eth_to, sizeof(msg->eth_to));
	}

	return ret;
}

_public_
int knot_xquic_recv(knot_xquic_conn_t **relays, knot_xdp_msg_t *msgs,
                    uint32_t count, knot_xquic_table_t *quic_table)
{
	memset(relays, 0, count * sizeof(*relays));

	for (uint32_t i = 0; i < count; i++) {
		knot_xdp_msg_t *msg = &msgs[i];
		const uint8_t *payl = msg->payload.iov_base;
		if ((msg->flags & KNOT_XDP_MSG_TCP) ||
		    msg->payload.iov_len < 4 ||
		    (payl[2] == 0 && payl[3] != 0)) { // not QUIC
			continue;
		}

		int ret = handle_packet(msg, quic_table, &relays[i]);
	}

	return KNOT_EOK;
}

_public_
int knot_xquic_send(knot_xdp_socket_t *sock, knot_xquic_conn_t *relay)
{
	if (relay == NULL) {
		return KNOT_EOK;
	}

	bool ipv6 = false; // FIXME

	knot_xdp_msg_t msg = { 0 };
	int ret = knot_xdp_send_alloc(sock, ipv6 ? KNOT_XDP_MSG_IPV6 : 0, &msg);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ngtcp2_path path = { 0 };

	ret = ngtcp2_conn_writev_stream(relay->conn, &path, NULL, msg.payload.iov_base, msg.payload.iov_len,
	                                NULL, NGTCP2_WRITE_STREAM_FLAG_FIN, relay->stream_id,
	                                relay->tx_query.iov_base, relay->tx_query.iov_len, get_timestamp());
	if (ret != KNOT_EOK) {
		return ret;
	}

	memcpy(&msg.ip_from, path.local.addr, sizeof(msg.ip_from));
	memcpy(&msg.ip_to, path.remote.addr, sizeof(msg.ip_to));

	memcpy(msg.eth_from, relay->last_eth_loc, sizeof(msg.eth_from));
	memcpy(msg.eth_to, relay->last_eth_rem, sizeof(msg.eth_to));

	uint32_t sent = 0;
	return knot_xdp_send(sock, &msg, 1, &sent);
}
