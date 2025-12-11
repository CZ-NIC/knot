/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include <stdbool.h>

/*! \brief QUIC parameters. */
typedef struct {
	/*! Use QUIC indicator. */
	bool enable;
} quic_params_t;

int quic_params_copy(quic_params_t *dst, const quic_params_t *src);

void quic_params_clean(quic_params_t *params);

#ifdef ENABLE_QUIC

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>

#include "libknot/probe/data.h"
#include "utils/common/tls.h"

typedef enum {
	CLOSED,    // Initialized
	CONNECTED, // RTT-0
	VERIFIED,  // RTT-1
} quic_state_t;

/* promise declarations */
typedef struct kdig_callbacks kdig_callbacks_t;
typedef struct srv_info srv_info_t;
typedef enum net_flags net_flags_t;
typedef struct net net_t;

typedef enum {
	/*! No error.  This is used when the connection or stream needs to be
	    closed, but there is no error to signal. */
	DOQ_NO_ERROR = 0x0,
	/*! The DoQ implementation encountered an internal error and is
	    incapable of pursuing the transaction or the connection. */
	DOQ_INTERNAL_ERROR = 0x1,
	/*! The DoQ implementation encountered a protocol error and is forcibly
	    aborting the connection. */
	DOQ_PROTOCOL_ERROR = 0x2,
	/*! A DoQ client uses this to signal that it wants to cancel an
	    outstanding transaction. */
	DOQ_REQUEST_CANCELLED = 0x3,
	/*! A DoQ implementation uses this to signal when closing a connection
	    due to excessive load. */
	DOQ_EXCESSIVE_LOAD = 0x4,
	/*!  A DoQ implementation uses this in the absence of a more specific
	     error code. */
	DOQ_UNSPECIFIED_ERROR = 0x5,
	/*! Alternative error code used for tests. */
	DOQ_ERROR_RESERVED = 0xd098ea5e
} quic_doq_error_t;

typedef struct test_env {
	uint64_t scenario;
	int16_t counter;
	char *buf;
	size_t bufsize;
	size_t bufend;
} test_env_t;

typedef struct quic_ctx {
	ngtcp2_crypto_conn_ref conn_ref;
	// Parameters
	quic_params_t params;

	// Context
	ngtcp2_settings settings;
	struct {
		int64_t id;
		uint64_t out_ack;
		struct iovec in_buffer;
		struct knot_tcp_inbufs_upd_res *in_parsed;
		size_t in_parsed_it;
		size_t in_parsed_total;
	} stream;
	ngtcp2_ccerr last_err;
	uint8_t secret[32];
	tls_ctx_t *tls;
	ngtcp2_conn *conn;
	ngtcp2_pkt_info pi;
	quic_state_t state;
	kdig_callbacks_t *cbs;
	test_env_t *env;
} quic_ctx_t;

extern const gnutls_datum_t doq_alpn;

int recv_stream_data_cb(ngtcp2_conn *conn, uint32_t flags,
	int64_t stream_id, uint64_t offset, const uint8_t *data,
	size_t datalen, void *user_data, void *stream_user_data);
int recv_stream_data_ignore_all_but_0(ngtcp2_conn *conn, uint32_t flags,
	int64_t stream_id, uint64_t offset, const uint8_t *data,
	size_t datalen, void *user_data, void *stream_user_data);

int quic_send_data(quic_ctx_t *ctx, int sockfd, int family,
	ngtcp2_vec *datav, size_t datavlen);
int quic_send_data_test(quic_ctx_t *ctx, int sockfd, int family,
	ngtcp2_vec *datav, size_t datavlen);
int quic_send_data_defer_second_packet(quic_ctx_t *ctx, int sockfd, int family,
	ngtcp2_vec *datav, size_t datavlen);
int quic_send_data_split(quic_ctx_t *ctx, int sockfd, int family,
	ngtcp2_vec *datav, size_t datavlen);

int quic_recv(quic_ctx_t *ctx, int sockfd);
int quic_recv_with_ack(quic_ctx_t *ctx, int sockfd);

uint64_t quic_timestamp(void);
uint64_t quic_timestamp_mock(void);

int quic_generate_secret(uint8_t *buf, size_t buflen);

int verify_certificate(gnutls_session_t session);

ngtcp2_conn *get_conn(ngtcp2_crypto_conn_ref *conn_ref);

uint32_t quic_get_ecn(struct msghdr *msg, const int family);

int quic_ctx_init(quic_ctx_t *ctx, tls_ctx_t *tls_ctx, const quic_params_t *params);

int get_expiry(quic_ctx_t *ctx);

int quic_ctx_connect(quic_ctx_t *ctx, int sockfd, struct addrinfo *dst_addr);

int offset_span(ngtcp2_vec **vec, size_t *veclen, size_t sub);

int quic_send_dns_query(quic_ctx_t *ctx, int sockfd, struct addrinfo *srv,
        const uint8_t *buf, const size_t buf_len);
int quic_send_dns_query_split(quic_ctx_t *ctx, int sockfd, struct addrinfo *srv,
	const uint8_t *buf, const size_t buf_len);
int quic_send_dns_query_sync(quic_ctx_t *ctx, int sockfd,
		struct addrinfo *srv, const uint8_t *buf, const size_t buf_len);

int quic_recv_dns_response(quic_ctx_t *ctx, uint8_t *buf, const size_t buf_len,
        struct addrinfo *srv);

void quic_ctx_close(quic_ctx_t *ctx);

void quic_ctx_deinit(quic_ctx_t *ctx);

void print_quic(const quic_ctx_t *ctx);

typedef int (*qtest_getaddr)(const srv_info_t *server, const int iptype,
		const int socktype, struct addrinfo  **info);

typedef void (*qtest_get_addr_str)(const struct sockaddr_storage *ss,
		  const knot_probe_proto_t protocol, char **dst);

typedef int (*qtest_tls_ctx_init)(tls_ctx_t *ctx, const tls_params_t *params,
	unsigned int flags, int wait);

// typedef int (*qtest_net_init_crypto)(net_t *net,
// 		const tls_params_t *tls_params,
// 		const https_params_t *https_params,
// 		const quic_params_t *quic_params);

typedef int (*qtest_quic_ctx_init)(quic_ctx_t *ctx, tls_ctx_t *tls_ctx, const quic_params_t *params);


typedef char *(*qtest_net_get_remote)(const net_t *net);

typedef int (*qtest_tls_ctx_setup_remote_endpoint)(tls_ctx_t *ctx, const gnutls_datum_t *alpn,
        size_t alpn_size, const char *priority, const char *remote);

typedef int (*qtest_quic_ctx_connect)(quic_ctx_t *ctx, int sockfd, struct addrinfo *dst_addr);

typedef int (*qtest_net_set_local_info)(net_t *net);

typedef int (*qtest_quic_send_dns_query)(quic_ctx_t *ctx, int sockfd, struct addrinfo *srv,
	const uint8_t *buf, const size_t buf_len);

typedef int (*qtest_offset_span)(ngtcp2_vec **vec, size_t *veclen, size_t sub);

typedef int (*qtest_quic_send_data)(quic_ctx_t *ctx, int sockfd, int family,
	ngtcp2_vec *datav, size_t datavlen);

typedef int (*qtest_net_ecn_set)(int sock, int family, uint8_t ecn);

/* maybe even sendmsg? */

typedef int (*qtest_quic_recv)(quic_ctx_t *ctx, int sockfd);

typedef uint64_t (*qtest_quic_timestamp)(void);

typedef int (*qtest_quic_generate_secret)(uint8_t *buf, size_t buflen);

typedef int (*qtest_verify_certificate)(gnutls_session_t session);

typedef ngtcp2_conn *(*qtest_get_conn)(ngtcp2_crypto_conn_ref *conn_ref);

typedef int (*qtest_get_expiry)(quic_ctx_t *ctx);

typedef int (*qtest_net_receive)(const net_t *net, uint8_t *buf, const size_t buf_len);

typedef int (*qtest_quic_recv_dns_response)(quic_ctx_t *ctx, uint8_t *buf, const size_t buf_len,
	struct addrinfo *srv);

typedef int (*ngtcp2_recv_stream_data_cb)( ngtcp2_conn * conn, uint32_t flags,
		int64_t stream_id, uint64_t offset, const uint8_t * data,
		size_t datalen, void * user_data, void * stream_user_data);

typedef struct kdig_callbacks {
	qtest_tls_ctx_setup_remote_endpoint tls_ctx_setup_remote_endpoint;
	// ngtcp2_recv_stream_data_cb ngtcp2_recv_stream_data_cb;
	qtest_quic_recv_dns_response quic_recv_dns_response;
	qtest_quic_generate_secret quic_generate_secret;
	qtest_quic_send_dns_query quic_send_dns_query;
	qtest_verify_certificate verify_certificate;
	qtest_net_set_local_info net_set_local_info;
	qtest_quic_ctx_connect quic_ctx_connect;
	qtest_net_get_remote net_get_remote;
	qtest_quic_send_data quic_send_data;
	qtest_quic_timestamp quic_timestamp;
	qtest_quic_ctx_init quic_ctx_init;
	qtest_get_addr_str get_addr_str;
	qtest_tls_ctx_init tls_ctx_init;
	qtest_offset_span offset_span;
	qtest_net_ecn_set net_ecn_set;
	qtest_net_receive net_receive;
	qtest_get_expiry get_expiry;
	qtest_quic_recv quic_recv;
	qtest_get_conn get_conn;
	qtest_getaddr getaddr;
} kdig_callbacks_t;

#endif //ENABLE_QUIC

