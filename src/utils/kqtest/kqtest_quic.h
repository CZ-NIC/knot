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

/* testcase env extra flags */
typedef enum {
	TEST_SEND_ONE_PAYLOAD = (1 << 2),
} quic_extra_flags;

typedef struct test_env {
	uint64_t scenario;
	int16_t counter;
	char *buf;
	size_t bufsize;
	size_t bufend;
	size_t stream_count;
	int extra;
	/* Can be used to store any additional test info both in and out */
	int result_buffer[1<<10];
} test_env_t;

struct stream {
	int64_t id;
	uint64_t out_ack;
	struct iovec in_buffer;
	struct knot_tcp_inbufs_upd_res *in_parsed;
	size_t in_parsed_it;
	size_t in_parsed_total;
};

typedef struct quic_ctx {
	ngtcp2_crypto_conn_ref conn_ref;
	// Parameters
	quic_params_t params;

	// Context
	ngtcp2_settings settings;
	// Some tests might need more concurrent streams
	struct stream *streams;
	size_t stream_count;
	size_t active;
	ngtcp2_ccerr last_err;
	uint8_t secret[32];
	tls_ctx_t *tls;
	ngtcp2_conn *conn;
	ngtcp2_pkt_info pi;
	quic_state_t state;
	kdig_callbacks_t *cbs;
	test_env_t *env;
	ngtcp2_cid last_scid;
	uint8_t last_scid_token[NGTCP2_STATELESS_RESET_TOKENLEN];
	bool last_scid_valid;
	int verbosity;
} quic_ctx_t;

extern const gnutls_datum_t doq_alpn;

#define RECEIVED_CLOSE_MAGIC 0xa91d3b8

int recv_stream_data_cb(ngtcp2_conn *conn, uint32_t flags,
	int64_t stream_id, uint64_t offset, const uint8_t *data,
	size_t datalen, void *user_data, void *stream_user_data);

int stream_reset_cb(ngtcp2_conn *conn, int64_t stream_id,
	uint64_t final_size, uint64_t app_error_code, void *user_data,
	void *stream_user_data);
int stream_reset_cb_malicious_survival(ngtcp2_conn *conn, int64_t stream_id,
	uint64_t final_size, uint64_t app_error_code, void *user_data,
	void *stream_user_data);

int quic_send_data(quic_ctx_t *ctx, int sockfd, int family,
	ngtcp2_vec *datav, size_t datavlen);
int quic_send_data_test(quic_ctx_t *ctx, int sockfd, int family,
	ngtcp2_vec *datav, size_t datavlen);
int quic_send_data_split(quic_ctx_t *ctx, int sockfd, int family,
	ngtcp2_vec *datav, size_t datavlen);
int quic_send_data_terminate(quic_ctx_t *ctx, int sockfd, int family,
	ngtcp2_vec *datav, size_t datavlen);
int quic_send_data_split_reset_stream(quic_ctx_t *ctx, int sockfd, int family,
	ngtcp2_vec *datav, size_t datavlen);

int quic_recv(quic_ctx_t *ctx, int sockfd);
int quic_recv_with_ack(quic_ctx_t *ctx, int sockfd);
int quic_recv_close_doq_error(quic_ctx_t *ctx, int sockfd);

uint64_t quic_timestamp(void);

int quic_generate_secret(uint8_t *buf, size_t buflen);

int verify_certificate(gnutls_session_t session);

ngtcp2_conn *get_conn(ngtcp2_crypto_conn_ref *conn_ref);

uint32_t quic_get_ecn(struct msghdr *msg, const int family);

int quic_ctx_init(quic_ctx_t *ctx, tls_ctx_t *tls_ctx,
		const quic_params_t *params);

int get_expiry(quic_ctx_t *ctx);

int quic_ctx_connect(quic_ctx_t *ctx, int sockfd, struct addrinfo *dst_addr);

int offset_span(ngtcp2_vec **vec, size_t *veclen, size_t sub);

int quic_send_dns_query(quic_ctx_t *ctx, int sockfd,
		struct addrinfo *srv, const uint8_t *buf, const size_t buf_len);
int quic_send_dns_query_split(quic_ctx_t *ctx, int sockfd,
		struct addrinfo *srv, const uint8_t *buf, const size_t buf_len);
int quic_send_dns_query_sync(quic_ctx_t *ctx, int sockfd,
		struct addrinfo *srv, const uint8_t *buf, const size_t buf_len);
int quic_send_dns_query_terminate(quic_ctx_t *ctx, int sockfd,
		struct addrinfo *srv, const uint8_t *buf, const size_t buf_len);
int quic_send_dns_query_stop_sending(quic_ctx_t *ctx, int sockfd,
		struct addrinfo *srv, const uint8_t *buf, const size_t buf_len);
int quic_send_dns_query_wrong_size_prefix(quic_ctx_t *ctx, int sockfd,
		struct addrinfo *srv, const uint8_t *buf, const size_t buf_len);
int quic_send_dns_query_open_uni_stream(quic_ctx_t *ctx, int sockfd,
		struct addrinfo *srv, const uint8_t *buf, const size_t buf_len);
int quic_send_doubled(quic_ctx_t *ctx, int sockfd,
		struct addrinfo *srv, const uint8_t *buf, const size_t buf_len);

int quic_recv_dns_response(quic_ctx_t *ctx, uint8_t *buf, const size_t buf_len,
		struct addrinfo *srv);

void quic_ctx_close(quic_ctx_t *ctx);

void quic_ctx_deinit(quic_ctx_t *ctx);

void print_quic(const quic_ctx_t *ctx);

typedef int (*kqtest_getaddr)(const srv_info_t *server, const int iptype,
		const int socktype, struct addrinfo  **info);

typedef void (*kqtest_get_addr_str)(const struct sockaddr_storage *ss,
		  const knot_probe_proto_t protocol, char **dst);

/* Forward declaration */
struct query;
typedef struct query query_t;

typedef knot_pkt_t *(*kqtest_create_query_packet)(const query_t *query);

typedef int (*kqtest_tls_ctx_init)(tls_ctx_t *ctx, const tls_params_t *params,
	unsigned int flags, int wait);

typedef int (*kqtest_quic_ctx_init)(quic_ctx_t *ctx, tls_ctx_t *tls_ctx,
		const quic_params_t *params);

typedef char *(*kqtest_net_get_remote)(const net_t *net);

typedef int (*kqtest_tls_ctx_setup_remote_endpoint)(tls_ctx_t *ctx,
		const gnutls_datum_t *alpn, size_t alpn_size,
		const char *priority, const char *remote);

typedef int (*kqtest_quic_ctx_connect)(quic_ctx_t *ctx, int sockfd,
		struct addrinfo *dst_addr);

typedef int (*kqtest_stream_reset_cb)(ngtcp2_conn *conn, int64_t stream_id,
	uint64_t final_size, uint64_t app_error_code, void *user_data,
	void *stream_user_data);

typedef int (*kqtest_net_set_local_info)(net_t *net);

typedef int (*kqtest_quic_send_dns_query)(quic_ctx_t *ctx, int sockfd,
		struct addrinfo *srv, const uint8_t *buf, const size_t buf_len);

typedef int (*kqtest_offset_span)(ngtcp2_vec **vec, size_t *veclen, size_t sub);

typedef int (*kqtest_quic_send_data)(quic_ctx_t *ctx, int sockfd, int family,
	ngtcp2_vec *datav, size_t datavlen);

typedef int (*kqtest_net_ecn_set)(int sock, int family, uint8_t ecn);

typedef int (*kqtest_quic_recv)(quic_ctx_t *ctx, int sockfd);

typedef uint64_t (*kqtest_quic_timestamp)(void);

typedef int (*kqtest_quic_generate_secret)(uint8_t *buf, size_t buflen);

typedef int (*kqtest_verify_certificate)(gnutls_session_t session);

typedef ngtcp2_conn *(*kqtest_get_conn)(ngtcp2_crypto_conn_ref *conn_ref);

typedef int (*kqtest_get_expiry)(quic_ctx_t *ctx);

typedef int (*kqtest_net_receive)(const net_t *net, uint8_t *buf,
		const size_t buf_len);

typedef int (*kqtest_quic_recv_dns_response)(quic_ctx_t *ctx, uint8_t *buf,
		const size_t buf_len, struct addrinfo *srv);

typedef int (*kqtest_quic_recv_dns_response)(quic_ctx_t *ctx, uint8_t *buf,
		const size_t buf_len, struct addrinfo *srv);

typedef int (*ngtcp2_recv_stream_data_cb)( ngtcp2_conn * conn, uint32_t flags,
		int64_t stream_id, uint64_t offset, const uint8_t * data,
		size_t datalen, void * user_data, void * stream_user_data);

typedef struct kdig_callbacks {
	kqtest_tls_ctx_setup_remote_endpoint tls_ctx_setup_remote_endpoint;
	kqtest_quic_recv_dns_response quic_recv_dns_response;
	kqtest_quic_generate_secret quic_generate_secret;
	kqtest_create_query_packet create_query_packet;
	kqtest_quic_send_dns_query quic_send_dns_query;
	kqtest_verify_certificate verify_certificate;
	kqtest_net_set_local_info net_set_local_info;
	kqtest_stream_reset_cb quic_stream_reset_cb;
	kqtest_quic_ctx_connect quic_ctx_connect;
	kqtest_net_get_remote net_get_remote;
	kqtest_quic_send_data quic_send_data;
	kqtest_quic_timestamp quic_timestamp;
	kqtest_quic_ctx_init quic_ctx_init;
	kqtest_get_addr_str get_addr_str;
	kqtest_tls_ctx_init tls_ctx_init;
	kqtest_offset_span offset_span;
	kqtest_net_ecn_set net_ecn_set;
	kqtest_net_receive net_receive;
	kqtest_get_expiry get_expiry;
	kqtest_quic_recv quic_recv;
	kqtest_get_conn get_conn;
	kqtest_getaddr getaddr;
} kdig_callbacks_t;

#endif //ENABLE_QUIC

