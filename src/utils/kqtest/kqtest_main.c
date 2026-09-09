/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <assert.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <ngtcp2/ngtcp2.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include "contrib/ucw/lists.h"
#include "libdnssec/crypto.h"
#include "libknot/errcode.h"
#include "utils/common/msg.h"
#include "utils/kqtest/kqtest_netio.h"
#include "utils/kqtest/kqtest_kdig_params.h"
#include "utils/kqtest/kqtest_kdig_exec.h"
#include "utils/kqtest/kqtest_quic.h"
#include <pthread.h>
#include <string.h>
#include <unistd.h>

#define PROGRAM_NAME "kqtest"

/* Max number of connection the array can hold, in case some test requires
 * more than one connection. */
#define CONN_COUNT 10

#define ENV_BUF_SIZE (1 << 16)
/* Perhaps a bit missleading name since we are actually retrieving net_ctx_t,
 * but the reason for this is to save width, so it is fine. */
#define getconn(x) x->conns[x->flc]

static char address[INET6_ADDRSTRLEN + 6/* port */ + 2/* @ chars */] = "@";
static int verbosity = 0;
static uint64_t query_index = 0;
#define QUERY_COUNT 15
static char* kqtest_queries[QUERY_COUNT] = {
	"example.com", "example.hu", "example.no", "example.sk", "example.de",
	"example.fi", "example.uk", "example.nl", "example.be", "example.fr",
	"example.es", "example.pl", "example.ee", "example.ie", "example.it"
};

enum test_suites {
	STREAM_TESTS = 0,
	PROTO_TESTS = 1,
	MANUAL_TESTS = 2,
};
char *test_suite_names[] = {
	"General stream data handling tests",
	"Protocol compliance tests",
	"Tests requiring manual veriifcation",
};

typedef struct net_ctx {
	net_t *net;
	kdig_params_t params;
} net_ctx_t;

typedef struct kqtest_state {
	net_ctx_t *conns;
	/* idx of the current conn, tests that terminate the connection
	 * should use burned_conn() to increment this value */
	size_t flc;
	size_t counter;
} kqtest_state_t;

static void reset_callbacks(net_t *net)
{
	net->cbs->tls_ctx_setup_remote_endpoint = tls_ctx_setup_remote_endpoint;
	net->cbs->create_query_packet = create_query_packet;
	net->cbs->net_set_local_info = net_set_local_info;
	net->cbs->net_get_remote = net_get_remote;
	net->cbs->tls_ctx_init = tls_ctx_init;
	net->cbs->get_addr_str = get_addr_str;
	net->cbs->net_receive = net_receive;
	// net->cbs->ngtcp2_recv_stream_data_cb = recv_stream_data_cb;
	net->cbs->quic_recv_dns_response = quic_recv_dns_response;
	net->cbs->quic_generate_secret = quic_generate_secret;
	net->cbs->quic_send_dns_query = quic_send_dns_query;
	net->cbs->verify_certificate = verify_certificate;
	net->cbs->quic_stream_reset_cb = stream_reset_cb;
	net->cbs->quic_ctx_connect = quic_ctx_connect;
	net->cbs->quic_send_data = quic_send_data;
	net->cbs->quic_timestamp = quic_timestamp;
	net->cbs->quic_ctx_init = quic_ctx_init;
	net->cbs->offset_span = offset_span;
	// net->cbs->net_ecn_set = net_ecn_set;
	net->cbs->get_expiry = get_expiry;
	net->cbs->quic_recv = quic_recv;
	net->cbs->get_conn = get_conn;
}

static void reset_env(net_t *net)
{
	assert(net->quic.env->buf);
	memset(net->quic.env->buf, 0x0, ENV_BUF_SIZE);
	net->quic.env->bufend = ENV_BUF_SIZE;
	net->quic.env->bufsize = ENV_BUF_SIZE;
	net->quic.env->scenario = 0;
	net->quic.env->counter = 0;
	net->quic.env->extra = 0;
}

static void reset_conn_state(net_t *net)
{
	reset_callbacks(net);
	reset_env(net);
}

static int create_net(const query_t *query, net_t *net)
{
	int ret;
	node_t *server;
	int socktype = get_socktype(query->protocol, query->type_num);
	int flags = query->fastopen ? NET_FLAGS_FASTOPEN : NET_FLAGS_NONE;
	/* Currently there is no use for multiserver kdigs */
	assert(list_size(&query->servers) == 1);
	server = HEAD(query->servers);
	srv_info_t *remote = (srv_info_t *)server;
	int iptype = get_iptype(query->ip, remote);

	for (size_t i = 0; i <= query->retries; i++) {
		// Initialize network structure for current server.
		ret = net_init(query->local, remote, iptype, socktype,
			       query->wait, flags,
			       (struct sockaddr *)&query->proxy.src,
			       (struct sockaddr *)&query->proxy.dst,
			       net);

		if (ret != KNOT_EOK) {
			if (ret == KNOT_NET_EADDR) {
				return KNOT_EADDRNOTAVAIL;
			}
			continue;
		}
		// Loop over all resolved addresses for remote.
		while (net->srv != NULL) {
			ret = net_init_crypto(net, &query->tls, &query->https,
					      &query->quic);
			if (ret == 0) {
				break;
			}
			net->srv = net->srv->ai_next;
		}
		break;
	}
	if (ret == 0) {
		return KNOT_EOK;
	}
	assert(0);
}


static int setup(void **state)
{
	*state = NULL;
	kqtest_state_t *ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return KNOT_ENOMEM;

	ctx->conns = calloc(CONN_COUNT, sizeof(struct net_ctx));
	if (!ctx->conns) {
		free(ctx);
		return KNOT_ENOMEM;
	}
	dnssec_crypto_init();
	*state = ctx;
	return KNOT_EOK;
}

/* ctx and uc_net arguments are mandatory. extra is there just in a case
 * some test requires more than one connection, the number of additional
 * connections is then passed to this function via the extra parameter as the
 * number of total connections required to run the test i.e. 2 if 2 conns are
 * required (the one initialized by defailt and an additional one). */
static int create_conn(kqtest_state_t *ctx, int *extra)
{
	/* Currently unused, prevent programming errors,
	 * TODO if some test requires > 1 conn remove the following if. */
	if (extra) return KNOT_EINVAL;

	if (!ctx || (extra && *extra > 1))
		return KNOT_EINVAL;

	int i = 0;
	for (; i < (!extra ? 1 : (*extra - 1)); i++) {
		ctx->conns[i].net = calloc(1, sizeof(net_t));
		if (!ctx->conns[i].net) {
			goto fail;
		}

		ctx->conns[i].net->sockfd = -1;
		if (create_net(ctx->conns[i].params.config, ctx->conns[i].net)
				!= KNOT_EOK) {
			goto fail_current;
		}

		ctx->conns[i].net->quic.env =
			calloc(1, sizeof(struct test_env));
		if (!ctx->conns[i].net->quic.env) {
			goto fail_current;
		}

		ctx->conns[i].net->quic.env->buf =
			calloc(ENV_BUF_SIZE, sizeof(char));
		if (!ctx->conns[i].net->quic.env->buf) {
			goto fail_current;
		}
		ctx->conns[i].net->quic.env->bufsize = ENV_BUF_SIZE;
		ctx->conns[i].net->quic.verbosity = verbosity;
		ctx->conns[i].net->verbosity = verbosity;
		ctx->conns[i].net->quic.env->bufend = 0;
		reset_callbacks(ctx->conns[i].net);
	}

	return 0;

fail_current:
	if (ctx->conns[0].net) {
		if (ctx->conns[0].net->quic.env) {
			if (ctx->conns[0].net->quic.env->buf) {
				free(ctx->conns[0].net->quic.env->buf);
			}
			free(ctx->conns[0].net->quic.env);
		}
		net_clean(ctx->conns[0].net);
		free(ctx->conns[0].net);
	}

fail:
	for (int k = 0; k < i; k++) {
		if (ctx->conns[k].net->quic.env) {
			free(ctx->conns[k].net->quic.env->buf);
			free(ctx->conns[k].net->quic.env);
		}

		kdig_clean(&ctx->conns[i].params);
		net_clean(ctx->conns[k].net);
		free(ctx->conns[k].net);
	}

	return KNOT_ENOMEM;
}

static int test_send_query(net_ctx_t conn)
{

	if (process_query(HEAD(conn.params.queries), conn.net) != KNOT_EOK) {
		WARN("Sanity check failed for new conn, test result is bogus!");
		assert_true(false);
		return -1;
	}
	reset_conn_state(conn.net);
	return 0;
}

/* Runs before every test, initilizes the query and one connetion*/
static int setup_unit_test_state(void **state)
{
	kqtest_state_t *ctx = *state;
	*state = NULL;
	int ret = KNOT_EINVAL;

	query_t *uc_query = NULL;
	int uc_argc = 3 + 1;
	char *uc_argv[] = {
		"", /* not relevant */
		"+quic",
		address,
		kqtest_queries[query_index++ % QUERY_COUNT],
	};

	int i = 0;
	if (ctx->conns[0].net != NULL) {
		WARN("Connection list has to be empty in setup_unit_test_state!");
		return ret;
	}
	if ((ret = kdig_parse(&ctx->conns[i].params, uc_argc, uc_argv,
					uc_query)) != KNOT_EOK) {
		WARN("Failed to parse params (%d)", ret);
		dnssec_crypto_cleanup();
		return ret;
	}
	if ((ret = create_conn(ctx, NULL)) != 0) {
		dnssec_crypto_cleanup();
		kdig_clean(&ctx->conns[0].params);
		WARN("Failed to create a connection (%d)", ret);
		return ret;
	}
	// /* TODO: We do not do keepalive here, should this really
	//  * be here? */
	if (test_send_query(ctx->conns[0]) != 0) {
		return -1;
	}
	*state = ctx;
	return ret;
}

static void terminate_conn(net_ctx_t conn)
{
	free(conn.net->quic.env->buf);
	free(conn.net->quic.env);
	net_close(conn.net);
	net_clean(conn.net);
	free(conn.net);
	kdig_clean(&conn.params);

}

static int teardown(void **state)
{
	if (!*state)
		return KNOT_EOK;

	kqtest_state_t *ctx = *state;
	dnssec_crypto_cleanup();

	free(ctx->conns);
	free(*state);
	*state = NULL;

	fflush(stdout);
	fflush(stderr);
	return KNOT_EOK;
}

static int test_cleanup(void **state)
{
	kqtest_state_t *ctx = *state;

	int i = 0;
	assert_non_null(HEAD(ctx->conns[i].params.queries));
	assert_non_null(ctx->conns[i].net);
	do {
		reset_conn_state(ctx->conns[i].net);
		assert_non_null(ctx->conns[i].net->quic.env);
		terminate_conn(ctx->conns[i]);
		ctx->conns[i].net = NULL;
		i++;
	} while (HEAD(ctx->conns[i].params.queries) && ctx->conns[i].net);

	return 0;
}

/*****************************************************************************
* 				Automated tests
* ----------------------------------------------------------------------------
* Following set of test verify basic protocol functionality as well as some
* interesting or unusual situations, some of them violate the RFC specification.
******************************************************************************/

/* sanity check that all connections are able to query the server. */
static void simple_sanity(void **state)
{
	kqtest_state_t *ctx = *state;
	assert_int_equal(process_query(HEAD(ctx->conns[0].params.queries),
				ctx->conns[0].net), 0);
}

/* This test opens a stream, sends the bidi stream opening request to the
 * remote and then waits. Implementations that do not set relatively strict
 * handshake timeouts might fails this test if they choose to terminate
 * the connection localy without sending any information back to the client. */
static void open_stream_and_timeout(void **state)
{
	kqtest_state_t *ctx = *state;
	getconn(ctx).net->cbs->quic_send_data = quic_send_data_test;
	getconn(ctx).net->cbs->quic_recv = quic_recv_close_doq_error;
	getconn(ctx).net->quic.env->scenario = 1;

	/* query should fail */
	assert_int_equal(process_query(HEAD(getconn(ctx).params.queries),
				getconn(ctx).net), -1);
	assert_int_equal(getconn(ctx).net->quic.last_err.type,
			NGTCP2_CCERR_TYPE_APPLICATION);
	assert_int_equal(getconn(ctx).net->quic.last_err.error_code,
			NGTCP2_APPLICATION_ERROR);
}

/* most DNS queries come in a single packet that opens the stream,
 * and contains the FIN flag as well. This test splits the payload */
static void stream_data_split_to_two_pkts(void **state)
{
	kqtest_state_t *ctx = *state;
	getconn(ctx).net->cbs->quic_send_dns_query = quic_send_dns_query_split;
	getconn(ctx).net->cbs->quic_send_data = quic_send_data_split;
	getconn(ctx).net->quic.env->counter = 2;
	assert_int_equal(process_query(HEAD(getconn(ctx).params.queries),
				getconn(ctx).net), 0);
}

static void stream_data_split_to_ten_pkts(void **state)
{
	kqtest_state_t *ctx = *state;
	getconn(ctx).net->cbs->quic_send_dns_query = quic_send_dns_query_split;
	getconn(ctx).net->cbs->quic_send_data = quic_send_data_split;
	getconn(ctx).net->quic.env->counter = 10;
	assert_int_equal(process_query(HEAD(getconn(ctx).params.queries),
				getconn(ctx).net), 0);
}

/* Test multiple active streams which send their queries split in half
 * so all the streams send their first half of the query
 * first and then send again with FIN the rest. */
static void multiple_parallel_streams(void **state)
{
	kqtest_state_t *ctx = *state;

	getconn(ctx).net->quic.env->extra = 10;
	getconn(ctx).net->quic.env->counter = 2;
	getconn(ctx).net->quic.env->scenario = NGTCP2_WRITE_STREAM_FLAG_NONE;
	getconn(ctx).net->cbs->quic_send_dns_query = quic_send_dns_query_sync;
	getconn(ctx).net->cbs->quic_send_data = quic_send_data_split;
	getconn(ctx).net->cbs->quic_recv = quic_recv_with_ack;
	assert_int_equal(process_query(HEAD(getconn(ctx).params.queries),
				getconn(ctx).net), 0);
}

static void send_one_byte_at_a_time(void **state)
{
	kqtest_state_t *ctx = *state;

	if (ctx->flc + 1 >= CONN_COUNT) {
		printf("Insufficient number of connection for this test, need >= 1");
		assert_true(false);
		return;
	}

	getconn(ctx).net->cbs->quic_send_dns_query = quic_send_dns_query_split;
	getconn(ctx).net->cbs->quic_send_data = quic_send_data_split;
	getconn(ctx).net->quic.env->scenario = NGTCP2_WRITE_STREAM_FLAG_NONE;
	/* -1 means send one byte at a time */
	getconn(ctx).net->quic.env->counter = -1;

	assert_int_equal(process_query(HEAD(getconn(ctx).params.queries),
				getconn(ctx).net), 0);
}

/* This test sends the first half of tha payload and right after that
 * sends RESET_STREAM. The peer (server) should in that point ACK the reset
 * and silently terminate the DNS request and delete the stream state. */
static void send_stream_reset_prefin(void **state)
{
	kqtest_state_t *ctx = *state;
	getconn(ctx).net->cbs->quic_send_data =
		quic_send_data_split_reset_stream;
	getconn(ctx).net->cbs->quic_send_dns_query = quic_send_dns_query_split;
	getconn(ctx).net->quic.env->scenario = NGTCP2_WRITE_STREAM_FLAG_NONE;
	assert_int_equal(process_query(HEAD(getconn(ctx).params.queries),
				getconn(ctx).net), -1);
}

/* Same as send_stream_reset_prefin but sends the entire payload including
 * the FIN flag prior to sending RESET_STREAM.
 * WARNING: This test requires the tested upstream to delay its answer.
 * Ideally configure your setup such that the server forwards to a dead
 * upstream, meaning there will be several seconds to transmit the reset stream
 * before the tested upstream responds with an answer of SERVFAIL. */
static void send_stream_reset_postfin(void **state)
{
	kqtest_state_t *ctx = *state;
	getconn(ctx).net->cbs->quic_send_data =
		quic_send_data_split_reset_stream;
	getconn(ctx).net->cbs->quic_send_dns_query = quic_send_dns_query;
	getconn(ctx).net->quic.env->scenario = NGTCP2_WRITE_STREAM_FLAG_FIN;
	assert_int_equal(process_query(HEAD(getconn(ctx).params.queries),
				getconn(ctx).net), -1);
}

/*****************************************************************************
*	 		RFC 9250 Protocol Error tests
* ----------------------------------------------------------------------------
* This set of tests simulates some protocol errors defined in RFC 9250 4.3.3.
* The response to these tests from the upstream server should forcibly abort
* the connection via CONNECTION_CLOSE and set the appropriate DoQ error code.
*
* These tests are automatic. Meaning they verify that the server responds to
* such errors in compliance with the RFC specification.
******************************************************************************/

/* a client or server receives a message with a non-zero Message ID */
static void send_non_zero_msgid(void **state)
{
	kqtest_state_t *ctx = *state;
	getconn(ctx).net->cbs->create_query_packet =
		create_query_packet_with_msgid;
	getconn(ctx).net->cbs->quic_recv = quic_recv_close_doq_error;
	assert_int_equal(process_query(HEAD(getconn(ctx).params.queries),
				getconn(ctx).net), -1);
	assert_int_equal(getconn(ctx).net->quic.last_err.type,
			NGTCP2_CCERR_TYPE_APPLICATION);
	assert_int_equal(getconn(ctx).net->quic.last_err.error_code,
			DOQ_PROTOCOL_ERROR);
}

/* a client or server receives a STREAM FIN before receiving all the
 * bytes for a message indicated in the 2-octet length field */
static void send_less_data_than_size_prefix(void **state)
{
	kqtest_state_t *ctx = *state;
	getconn(ctx).net->cbs->quic_send_dns_query =
		quic_send_dns_query_wrong_size_prefix;
	getconn(ctx).net->cbs->quic_recv = quic_recv_close_doq_error;
	getconn(ctx).net->quic.env->extra = 50;
	assert_int_equal(process_query(HEAD(getconn(ctx).params.queries),
				getconn(ctx).net), -1);
	assert_int_equal(getconn(ctx).net->quic.last_err.type,
			NGTCP2_CCERR_TYPE_APPLICATION);
	assert_int_equal(getconn(ctx).net->quic.last_err.error_code,
			DOQ_PROTOCOL_ERROR);
}
/* Same as above but send more */
static void send_more_data_than_size_prefix(void **state)
{
	kqtest_state_t *ctx = *state;
	getconn(ctx).net->cbs->quic_send_dns_query =
		quic_send_dns_query_wrong_size_prefix;
	getconn(ctx).net->cbs->quic_recv = quic_recv_close_doq_error;
	getconn(ctx).net->quic.env->extra = -50;
	assert_int_equal(process_query(HEAD(getconn(ctx).params.queries),
				getconn(ctx).net), -1);
	assert_int_equal(getconn(ctx).net->quic.last_err.type,
			NGTCP2_CCERR_TYPE_APPLICATION);
	assert_int_equal(getconn(ctx).net->quic.last_err.error_code,
			DOQ_PROTOCOL_ERROR);
}

/* a server receives more than one query on a stream */
/* DEV NOTE: this isn't really different for out implementation, but some
 * other miplementation might accept secondary query if it is prepended
 * like a proper query with the size prefix. TODO but low prio since this
 * cannot happen in out implementation. */
static void send_two_size_prefixed_queries(void **state)
{
	kqtest_state_t *ctx = *state;
	getconn(ctx).net->cbs->quic_send_dns_query = quic_send_doubled;
	getconn(ctx).net->cbs->quic_recv = quic_recv_close_doq_error;
	assert_int_equal(process_query(HEAD(getconn(ctx).params.queries),
				getconn(ctx).net), -1);
	assert_int_equal(getconn(ctx).net->quic.last_err.type,
			NGTCP2_CCERR_TYPE_APPLICATION);
	assert_int_equal(getconn(ctx).net->quic.last_err.error_code,
			DOQ_PROTOCOL_ERROR);
}

/* the client or server does not indicate the expected STREAM FIN
 * after sending requests or responses (see Section 4.2[meant in RFC 9250])
 * WARNING: This test is not really automated since the RFC doesn't exactly
 * specify how this situation should be handled. Most implementations will
 * just timeout the connection, that solution should be ok. */
static void missing_stream_fin(void **state)
{
	kqtest_state_t *ctx = *state;
	getconn(ctx).net->quic.env->scenario = NGTCP2_STREAM_DATA_FLAG_NONE;
	getconn(ctx).net->quic.env->extra = TEST_SEND_ONE_PAYLOAD;
	getconn(ctx).net->quic.env->counter = 1;
	getconn(ctx).net->cbs->quic_send_dns_query = quic_send_dns_query_split;
	getconn(ctx).net->cbs->quic_send_data = quic_send_data_split;
	getconn(ctx).net->cbs->quic_recv = quic_recv_close_doq_error;
	assert_int_equal(process_query(HEAD(getconn(ctx).params.queries),
				getconn(ctx).net), 0);
}

/* an implementation receives a message containing the edns-tcp-keepalive
 * EDNS(0) Option [RFC7828] (see Section 5.5.2[meant in RFC 9250]) */
static void send_edns_keepalive(void **state)
{
	kqtest_state_t *ctx = *state;
	query_t *q = HEAD(ctx->conns[0].params.queries);
	ednsopt_t *opt =
		ednsopt_create(KNOT_EDNS_OPTION_TCP_KEEPALIVE, 0, NULL);
	add_tail(&q->edns_opts, &opt->n);
	getconn(ctx).net->cbs->quic_recv = quic_recv_close_doq_error;
	assert_int_equal(process_query(HEAD(getconn(ctx).params.queries),
				getconn(ctx).net), -1);
	assert_int_equal(getconn(ctx).net->quic.last_err.type,
			NGTCP2_CCERR_TYPE_APPLICATION);
	assert_int_equal(getconn(ctx).net->quic.last_err.error_code,
			DOQ_PROTOCOL_ERROR);
}

/* a client or a server attempts to open a unidirectional QUIC stream */
/* NOTE This situation might be handled by the QUIC library used
 * for the server's DoQ implementation since the server should prevent
 * the counterside from opening unidirectional streams at all by setting
 * initial_max_stream_uni to 0. If this is not set the implementation will
 * attempt to open such stream, if uni stream limit is 0 the test passes. */
static void open_unidirectional(void **state)
{
	kqtest_state_t *ctx = *state;
	getconn(ctx).net->cbs->quic_send_dns_query =
		quic_send_dns_query_open_uni_stream;
	assert_int_equal(process_query(HEAD(getconn(ctx).params.queries),
				getconn(ctx).net), -1);
}

/*****************************************************************************
* 		Tests that require manual verification
* ----------------------------------------------------------------------------
* These tests do not provide any meaningful information in the cmocka output.
* If these tests pass it ONLY means that they were executed without any
* problems. The result itself and the response of the tested implementation has
* to be verified manually, it is strongly recomended to enable ngtcp2 debug log
* (using the -V option) when running these tests.
******************************************************************************/

/* This test is supposed to test the state handling
 * of an abandoned stream. Disable the test or create such a setup in which
 * the tested server takes a long time to receive (but eventually it does
 * receive) the query. For example using a modified resolver which the tested
 * implementation forwards to.
 * This tests only fails if the sequence of sends wan't performed
 * corretly. Hence the result of this test is to be interpreted as follows:
 * if this test failed the desired state likely wasn't reached on the
 * tested implementation, voiding the results. The result only
 * tracks the correct execution of the test, the real result has to
 * be inspected on the server. */
static void send_and_close(void **state)
{
	kqtest_state_t *ctx = *state;
	getconn(ctx).net->cbs->quic_send_dns_query =
		quic_send_dns_query_terminate;
	getconn(ctx).net->cbs->quic_send_data = quic_send_data_terminate;
	getconn(ctx).net->quic.env->scenario = NGTCP2_WRITE_STREAM_FLAG_NONE;
	assert_int_equal(process_query(HEAD(getconn(ctx).params.queries),
				getconn(ctx).net), -1);
}

/* This test is intended to verify that the server correctly handles
 * a situation where the client sends data after STOP_SENDING. */
static void send_after_stop_sending(void **state)
{
	kqtest_state_t *ctx = *state;
	getconn(ctx).net->cbs->quic_send_dns_query =
		quic_send_dns_query_stop_sending;
	getconn(ctx).net->cbs->quic_stream_reset_cb =
		stream_reset_cb_malicious_survival;
	getconn(ctx).net->cbs->net_receive = net_receive_fail_ok;
	getconn(ctx).net->cbs->quic_send_data = quic_send_data_split;
	getconn(ctx).net->quic.env->scenario = NGTCP2_WRITE_STREAM_FLAG_NONE;
	getconn(ctx).net->quic.env->counter = 2;
	assert_int_equal(process_query(HEAD(getconn(ctx).params.queries),
				getconn(ctx).net), 0);
}

int main(int argc, char *argv[])
{
	bool enable_manual = false;
	if (argc == 2 && (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h"))) {
		printf("kqtest [OPTIONS] address port\tkqtest requires an address and a port of the DoQ server that is to be tested\n");
		printf("kqtest --help \t\t\tdisplays this help message\n");
		printf("kqtest OPTIONS:\n");
		printf("\t -v\t\t\tprint usual kdig output alongside test results\n");
		printf("\t -V\t\t\tprint usual kdig output and ngtcp2 log alongside test results\n");
		printf("\t -m\t\t\tRun manual tests, these have no interpretable results and have to be verified on the server side (via log inspection and/or debug)\n");
		return KNOT_EINVAL;
	}

#define MAX_ARGS 5
#define MIN_ARGS 3
#define FLAG_ARGS_MIN_POS 1
#define FLAG_ARGS_MAX_POS 2
	if ((argc == MIN_ARGS && argv[FLAG_ARGS_MAX_POS][0] == '-')
			|| argc < MIN_ARGS
			|| argc > MAX_ARGS) {
		printf("Invalid number of arguments, see --help\n");
		return KNOT_EINVAL;
	}

	for (int i = FLAG_ARGS_MIN_POS;
			i < (FLAG_ARGS_MIN_POS + argc - MIN_ARGS); i++) {
		if (strlen(argv[i]) != 2) {
			printf("Unknown option '%s', see --help\n", argv[i]);
			return KNOT_EINVAL;
		} else if (!strcmp(argv[i], "-v") && verbosity == 0) {
			verbosity = 1;
		} else if (!strcmp(argv[i], "-V") && verbosity == 0) {
			verbosity = 2;
		} else if (!strcmp(argv[i], "-m") && enable_manual == false) {
			enable_manual = true;
		} else {
			printf("Unknown or duplicit option '%s', see --help\n",
					argv[i]);
			return KNOT_EINVAL;
		}
	}

	size_t addrlen = strlen(argv[1 + !!verbosity + enable_manual]);
	size_t portlen = strlen(argv[2 + !!verbosity + enable_manual]);
	strncpy(address + 1, argv[1 + !!verbosity + enable_manual], addrlen);
	address[addrlen + 1] = '@';
	strncpy(address + 1 + addrlen + 1,
			argv[2 + !!verbosity + enable_manual], portlen);

	printf("testing address: %s\n", address);

	#define c_u_t(test_fun) cmocka_unit_test_setup_teardown(test_fun, \
			setup_unit_test_state, test_cleanup)
	#define c_m_unit_test CMUnitTest

	const struct c_m_unit_test stream_tests[] = {
		c_u_t(simple_sanity),
		c_u_t(open_stream_and_timeout),
		c_u_t(stream_data_split_to_two_pkts),
		c_u_t(stream_data_split_to_ten_pkts),
		c_u_t(multiple_parallel_streams),
		c_u_t(send_one_byte_at_a_time),
		c_u_t(send_stream_reset_prefin),
		c_u_t(send_stream_reset_postfin),
	};
	cmocka_run_group_tests_name(test_suite_names[STREAM_TESTS],
			stream_tests, setup, teardown);

	const struct c_m_unit_test proto_compliance_tests[] = {
		c_u_t(send_non_zero_msgid),
		c_u_t(send_less_data_than_size_prefix),
		c_u_t(send_more_data_than_size_prefix),
		c_u_t(send_two_size_prefixed_queries),
		c_u_t(missing_stream_fin),
		c_u_t(send_edns_keepalive),
		c_u_t(open_unidirectional),
	};
	cmocka_run_group_tests_name(test_suite_names[PROTO_TESTS],
			proto_compliance_tests, setup, teardown);

	if (enable_manual) {
		const struct c_m_unit_test manual_verification_tests[] = {
			c_u_t(send_and_close),
			c_u_t(send_after_stop_sending),
		};
		cmocka_run_group_tests_name(test_suite_names[MANUAL_TESTS],
				manual_verification_tests, setup, teardown);
	}

	return KNOT_EOK;
}
