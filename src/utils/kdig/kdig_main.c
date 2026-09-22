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
#include "libknot/dnssec/crypto.h"
#include "libknot/errcode.h"
#include "utils/common/msg.h"
#include "utils/kdig/kdig_netio.h"
#include "utils/kdig/kdig_params.h"
#include "utils/kdig/kqtest_kdig_exec.h"
#include "utils/kdig/kdig_quic.h"
#include <pthread.h>
#include <string.h>
#include <unistd.h>

#define PROGRAM_NAME "kdig"

#define ENV_BUF_SIZE (1 << 16)

static char address[NI_MAXHOST + 8];
static int verbosity = 0;
static uint64_t query_index = 0;
#define QUERY_COUNT 15
static char* kqtest_queries[QUERY_COUNT] = {
	"example.com", "example.hu", "example.no", "example.sk", "example.de",
	"example.fi", "example.uk", "example.nl", "example.be", "example.fr",
	"example.es", "example.pl", "example.ee", "example.ie", "example.it"
};

enum test_suites {
	SANITY_TESTS = 0,
	STREAM_TESTS = 1,
	PROTO_TESTS = 2,
	MANUAL_TESTS = 3,
};
char *test_suite_names[] = {
	"Send a query over DoQ",
	"General stream data handling tests",
	"Protocol compliance tests",
	"Tests requiring manual verifcation",
};

typedef struct kqtest_state {
	net_t *net;
	kdig_params_t params;
} kqtest_state_t;

static void reset_callbacks(net_t *net)
{
	net->cbs->tls_ctx_setup_remote_endpoint = tls_ctx_setup_remote_endpoint;
	net->cbs->quic_recv_dns_response = quic_recv_dns_response;
	net->cbs->quic_generate_secret = quic_generate_secret;
	net->cbs->create_query_packet = create_query_packet;
	net->cbs->quic_send_dns_query = quic_send_dns_query;
	net->cbs->verify_certificate = verify_certificate;
	net->cbs->net_set_local_info = net_set_local_info;
	net->cbs->quic_ctx_connect = quic_ctx_connect;
	net->cbs->stream_reset_cb = stream_reset_cb;
	net->cbs->net_get_remote = net_get_remote;
	net->cbs->quic_send_data = quic_send_data;
	net->cbs->quic_timestamp = quic_timestamp;
	net->cbs->quic_ctx_init = quic_ctx_init;
	net->cbs->get_addr_str = get_addr_str;
	net->cbs->tls_ctx_init = tls_ctx_init;
	net->cbs->offset_span = offset_span;
	net->cbs->net_receive = net_receive;
	net->cbs->get_expiry = get_expiry;
	net->cbs->quic_recv = quic_recv;
	net->cbs->get_conn = get_conn;
}

static void reset_env(net_t *net)
{
	net->quic.env->scenario = 0;
	net->quic.env->counter = 0;
	net->quic.env->extra.bitflag = 0;
	net->quic.env->extra.error_observed = 0;
	net->quic.env->extra.add_to_size_prefix = 0;
	net->quic.env->extra.request_stream_count = 1;
	net->quic.env->extra.expected_response_count = 1;
}


static void reset_conn_state(net_t *net)
{
	reset_callbacks(net);
	reset_env(net);
}

static int create_net(const query_t *query, net_t *net)
{
	int socktype = get_socktype(query->protocol, query->type_num);
	assert(list_size(&query->servers) == 1);
	srv_info_t *remote = (srv_info_t *)HEAD(query->servers);
	int iptype = get_iptype(query->ip, remote);

	int ret = net_init(query->local, remote, iptype, socktype, query->wait,
			(struct sockaddr *)&query->proxy.src,
			(struct sockaddr *)&query->proxy.dst, net);
	if (ret != KNOT_EOK) {
		return (ret == KNOT_NET_EADDR) ? KNOT_EADDRNOTAVAIL : ret;
	}

	return net_init_crypto(net, &query->tls, &query->https, &query->quic);
}

static int setup(void **state)
{
	*state = NULL;
	kqtest_state_t *ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return KNOT_ENOMEM;

	dnssec_crypto_init();
	*state = ctx;
	return KNOT_EOK;
}

static int create_conn(kqtest_state_t *ctx)
{
	if (!ctx)
		return KNOT_EINVAL;

	ctx->net = calloc(1, sizeof(net_t));
	if (!ctx->net) {
		goto fail;
	}

	ctx->net->sockfd = -1;
	if (create_net(ctx->params.config, ctx->net)
			!= KNOT_EOK) {
		goto fail;
	}

	ctx->net->quic.env =
		calloc(1, sizeof(struct test_env));
	if (!ctx->net->quic.env) {
		goto fail;
	}

	ctx->net->quic.verbosity = verbosity;
	ctx->net->verbosity = verbosity;
	reset_callbacks(ctx->net);

	return KNOT_EOK;

fail:
	if (ctx->net) {
		if (ctx->net->quic.env) {
			free(ctx->net->quic.env);
		}
		net_close(ctx->net);
		net_clean(ctx->net);
		free(ctx->net);
	}

	return KNOT_ENOMEM;
}

static void terminate_conn(struct kqtest_state *ctx)
{
	net_close(ctx->net);
	net_clean(ctx->net);
	free(ctx->net->quic.env);
	free(ctx->net);

}

static int test_send_query(kqtest_state_t *ctx)
{
	if (process_query(HEAD(ctx->params.queries), ctx->net) != KNOT_EOK) {
		WARN("Sanity check failed for new conn, test result is bogus!");
		return -1;
	}
	reset_conn_state(ctx->net);
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

	if (ctx->net != NULL) {
		WARN("Connection list has to be empty in setup_unit_test_state!");
		return ret;
	}

	if ((ret = kdig_parse(&ctx->params, uc_argc, uc_argv,
					uc_query)) != KNOT_EOK) {
		WARN("Failed to parse params (%d)", ret);
		return ret;
	}

	if ((ret = create_conn(ctx)) != 0) {
		kdig_clean(&ctx->params);
		return ret;
	}
	if ((ret = test_send_query(ctx)) != 0) {
		terminate_conn(ctx);
		kdig_clean(&ctx->params);
		return ret;
	}

	*state = ctx;
	return ret;
}

static int teardown(void **state)
{
	if (!*state)
		return KNOT_EOK;

	dnssec_crypto_cleanup();

	free(*state);
	*state = NULL;

	fflush(stdout);
	fflush(stderr);
	return KNOT_EOK;
}

static int test_cleanup(void **state)
{
	kqtest_state_t *ctx = *state;

	assert_non_null(HEAD(ctx->params.queries));
	assert_non_null(ctx->net);
	reset_conn_state(ctx->net);
	assert_non_null(ctx->net->quic.env);
	terminate_conn(ctx);
	kdig_clean(&ctx->params);
	ctx->net = NULL;

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
	assert_int_equal(process_query(HEAD(ctx->params.queries),
				ctx->net), 0);
}

/* This test opens a stream, sends the bidi stream opening request to the
 * remote and then waits. Implementations that do not set relatively strict
 * handshake timeouts might choose to terminate the connection without sending
 * any information back to the client. */
static void open_stream_and_timeout(void **state)
{
	kqtest_state_t *ctx = *state;

	ctx->net->cbs->quic_send_data = quic_send_data_test;
	ctx->net->cbs->quic_recv = quic_recv_close_doq_error;
	ctx->net->quic.env->scenario = 1;
	assert_int_equal(process_query(HEAD(ctx->params.queries),
				ctx->net), -1);
	/* Silent conn termination is allowed. */
	if (ctx->net->quic.last_err.error_code != 0) {
		assert_int_equal(ctx->net->quic.last_err.type,
				NGTCP2_CCERR_TYPE_APPLICATION);
		assert_int_equal(ctx->net->quic.last_err.error_code,
				NGTCP2_APPLICATION_ERROR);
	}
}

/* most DNS queries come in a single packet that opens the stream,
 * and contains the FIN flag as well. This test splits the payload */
static void stream_data_split_to_two_pkts(void **state)
{
	kqtest_state_t *ctx = *state;
	ctx->net->cbs->quic_send_dns_query = quic_send_dns_query_split;
	ctx->net->cbs->quic_send_data = quic_send_data_split;
	ctx->net->quic.env->counter = 2;
	assert_int_equal(process_query(HEAD(ctx->params.queries),
				ctx->net), 0);
}

static void stream_data_split_to_ten_pkts(void **state)
{
	kqtest_state_t *ctx = *state;
	ctx->net->cbs->quic_send_dns_query = quic_send_dns_query_split;
	ctx->net->cbs->quic_send_data = quic_send_data_split;
	ctx->net->quic.env->counter = 10;
	assert_int_equal(process_query(HEAD(ctx->params.queries),
				ctx->net), 0);
}

/* Test multiple active streams which send their queries split in half
 * so all the streams send their first half of the query
 * first and then send again with FIN the rest. */
static void multiple_parallel_streams(void **state)
{
	kqtest_state_t *ctx = *state;

	ctx->net->quic.env->extra.request_stream_count = 10;
	ctx->net->quic.env->extra.expected_response_count = 10;
	ctx->net->quic.env->counter = 2;
	ctx->net->quic.env->scenario = NGTCP2_WRITE_STREAM_FLAG_NONE;
	ctx->net->cbs->quic_send_dns_query = quic_send_dns_query_sync;
	ctx->net->cbs->quic_send_data = quic_send_data_split;
	ctx->net->cbs->quic_recv = quic_recv_with_ack;
	assert_int_equal(process_query(HEAD(ctx->params.queries),
				ctx->net), 0);
}

static void send_one_byte_at_a_time(void **state)
{
	kqtest_state_t *ctx = *state;

	ctx->net->cbs->quic_send_dns_query = quic_send_dns_query_split;
	ctx->net->cbs->quic_send_data = quic_send_data_split;
	ctx->net->quic.env->scenario = NGTCP2_WRITE_STREAM_FLAG_NONE;
	/* -1 means send one byte at a time */
	ctx->net->quic.env->counter = -1;
	assert_int_equal(process_query(HEAD(ctx->params.queries),
				ctx->net), 0);
}

/* This test sends the first half of tha payload and right after that
 * sends RESET_STREAM. The peer (server) should in that point ACK the reset
 * and silently terminate the DNS request and delete the stream state. */
static void send_stream_reset_prefin(void **state)
{
	kqtest_state_t *ctx = *state;
	ctx->net->cbs->quic_send_data =
		quic_send_data_split_reset_stream;
	ctx->net->cbs->quic_send_dns_query = quic_send_dns_query_split;
	ctx->net->quic.env->scenario = NGTCP2_WRITE_STREAM_FLAG_NONE;
	assert_int_equal(process_query(HEAD(ctx->params.queries),
				ctx->net), -1);
}

/*****************************************************************************
*	 		RFC 9250 Protocol Error tests
* ----------------------------------------------------------------------------
* This set of tests simulates some protocol errors defined in RFC 9250 4.3.3.
* The response to these tests from the upstream server should forcibly abort
* the connection via CONNECTION_CLOSE and set the appropriate DoQ error code.
*
* NOTE: The RFC specification also declares silent connection termination as an
* appropriate response to these procotol errors. These test, however, expect
* a response. If your implementation deliberately doesn't send CONNECTION_CLOSE
* these tests will fail which is a false positive. The server should not respond
* with an answer, failing the first assertion of each test is a protocol
* violation!
*
******************************************************************************/

/* a client or server receives a message with a non-zero Message ID */
static void send_non_zero_msgid(void **state)
{
	kqtest_state_t *ctx = *state;
	ctx->net->cbs->create_query_packet =
		create_query_packet_with_msgid;
	ctx->net->cbs->quic_recv = quic_recv_close_doq_error;
	assert_int_equal(process_query(HEAD(ctx->params.queries),
				ctx->net), -1);
	assert_int_equal(ctx->net->quic.env->extra.error_observed, 1);
	assert_int_equal(ctx->net->quic.last_err.type,
			NGTCP2_CCERR_TYPE_APPLICATION);
	assert_int_equal(ctx->net->quic.last_err.error_code,
			DOQ_PROTOCOL_ERROR);
}

/* a client or server receives a STREAM FIN before receiving all the
 * bytes for a message indicated in the 2-octet length field */
static void send_less_data_than_size_prefix(void **state)
{
	kqtest_state_t *ctx = *state;
	ctx->net->cbs->quic_send_dns_query =
		quic_send_dns_query_wrong_size_prefix;
	ctx->net->cbs->quic_recv = quic_recv_close_doq_error;
	ctx->net->quic.env->extra.add_to_size_prefix = 50;
	assert_int_equal(process_query(HEAD(ctx->params.queries),
				ctx->net), -1);
	assert_int_equal(ctx->net->quic.env->extra.error_observed, 1);
	assert_int_equal(ctx->net->quic.last_err.type,
			NGTCP2_CCERR_TYPE_APPLICATION);
	assert_int_equal(ctx->net->quic.last_err.error_code,
			DOQ_PROTOCOL_ERROR);
}
/* Same as above but send more */
static void send_more_data_than_size_prefix(void **state)
{
	kqtest_state_t *ctx = *state;
	ctx->net->cbs->quic_send_dns_query =
		quic_send_dns_query_wrong_size_prefix;
	ctx->net->cbs->quic_recv = quic_recv_close_doq_error;
	ctx->net->quic.env->extra.add_to_size_prefix = -50;
	assert_int_equal(process_query(HEAD(ctx->params.queries),
				ctx->net), -1);
	assert_int_equal(ctx->net->quic.env->extra.error_observed, 1);
	assert_int_equal(ctx->net->quic.last_err.type,
			NGTCP2_CCERR_TYPE_APPLICATION);
	assert_int_equal(ctx->net->quic.last_err.error_code,
			DOQ_PROTOCOL_ERROR);
}

/* a server receives more than one query on a stream */
/* DEV NOTE: this isn't really different for out implementation, but some
 * other miplementation might accept secondary query if it is prepended
 * like a proper query with the size prefix. */
static void send_two_size_prefixed_queries(void **state)
{
	kqtest_state_t *ctx = *state;
	ctx->net->cbs->quic_send_dns_query = quic_send_doubled;
	ctx->net->cbs->quic_recv = quic_recv_close_doq_error;
	assert_int_equal(process_query(HEAD(ctx->params.queries),
				ctx->net), -1);
	assert_int_equal(ctx->net->quic.env->extra.error_observed, 1);
	assert_int_equal(ctx->net->quic.last_err.type,
			NGTCP2_CCERR_TYPE_APPLICATION);
	assert_int_equal(ctx->net->quic.last_err.error_code,
			DOQ_PROTOCOL_ERROR);
}

/* the client or server does not indicate the expected STREAM FIN
 * after sending requests or responses (see Section 4.2[meant in RFC 9250])
 * WARNING: This test is anomalous, it isn't really clear in the RFC how
 * this should be handled or even detected. Streams message with no stream
 * data and FIN flag present is allowed. Meaning the server cannot determine
 * whether missing FIN after receiving the wire size prefix of data is an error
 * or just a delayed packet with FIN flag. Therefore all we require is that
 * the server doesn't respond with an answer untill the connection times out. */
static void missing_stream_fin(void **state)
{
	kqtest_state_t *ctx = *state;
	ctx->net->quic.env->scenario = NGTCP2_WRITE_STREAM_FLAG_NONE;
	ctx->net->quic.env->extra.bitflag = TEST_SEND_ONE_PAYLOAD;
	ctx->net->quic.env->counter = 1;
	ctx->net->cbs->quic_send_dns_query = quic_send_dns_query_split;
	ctx->net->cbs->quic_send_data = quic_send_data_split;
	ctx->net->cbs->quic_recv = quic_recv_close_doq_error;
	assert_int_equal(process_query(HEAD(ctx->params.queries),
				ctx->net), -1);
}

/* an implementation receives a message containing the edns-tcp-keepalive
 * EDNS(0) Option [RFC7828] (see Section 5.5.2[meant in RFC 9250]) */
static void send_edns_keepalive(void **state)
{
	kqtest_state_t *ctx = *state;
	query_t *q = HEAD(ctx->params.queries);
	ednsopt_t *opt =
		ednsopt_create(KNOT_EDNS_OPTION_TCP_KEEPALIVE, 0, NULL);
	add_tail(&q->edns_opts, &opt->n);
	ctx->net->cbs->quic_recv = quic_recv_close_doq_error;
	assert_int_equal(process_query(HEAD(ctx->params.queries),
				ctx->net), -1);
	assert_int_equal(ctx->net->quic.env->extra.error_observed, 1);
	assert_int_equal(ctx->net->quic.last_err.type,
			NGTCP2_CCERR_TYPE_APPLICATION);
	assert_int_equal(ctx->net->quic.last_err.error_code,
			DOQ_PROTOCOL_ERROR);
}

/* Simply checks if the client is allowed to open a unidirectional stream.
 * The server decides the number of allowed unidirectional streams when
 * configuring the connection params. Setting params.initial_max_streams_uni
 * to anything other than 0 is not incorrect for DoQ */
static void open_unidirectional(void **state)
{
	kqtest_state_t *ctx = *state;

	uint64_t uni_left =
		ngtcp2_conn_get_streams_uni_left(ctx->net->quic.conn);
	assert_int_equal(uni_left, 0);
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
	ctx->net->cbs->quic_send_dns_query =
		quic_send_dns_query_terminate;
	ctx->net->cbs->quic_send_data = quic_send_data_terminate;
	ctx->net->quic.env->scenario = NGTCP2_WRITE_STREAM_FLAG_NONE;
	assert_int_equal(process_query(HEAD(ctx->params.queries),
				ctx->net), -1);
}

/* This test is intended to verify that the server correctly handles
 * a situation where the client sends data after STOP_SENDING. */
static void send_after_stop_sending(void **state)
{
	kqtest_state_t *ctx = *state;
	ctx->net->cbs->quic_send_dns_query =
		quic_send_dns_query_stop_sending;
	ctx->net->cbs->stream_reset_cb =
		stream_reset_cb_malicious_survival;
	ctx->net->cbs->net_receive = net_receive_fail_ok;
	ctx->net->cbs->quic_send_data = quic_send_data_split;
	ctx->net->quic.env->extra.bitflag |= TEST_KEEP_SPLIT_VECTOR;
	ctx->net->quic.env->scenario = NGTCP2_WRITE_STREAM_FLAG_NONE;
	ctx->net->quic.env->counter = 2;
	assert_int_equal(process_query(HEAD(ctx->params.queries),
				ctx->net), 0);
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
	ctx->net->cbs->quic_send_data =
		quic_send_data_split_reset_stream;
	ctx->net->cbs->quic_send_dns_query = quic_send_dns_query;
	ctx->net->quic.env->scenario = NGTCP2_WRITE_STREAM_FLAG_FIN;
	assert_int_equal(process_query(HEAD(ctx->params.queries),
				ctx->net), -1);
}


/*****************************************************************************/

void print_help(void)
{
	printf("Usage: %s [-v|-V log level] [-m manual tests] address port\n"
	       "       -h, --help   displays this help message\n"
	       "       -v           print usual kdig output alongside test results\n"
	       "       -V           print usual kdig output and ngtcp2 log\n"
	       "                    alongside test results\n"
	       "       -m           Run manual tests, these have no interpretable results\n"
	       "                    and have to be verified on the server side\n"
	       "                    (via log inspection and/or debug)\n",
	       PROGRAM_NAME);
}

int main(int argc, char *argv[])
{
	int result = 0;
	bool enable_manual = false;
	if (argc == 2 && (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h"))) {
		print_help();
		return KNOT_EINVAL;
	}

#define MAX_ARGS 5
#define MIN_ARGS 3
#define FLAG_ARGS_MIN_POS 1
#define FLAG_ARGS_MAX_POS 2
	if ((argc == MIN_ARGS && argv[FLAG_ARGS_MAX_POS][0] == '-')
			|| argc < MIN_ARGS
			|| argc > MAX_ARGS) {
		ERR("Invalid number of arguments, see --help");
		return KNOT_EINVAL;
	}

	int i = FLAG_ARGS_MIN_POS;
	for (; i < (FLAG_ARGS_MIN_POS + argc - MIN_ARGS); i++) {
		if (strlen(argv[i]) != 2) {
			ERR("Unknown option '%s', see --help", argv[i]);
			return KNOT_EINVAL;
		} else if (!strcmp(argv[i], "-v") && verbosity == 0) {
			verbosity = 1;
		} else if (!strcmp(argv[i], "-V") && verbosity == 0) {
			verbosity = 2;
		} else if (!strcmp(argv[i], "-m") && enable_manual == false) {
			enable_manual = true;
		} else {
			ERR("Unknown or duplicit option '%s', see --help",
					argv[i]);
			return KNOT_EINVAL;
		}
	}

	int n = snprintf(address, sizeof(address), "@%s@%s",
			 argv[i], argv[i + 1]);
	if (n < 0 || (size_t)n >= sizeof(address)) {
		ERR("address or port too long\n");
		return KNOT_EINVAL;
	}

	INFO("testing address: %s\n", address);

	#define c_u_t(test_fun) cmocka_unit_test_setup_teardown(test_fun, \
			setup_unit_test_state, test_cleanup)
	#define c_m_unit_test CMUnitTest

	const struct c_m_unit_test regular_query_test[] = {
		c_u_t(simple_sanity)
	};
	result = cmocka_run_group_tests_name(test_suite_names[SANITY_TESTS],
			regular_query_test, setup, teardown);
	if (result != 0) {
		ERR("Upstream failed to resolve a query send via DoQ, aborting tests, check that upstream is alive and accepts DoQ on '%s'",
				address);
		return result;
	}

	const struct c_m_unit_test stream_tests[] = {
		c_u_t(open_stream_and_timeout),
		c_u_t(stream_data_split_to_two_pkts),
		c_u_t(stream_data_split_to_ten_pkts),
		c_u_t(multiple_parallel_streams),
		c_u_t(send_one_byte_at_a_time),
		c_u_t(send_stream_reset_prefin),
	};
	result += cmocka_run_group_tests_name(test_suite_names[STREAM_TESTS],
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
	result += cmocka_run_group_tests_name(test_suite_names[PROTO_TESTS],
			proto_compliance_tests, setup, teardown);

	if (enable_manual) {
		const struct c_m_unit_test manual_verification_tests[] = {
			c_u_t(send_and_close),
			c_u_t(send_after_stop_sending),
			c_u_t(send_stream_reset_postfin),
		};
		result += cmocka_run_group_tests_name(
				test_suite_names[MANUAL_TESTS],
				manual_verification_tests, setup, teardown);
	}

	return result;
}
