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
#include "utils/kdig_qtest/qtest_netio.h"
#include "utils/kdig_qtest/qtest_params.h"
#include "utils/kdig_qtest/qtest_kdig_params.h"
#include "utils/kdig_qtest/qtest_kdig_exec.h"
#include "libknot/libknot.h"
#include "utils/kdig_qtest/qtest_quic.h"
#include <pthread.h>
#include <string.h>
#include <unistd.h>

/* Setting this to false will disable tests that require inspection of the
 * server state. Not all tests defined in this utility can be fully automated.
 * some require deep inspection of the server state, for these tests the result
 * only informs the user that the test was performed succesfully. These
 * are disabled for automated testing (e.g. CI/CD) to avoid confusion */
#define MANUAL_TESTING true

#define QUERIES_1_COUNT 1
#define QUERIES_3_COUNT 3
#define QUERIES_10_COUNT 10
#define QUERIES_MANY_COUT 239
#define QUERIES_1 "example.com"
#define QUERIES_3 "example.com", "nic.cz", "nic.de"
// #define QUERIES_10 "example.com", "ulaanbaatar.mn", "nic.cz", "venmo.com",\
// "cern.ch", "adyen.com", "dlocal.com", "redis.io", "skrill.com", "paxum.com"
#define QUERIES_10 "domreg.net.fj", "ulaanbaatar.mn", "nic.cz", "venmo.com",\
"cern.ch", "adyen.com", "dlocal.com", "redis.io", "skrill.com", "paxum.com"
#define QUERIES_MANY "nic.cz", "nic.de", "ulaanbaatar.mn", \
"venmo.com", "zellepay.com", "adyen.com", "dlocal.com", "braintreepayments.com", \
"skrill.com", "paxum.com", "neteller.com", "remitly.com", "worldremit.com", \
"moneygram.com", "westernunion.com", "numpy.org", "pandas.pydata.org", \
"databricks.com", "snowflake.com", "tableau.com", "powerbi.com", "qlik.com", \
"splunk.com", "elastic.co", "mongodb.com", "cassandra.apache.org", \
"postgresql.org", "mysql.com", "mariadb.com", "redis.io", "apache.org", \
"nginx.com", "tomcat.apache.org", "societegenerale.com", "unicreditgroup.eu", \
"credit-suisse.com", "ubs.com", "ing.com", "capitalone.com", "pnc.com", \
"turbotax.intuit.com", "dell.com", "adtax.com", "xerox.com", "docusign.com", \
"house.gov", "nato.int", "iaea.org", "oecd.org", "wto.org", "imf.org", \
"worldbank.org", "esa.int", "esa.org", "cern.ch", "jaxa.jp", "spacex.com", \
"blueorigin.com", "virgingalactic.com", "rocketlabusa.com", "thespacestore.com", \
"livechat.com", "zendesk.com", "google.com", "cloudflare.com", "example.com", \
"nic.cz", "seznam.cz", "kosice.sk", "ulaanbaatar.mn", "ars.electronica.art", \
"www.joburg.org.za", "amazon.com", "microsoft.com", "apple.com", "github.com", \
"facebook.com", "twitter.com", "linkedin.com", "netflix.com", "usa.gov", \
"gov.uk", "europa.eu", "canada.ca", "gov.in", "gov.au", "gov.sg", "house.gov", \
"nato.int", "iaea.org", "oecd.org", "wto.org", "imf.org", "worldbank.org", \
"esa.int", "esa.org", "cern.ch", "jaxa.jp", "spacex.com", "blueorigin.com", \
"virgingalactic.com", "rocketlabusa.com", "thespacestore.com", "livechat.com", \
"zendesk.com", "helpscout.com", "freshdesk.com", "intercom.com", "genesys.com", \
"avaya.com", "twilio.com", "ringcentral.com", "zoom.us", "logitech.com", \
"poly.com", "clearbit.com", "hubspot.com", "bbc.com", "nytimes.com", "cnn.com", \
"aljazeera.com", "reuters.com", "forbes.com", "braintreepayments.com", \
"skrill.com", "paxum.com", "neteller.com", "remitly.com", "worldremit.com", \
"moneygram.com", "westernunion.com", "numpy.org", "pandas.pydata.org", \
"databricks.com", "snowflake.com", "tableau.com", "powerbi.com", "qlik.com", \
"splunk.com", "elastic.co", "mongodb.com", "cassandra.apache.org", \
"postgresql.org", "mysql.com", "mariadb.com", "redis.io", "apache.org", \
"nginx.com", "tomcat.apache.org", "societegenerale.com", "unicreditgroup.eu", \
"credit-suisse.com", "ubs.com", "ing.com", "capitalone.com", "pnc.com", \
"turbotax.intuit.com", "dell.com", "adtax.com", "xerox.com", "docusign.com", \
"house.gov", "nato.int", "iaea.org", "oecd.org", "wto.org", "imf.org", \
"worldbank.org", "esa.int", "esa.org", "cern.ch", "jaxa.jp", "spacex.com", \
"blueorigin.com", "virgingalactic.com", "rocketlabusa.com", "thespacestore.com", \
"livechat.com", "zendesk.com", "google.com", "cloudflare.com", "example.com", \
"nic.cz", "seznam.cz", "kosice.sk", "ulaanbaatar.mn", "ars.electronica.art", \
"www.joburg.org.za", "amazon.com", "microsoft.com", "apple.com", "github.com", \
"facebook.com", "twitter.com", "linkedin.com", "netflix.com", "usa.gov", \
"gov.uk", "europa.eu", "canada.ca", "gov.in", "gov.au", "gov.sg", "house.gov", \
"nato.int", "iaea.org", "oecd.org", "wto.org", "imf.org", "worldbank.org", \
"esa.int", "esa.org", "cern.ch", "jaxa.jp", "spacex.com", "blueorigin.com", \
"virgingalactic.com", "rocketlabusa.com", "thespacestore.com", "livechat.com", \
"zendesk.com", "helpscout.com", "freshdesk.com", "intercom.com", "genesys.com", \
"avaya.com", "twilio.com", "ringcentral.com", "zoom.us", "logitech.com", \
"poly.com", "clearbit.com", "hubspot.com", "bbc.com", "nytimes.com", "cnn.com", \
"aljazeera.com", "reuters.com", "forbes.com"

/* how many connection will be open for each unit test group.
 * Some tests are designed to close the connection, it is simpler
 * to create more connections and just use the next once the
 * terminal test finishes */
#define CONN_COUNT 10

#define ENV_BUF_SIZE (1 << 16)

/* Global variable is ugly, but cmocka setup doesn't allow
 * arguments so this is an acceptable hack for now */
static char address[INET6_ADDRSTRLEN + 6/* port */ + 2/* @ chars */] = "@";

typedef struct net_ctx {
	net_t *net;
	kdig_params_t params;
} net_ctx_t;

typedef struct qtest_state {
	net_ctx_t *conns;
	/* idx of the current conn, tests that terminate the connection
	 * should use burned_conn() to increment this value */
	size_t flc;
	size_t counter;
} qtest_state_t;

int create_net(const query_t *query, net_t *net)
{
	node_t *server;
	int ret;

	// Get connection parameters.
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

static void reset_callbacks(net_t *net)
{
	net->cbs->tls_ctx_setup_remote_endpoint = tls_ctx_setup_remote_endpoint;
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


static int setup(void **state)
{
	int i = 0;
	int ret = KNOT_ENOMEM;
	net_t *uc_net = NULL;
	query_t *uc_query = NULL;
	qtest_state_t *ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		goto fail;

	ctx->conns = calloc(CONN_COUNT, sizeof(struct net_ctx));
	if (!ctx->conns) {
		goto fail;
	}

	int uc_argc = 3 + QUERIES_10_COUNT;
	char *uc_argv[] = {
		"", /* not relevant */
		"+quic",
		address,
		QUERIES_10
	};

	dnssec_crypto_init();
	for (; i < CONN_COUNT; i++) {
		if ((ret = kdig_parse(&ctx->conns[i].params, uc_argc, uc_argv,
					uc_query)) != KNOT_EOK) {
			dnssec_crypto_cleanup();
			goto fail;
		}

		ctx->conns[i].net = calloc(1, sizeof(*uc_net));
		if (!ctx->conns[i].net) {
			goto loop_fail;
		}

		ctx->conns[i].net->sockfd = -1;
		if (create_net(ctx->conns[i].params.config, ctx->conns[i].net)
				!= KNOT_EOK) {
			goto loop_fail;
		}

		ctx->conns[i].net->quic.env =
			calloc(1, sizeof(struct test_env));
		if (!ctx->conns[i].net->quic.env) {
			goto loop_fail;
		}

		ctx->conns[i].net->quic.env->buf =
			calloc(ENV_BUF_SIZE, sizeof(char));
		if (!ctx->conns[i].net->quic.env->buf) {
			goto loop_fail;
		}
		ctx->conns[i].net->quic.env->bufsize = ENV_BUF_SIZE;
		ctx->conns[i].net->quic.env->bufend = 0;
		reset_callbacks(ctx->conns[i].net);
	}

	*state = ctx;
	return KNOT_EOK;

loop_fail:
	dnssec_crypto_cleanup();
	kdig_clean(&ctx->conns[i].params);

	if (ctx->conns[i].net) {
		if (ctx->conns[i].net->quic.env) {
			if (ctx->conns[i].net->quic.env->buf) {
				free(ctx->conns[i].net->quic.env->buf);
			}
			free(ctx->conns[i].net->quic.env);
		}
		net_clean(ctx->conns[i].net);
		free(ctx->conns[i].net);
	}

fail:
	if (ctx->conns) {
		for (int k = 0; k < i; k++) {
			if (ctx->conns[k].net->quic.env) {
				free(ctx->conns[k].net->quic.env->buf);
				free(ctx->conns[k].net->quic.env);
			}

			kdig_clean(&ctx->conns[i].params);
			net_clean(ctx->conns[k].net);
			free(ctx->conns[k].net);
		}

		free(ctx->conns);
	}

	if (ctx)
		free(ctx);

	*state = NULL;
	return ret;
}

static int teardown(void **state)
{
	if (!*state)
		return KNOT_EOK;

	qtest_state_t *ctx = *state;
	dnssec_crypto_cleanup();

	for (int i = 0; i < CONN_COUNT; i++) {
		free(ctx->conns[i].net->quic.env->buf);
		free(ctx->conns[i].net->quic.env);
		net_close(ctx->conns[i].net);
		net_clean(ctx->conns[i].net);
		free(ctx->conns[i].net);
		kdig_clean(&ctx->conns[i].params);
	}

	free(ctx->conns);
	free(*state);
	*state = NULL;

	return KNOT_EOK;
}

static void burned_conn(qtest_state_t *ctx)
{
	/* The enrite program should fail if we have insufficient number
	 * of connections for this test group */
	if (ctx->flc + 1 < CONN_COUNT) {
		WARN("Insufficient number of conns for the run tests, either some test killed the connection unexpectedly or programming error.");
		/* TODO cleaner death */
		assert(false);
	}
	++ctx->flc;
}


/*****************************************************************************
* 				Automated tests
******************************************************************************/

/* sanity check that all connections are able to query the server. */
static void simple_sanity(void **state)
{
	qtest_state_t *ctx = *state;
	for (int i = 0; i < CONN_COUNT; i++) {
		assert_int_equal(process_query(
					HEAD(ctx->conns[i].params.queries),
					ctx->conns[i].net), KNOT_EOK);
		reset_conn_state(ctx->conns[i].net);
	}
}

static void open_stream_and_timeout(void **state)
{
	qtest_state_t *ctx = *state;
	ctx->conns[ctx->flc].net->cbs->quic_send_data = quic_send_data_test;
	ctx->conns[ctx->flc].net->quic.env->scenario = 1;

	/* query should fail */
	assert_int_equal(process_query(
				HEAD(ctx->conns[ctx->flc].params.queries),
				ctx->conns[ctx->flc].net), -1);
	assert_int_equal(ctx->conns[ctx->flc].net->quic.last_err.error_code,
			NGTCP2_ERR_IDLE_CLOSE);
	// assert_int_equal(ctx->conns[ctx->flc].net->quic.state, CLOSED);
	burned_conn(ctx);
}

/* most DNS queries come in a single packet that opens the stream,
 * and contains the FIN flag as well. This test splits the payload */
static void stream_data_split_to_two_pkts(void **state)
{
	qtest_state_t *ctx = *state;
	reset_callbacks(ctx->conns[ctx->flc].net);
	ctx->conns[ctx->flc].net->cbs->quic_send_dns_query =
		quic_send_dns_query_split;
	ctx->conns[ctx->flc].net->cbs->quic_send_data = quic_send_data_split;

	ctx->conns[ctx->flc].net->quic.env->scenario =
		NGTCP2_WRITE_STREAM_FLAG_NONE;
	ctx->conns[ctx->flc].net->quic.env->counter = 2;
	/* FIXME: this test shouldn't terminate the connection
	 * it ends up in PROTOCOL ERROR for some reason */
	assert_int_equal(process_query(
				HEAD(ctx->conns[ctx->flc].params.queries),
				ctx->conns[ctx->flc].net), 0);
	reset_conn_state(ctx->conns[ctx->flc].net);
}

static void stream_data_split_to_ten_pkts(void **state)
{
	qtest_state_t *ctx = *state;
	reset_callbacks(ctx->conns[ctx->flc].net);
	ctx->conns[ctx->flc].net->cbs->quic_send_dns_query =
		quic_send_dns_query_split;
	ctx->conns[ctx->flc].net->cbs->quic_send_data = quic_send_data_split;
	ctx->conns[ctx->flc].net->quic.env->scenario =
		NGTCP2_WRITE_STREAM_FLAG_NONE;
	ctx->conns[ctx->flc].net->quic.env->counter = 10;

	assert_int_equal(process_query(
				HEAD(ctx->conns[ctx->flc].params.queries),
				ctx->conns[ctx->flc].net), 0);
	reset_conn_state(ctx->conns[ctx->flc].net);

	burned_conn(ctx);
}

/* By splitting the query into two and setting the scenario to FIN we'll only
 * send the first half of the query */
static void stream_data_send_half_of_query(void **state)
{
	qtest_state_t *ctx = *state;
	reset_callbacks(ctx->conns[ctx->flc].net);
	ctx->conns[ctx->flc].net->cbs->quic_send_dns_query =
		quic_send_dns_query_split;
	ctx->conns[ctx->flc].net->cbs->quic_send_data = quic_send_data_split;
	ctx->conns[ctx->flc].net->cbs->quic_recv =
		quic_recv_close_doq_error;
	ctx->conns[ctx->flc].net->quic.env->scenario =
		NGTCP2_WRITE_STREAM_FLAG_FIN;
	ctx->conns[ctx->flc].net->quic.env->scenario = DOQ_PROTOCOL_ERROR;
	ctx->conns[ctx->flc].net->quic.env->counter = 2;
	assert(ctx->conns[ctx->flc].net->quic.env->extra == 0);
	ctx->conns[ctx->flc].net->quic.env->extra = TEST_SEND_ONE_PAYLOAD;

	assert_int_equal(process_query(
				HEAD(ctx->conns[ctx->flc].params.queries),
				ctx->conns[ctx->flc].net), -1);
	assert_int_equal(ctx->conns[ctx->flc].net->quic.last_err.error_code,
			DOQ_PROTOCOL_ERROR);
	burned_conn(ctx);
}

/* test multiple active streams which send their queries split in half
 * this test is quite pointless. This test doesn't work as there is
 * a lot of missing code for handligh multiple streams. you can run it
 * and ispect the server that it actually accepted N streams, resolved the
 * queries and attemped to send the answers to the N streams.
 * if this functionality is ever added replace the asserted
 * return code from -1 back to 0 */
static void multiple_parallel_streams(void **state)
{
	qtest_state_t *ctx = *state;

	if (ctx->flc + 2 >= CONN_COUNT) {
		printf("Insufficient number of connection for this test, need >= 2");
		assert_true(false);
		return;
	}

	ctx->conns[ctx->flc].net->cbs->quic_send_dns_query =
		quic_send_dns_query_sync;
	ctx->conns[ctx->flc].net->cbs->quic_send_data = quic_send_data_split;
	ctx->conns[ctx->flc].net->cbs->quic_recv = quic_recv_with_ack;
	ctx->conns[ctx->flc].net->quic.env->scenario =
		NGTCP2_WRITE_STREAM_FLAG_NONE;
	ctx->conns[ctx->flc].net->quic.env->counter = 2;

	/* FIXME I do not really remember what this checks but it fails
	 * when qtest tests unbound */
	assert_int_equal(ctx->conns[ctx->flc].net->quic.env->extra, 0);

	assert_int_equal(process_query(
				HEAD(ctx->conns[ctx->flc].params.queries),
				ctx->conns[ctx->flc].net), -1/*shoudl be 0 but this test is unfinished*/);
	reset_conn_state(ctx->conns[ctx->flc].net);

	burned_conn(ctx);
}

static void send_one_byte_at_a_time(void **state)
{
	qtest_state_t *ctx = *state;

	if (ctx->flc + 1 >= CONN_COUNT) {
		printf("Insufficient number of connection for this test, need >= 1");
		assert_true(false);
		return;
	}

	reset_callbacks(ctx->conns[ctx->flc].net);
	ctx->conns[ctx->flc].net->cbs->quic_send_dns_query =
		quic_send_dns_query_split;
	ctx->conns[ctx->flc].net->cbs->quic_send_data =
		quic_send_data_split;
	ctx->conns[ctx->flc].net->quic.env->scenario =
		NGTCP2_WRITE_STREAM_FLAG_NONE;
	/* -1 means send one byte at a time */
	ctx->conns[ctx->flc].net->quic.env->counter = -1;

	assert_int_equal(process_query(
				HEAD(ctx->conns[ctx->flc].params.queries),
				ctx->conns[ctx->flc].net), 0);
	reset_conn_state(ctx->conns[ctx->flc].net);

	burned_conn(ctx);
}

/* this test attempts to reach the limits of the congestion control window.
 * it expects both the remote and local endpoints to increase these limits
 * since sending a large amount. */
static void test_stream_data_extension(void **state)
{
	qtest_state_t *ctx = *state;
	reset_callbacks(ctx->conns[ctx->flc].net);
	ssize_t pld_size = (1 << 16) - (1 << 10);
	assert(ctx->conns[ctx->flc].net->quic.env->bufsize >= pld_size);
	memset(&ctx->conns[ctx->flc].net->quic.env->buf, 0x0, pld_size);
	knot_wire_write_u16((uint8_t *)ctx->conns[ctx->flc].net->quic.env->buf,
			pld_size - 2);
	ctx->conns[ctx->flc].net->quic.env->bufend = pld_size;
}

/* Check the handling of a situation where a server receives
 * less data than advertised in the size prefix, should result
 * in a CONNECTION_CLOSE frame with DOQ_PROTOCOL_ERROR, but really
 * only should, silent con termination is also acceptable according to RFC 9250
 *
 * This and the subsequert test use env->extra to store the
 * value that is to be added or subracted from the size_prefix */
static void send_less_data_than_size_prefix(void **state)
{
	qtest_state_t *ctx = *state;
	reset_callbacks(ctx->conns[ctx->flc].net);
	ctx->conns[ctx->flc].net->cbs->quic_send_dns_query =
		quic_send_dns_query_wrong_size_prefix;
	ctx->conns[ctx->flc].net->cbs->quic_recv =
		quic_recv_close_doq_error;
	ctx->conns[ctx->flc].net->quic.env->extra = 50;
	ctx->conns[ctx->flc].net->quic.env->scenario = DOQ_PROTOCOL_ERROR;

	assert_int_equal(process_query(
				HEAD(ctx->conns[ctx->flc].params.queries),
				ctx->conns[ctx->flc].net), -1);
	assert_int_equal(ctx->conns[ctx->flc].net->quic.env->extra,
			RECEIVED_CLOSE_MAGIC);
	burned_conn(ctx);
}

/* Same as above but send more */
static void send_more_data_than_size_prefix(void **state)
{
	qtest_state_t *ctx = *state;
	reset_callbacks(ctx->conns[ctx->flc].net);
	ctx->conns[ctx->flc].net->cbs->quic_send_dns_query =
		quic_send_dns_query_wrong_size_prefix;
	ctx->conns[ctx->flc].net->cbs->quic_recv =
		quic_recv_close_doq_error;
	ctx->conns[ctx->flc].net->quic.env->extra = -50;
	ctx->conns[ctx->flc].net->quic.env->scenario = DOQ_PROTOCOL_ERROR;

	assert_int_equal(process_query(
				HEAD(ctx->conns[ctx->flc].params.queries),
				ctx->conns[ctx->flc].net), -1);
	assert_int_equal(ctx->conns[ctx->flc].net->quic.env->extra,
			RECEIVED_CLOSE_MAGIC);
	burned_conn(ctx);
}

/* This test is anomalous and should not be used! */
static void send_only_initial(void **state)
{
	qtest_state_t *ctx = *state;
	reset_callbacks(ctx->conns[ctx->flc].net);
	ctx->conns[ctx->flc].net->cbs->quic_ctx_connect =
		quic_ctx_connect_only_initial;
	ctx->conns[ctx->flc].net->cbs->quic_recv =
		quic_recv_close_doq_error;
	ctx->conns[ctx->flc].net->quic.env->scenario = DOQ_NO_ERROR;

	assert_int_equal(process_query(
				HEAD(ctx->conns[ctx->flc].params.queries),
				ctx->conns[ctx->flc].net), -1);
	assert_int_equal(ctx->conns[ctx->flc].net->quic.env->extra,
			RECEIVED_CLOSE_MAGIC);
	burned_conn(ctx);
}

/* This test sends the first half of tha payload and right after that
 * sends RESET_STREAM. The peer (server) should in that point ACK the reset
 * and silently terminate the DNS request and delete the stream state. */
static void send_stream_reset_prefin(void **state)
{
	qtest_state_t *ctx = *state;
	reset_callbacks(ctx->conns[ctx->flc].net);
	ctx->conns[ctx->flc].net->cbs->quic_send_data =
		quic_send_data_split_reset_stream;
	ctx->conns[ctx->flc].net->cbs->quic_send_dns_query =
		quic_send_dns_query_split;
	ctx->conns[ctx->flc].net->quic.env->scenario =
		NGTCP2_WRITE_STREAM_FLAG_NONE;
	assert_int_equal(process_query(
				HEAD(ctx->conns[ctx->flc].params.queries),
				ctx->conns[ctx->flc].net), -1);
	burned_conn(ctx);
}

/* Same as send_stream_reset_prefin but sends the entire payload including
 * the FIN flag prior to sending RESET_STREAM.
 * WARNING: This test requires the tested upstream to delay its answer.
 * Ideally configure your setup such that it forwards to a dead 'up'upstream,
 * meaning there will be several seconds to transmit the reset stream before
 * the tested upstream responds with an answer of SERVFAIL. */
static void send_stream_reset_postfin(void **state)
{
	qtest_state_t *ctx = *state;
	reset_callbacks(ctx->conns[ctx->flc].net);
	ctx->conns[ctx->flc].net->cbs->quic_send_data =
		quic_send_data_split_reset_stream;
	ctx->conns[ctx->flc].net->cbs->quic_send_dns_query =
		quic_send_dns_query;
	ctx->conns[ctx->flc].net->quic.env->scenario =
		NGTCP2_WRITE_STREAM_FLAG_FIN;
	assert_int_equal(process_query(
				HEAD(ctx->conns[ctx->flc].params.queries),
				ctx->conns[ctx->flc].net), -1);
	burned_conn(ctx);
}

/*****************************************************************************
* 		Tests that require manual verification
******************************************************************************/

/* This test is supposted to test the state handling
 * of an abandoned stream. Disable the test or create such a setup in which
 * the tested resolver takes a long time to receive (but eventually it does
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
	qtest_state_t *ctx = *state;
	reset_callbacks(ctx->conns[ctx->flc].net);
	ctx->conns[ctx->flc].net->cbs->quic_send_data =
		quic_send_data_terminate;
	ctx->conns[ctx->flc].net->cbs->quic_send_dns_query =
		quic_send_dns_query_terminate;
	ctx->conns[ctx->flc].net->quic.env->scenario =
		NGTCP2_WRITE_STREAM_FLAG_NONE;
	assert_int_equal(process_query(
				HEAD(ctx->conns[ctx->flc].params.queries),
				ctx->conns[ctx->flc].net), -1);
	burned_conn(ctx);
}

/* This test is not able to correctly verify the result. a success of this
 * test is ONLY A HINT that the test might have been performed correctly.
 * The verification of the result is up to the programmer. the correct behaviour
 * is for the server to respond to the initial RESET_STREAM by stopping the
 * transaction as stated in RFC 9250 4.3.1.  Transaction Cancellation.
 * The server should also handle the fact that the client maliciosly
 * transports a stream frame after the STOP_SENDING frame. */
static void send_after_stop_sending(void **state)
{
	qtest_state_t *ctx = *state;
	reset_callbacks(ctx->conns[ctx->flc].net);
	ctx->conns[ctx->flc].net->cbs->net_receive = net_receive_fail_ok;
	ctx->conns[ctx->flc].net->cbs->quic_send_data = quic_send_data_split;
	ctx->conns[ctx->flc].net->cbs->quic_send_dns_query =
		quic_send_dns_query_stop_sending;
	ctx->conns[ctx->flc].net->cbs->quic_stream_reset_cb =
		stream_reset_cb_malicious_survival;
	ctx->conns[ctx->flc].net->quic.env->scenario =
		NGTCP2_WRITE_STREAM_FLAG_NONE;
	ctx->conns[ctx->flc].net->quic.env->counter = 2;
	assert_int_equal(process_query(
				HEAD(ctx->conns[ctx->flc].params.queries),
				ctx->conns[ctx->flc].net), 0);
	burned_conn(ctx);
}

static void client_send_stateless_reset(void **state)
{
	qtest_state_t *ctx = *state;
	reset_callbacks(ctx->conns[ctx->flc].net);
	ctx->conns[ctx->flc].net->cbs->quic_recv_dns_response =
		quic_maybe_send_stateless_reset;
	ctx->conns[ctx->flc].net->quic.env->scenario =
		NGTCP2_WRITE_STREAM_FLAG_NONE;
	assert_int_equal(process_query(
				HEAD(ctx->conns[ctx->flc].params.queries),
				ctx->conns[ctx->flc].net), 0);
	burned_conn(ctx);
}

/* Every test has to have as the very last line either of the following
 * Option 1: // The test is expected to terminate the connection
 * 	burned_conn(ctx);
 * Option 2: // The conn should survive the test and the env variables are to be reset
 * 	reset_conn_state(ctx->conns[ctx->flc].net);
 */
int main(int argc, char *argv[])
{
	if (argc == 2 && (strcmp(argv[0], "--help") || strcmp(argv[0], "-h"))) {
		printf("qtest address port     qtest requires an address and a port of the DoQ server that is to be tested\n");
		printf("qtest --help displays this help message\n");
		return KNOT_EINVAL;
	}

	if (argc != 3) {
		printf("Invalid number of arguments, see --help\n");
		return KNOT_EINVAL;
	}

	size_t addrlen = strlen(argv[1]);
	size_t portlen = strlen(argv[2]);
	strncpy(address + 1, argv[1], addrlen);
	address[addrlen + 1] = '@';
	strncpy(address + 1 + addrlen + 1, argv[2], portlen);

	printf("testing address: %s\n", address);

	#define c_u_t(x) cmocka_unit_test(x)
	#define c_m_unit_test CMUnitTest
	const struct c_m_unit_test stream_tests[] = {
		c_u_t(simple_sanity),
		/* Causes timeout issues for the precreated conns, that part has
		 * to be fixed, therefore TODO: Create conns per started test,
		 * not in advance! */
		// c_u_t(open_stream_and_timeout),
		c_u_t(stream_data_split_to_two_pkts),
		c_u_t(stream_data_split_to_ten_pkts),
		c_u_t(stream_data_send_half_of_query),
		c_u_t(multiple_parallel_streams),
		c_u_t(send_one_byte_at_a_time),
		// c_u_t(test_stream_data_extension),
		c_u_t(send_less_data_than_size_prefix),
		c_u_t(send_more_data_than_size_prefix),
		// /* This test is anomalous and should not be used! */
		// // c_u_t(send_only_initial),
		c_u_t(send_stream_reset_prefin),
		c_u_t(send_stream_reset_postfin),
#if MANUAL_TESTING
		// c_u_t(send_and_close),
		// c_u_t(send_after_stop_sending),
		// c_u_t(client_send_stateless_reset),
#if ENABLE_SLOWLORIS_TEST
		c_u_t(slowloris_test),
#endif /* ENABLE_SLOWLORIS_TEST */
#endif /* MANUAL_TESTING */
	};

	return cmocka_run_group_tests(stream_tests, setup, teardown);
}
