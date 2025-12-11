/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <assert.h>
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
#include "utils/kdig_qtest/qtest_netio.h"
#include "utils/kdig_qtest/qtest_params.h"
#include "utils/kdig_qtest/qtest_kdig_params.h"
#include "utils/kdig_qtest/qtest_kdig_exec.h"
#include "libknot/libknot.h"
#include "utils/kdig_qtest/qtest_quic.h"
#include <pthread.h>
#include <string.h>

/* address and port where which is to be tested.
 * Requires the address syntax to be kdig compatible
 * i.e "@ipv4/6@port" */
#define TESTED_ADDRESS "@127.0.0.1@8853"

#define QUERIES_1_COUNT 1
#define QUERIES_3_COUNT 3
#define QUERIES_10_COUNT 10
#define QUERIES_MANY_COUT 239
#define QUERIES_1 "nic.cz"
#define QUERIES_3 "nic.cz", "nic.de", "ulaanbaatar.mn"
#define QUERIES_10 "ulaanbaatar.mn", "nic.cz", "nic.de", "venmo.com",\
"cern.ch", "adyen.com", "dlocal.com", "redis.io", "skrill.com", "paxum.com"
#define QUERIES_MANY "nic.cz", "nic.de", "ulaanbaatar.mn" \
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
#define CONN_COUNT 5

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

	// Loop over the number of retries.
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
		if (create_net(ctx->conns[i].params.config, ctx->conns[i].net) != KNOT_EOK) {
			goto loop_fail;
		}

		ctx->conns[i].net->quic.env = malloc(sizeof(struct test_env));
		if (!ctx->conns[i].net->quic.env) {
			goto loop_fail;
		}

		ctx->conns[i].net->quic.env->buf = calloc(1 << 16, sizeof(char));
		if (!ctx->conns[i].net->quic.env->buf) {
			goto loop_fail;
		}
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
	 * of connection for this test group */
	assert(ctx->flc + 1 < CONN_COUNT);
	++ctx->flc;
}

/* sanity check that all connections query the server correctly*/
static void simple_sanity(void **state)
{
	qtest_state_t *ctx = *state;
	for (int i = 0; i < CONN_COUNT; i++) {
		assert_int_equal(process_query(HEAD(ctx->conns[i].params.queries),
					ctx->conns[i].net), KNOT_EOK);
	}
}

static void open_stream_and_timeout(void **state)
{
	qtest_state_t *ctx = *state;
	ctx->conns[ctx->flc].net->cbs->quic_send_data = quic_send_data_test;
	ctx->conns[ctx->flc].net->quic.env->scenario = 1;

	/* query should fail */
	assert_int_equal(process_query(HEAD(ctx->conns[ctx->flc].params.queries),
				ctx->conns[ctx->flc].net), -1);
	assert_int_equal(ctx->conns[ctx->flc].net->quic.last_err.error_code, NGTCP2_ERR_IDLE_CLOSE);
	assert_int_equal(ctx->conns[ctx->flc].net->quic.state, CLOSED);
	burned_conn(ctx);
}

/* most DNS queries come in a single packet that opens the stream,
 * and contains the FIN flag as well. This test splits the payload */
static void stream_data_split_to_two_pkts(void **state)
{
	qtest_state_t *ctx = *state;
	reset_callbacks(ctx->conns[ctx->flc].net);
	ctx->conns[ctx->flc].net->cbs->quic_send_dns_query = quic_send_dns_query_split;
	ctx->conns[ctx->flc].net->cbs->quic_send_data = quic_send_data_split;

	ctx->conns[ctx->flc].net->quic.env->scenario = NGTCP2_WRITE_STREAM_FLAG_NONE;
	ctx->conns[ctx->flc].net->quic.env->counter = 2;
	/* FIXME: this test shouldn't terminate the connection
	 * it ends up in PROTOCOL ERROR for some reason */
	assert_int_equal(process_query(HEAD(ctx->conns[ctx->flc].params.queries),
				ctx->conns[ctx->flc].net), 0);
}

static void stream_data_split_to_ten_pkts(void **state)
{
	qtest_state_t *ctx = *state;
	reset_callbacks(ctx->conns[ctx->flc].net);
	ctx->conns[ctx->flc].net->cbs->quic_send_dns_query = quic_send_dns_query_split;
	ctx->conns[ctx->flc].net->cbs->quic_send_data = quic_send_data_split;
	ctx->conns[ctx->flc].net->quic.env->scenario = NGTCP2_WRITE_STREAM_FLAG_NONE;
	ctx->conns[ctx->flc].net->quic.env->counter = 10;

	assert_int_equal(process_query(HEAD(ctx->conns[ctx->flc].params.queries),
				ctx->conns[ctx->flc].net), 0);
}

/* By splitting the query into two and setting the scenario to FIN we'll only
 * send the first half of the query,
 * TODO: check that the server really doesn't have to send CONN_CLOSE
 * knot-resolver doesn't as of now */
static void stream_data_send_half_of_query(void **state)
{
	qtest_state_t *ctx = *state;
	ctx->conns[ctx->flc].net->cbs->quic_send_dns_query = quic_send_dns_query_split;
	ctx->conns[ctx->flc].net->cbs->quic_send_data = quic_send_data_split;
	ctx->conns[ctx->flc].net->quic.env->scenario = NGTCP2_WRITE_STREAM_FLAG_FIN;
	ctx->conns[ctx->flc].net->quic.env->counter = 2;

	assert_int_equal(process_query(HEAD(ctx->conns[ctx->flc].params.queries),
				ctx->conns[ctx->flc].net), -1);
	assert_int_equal(ctx->conns[ctx->flc].net->quic.last_err.error_code, NGTCP2_PROTOCOL_VIOLATION);
	burned_conn(ctx);
}

/* test multiple active streams which send their queries split in half
 * this test is quite pointless */
static void multiple_parallel_streams(void **state)
{
	qtest_state_t *ctx = *state;

	if (ctx->flc + 2 >= CONN_COUNT) {
		printf("Insufficient number of connection for this test, need >= 2");
		assert_true(false);
		return;
	}

	// ctx->conns[ctx->flc].net->cbs->ngtcp2_recv_stream_data_cb = recv_stream_data_ignore_all_but_0;
	ctx->conns[ctx->flc].net->cbs->quic_send_dns_query = quic_send_dns_query_sync;
	ctx->conns[ctx->flc].net->cbs->quic_send_data = quic_send_data_split;
	ctx->conns[ctx->flc].net->cbs->quic_recv = quic_recv_with_ack;
	ctx->conns[ctx->flc].net->quic.env->scenario = NGTCP2_WRITE_STREAM_FLAG_NONE;
	ctx->conns[ctx->flc].net->quic.env->counter = 2;
	assert_int_equal(process_query(HEAD(ctx->conns[ctx->flc].params.queries),
				ctx->conns[ctx->flc].net), 0);
}

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
		c_u_t(open_stream_and_timeout),
		c_u_t(stream_data_split_to_two_pkts),
		c_u_t(stream_data_split_to_ten_pkts),
		c_u_t(stream_data_send_half_of_query),
		c_u_t(multiple_parallel_streams),
	};

	return cmocka_run_group_tests(stream_tests, setup, teardown);
}
