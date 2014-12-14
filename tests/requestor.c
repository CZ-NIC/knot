/*  Copyright (C) 2013 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <tap/basic.h>
#include <string.h>
#include <stdlib.h>

#include "libknot/internal/mempool.h"
#include "libknot/processing/layer.h"
#include "libknot/processing/requestor.h"
#include "fake_server.h"

/* @note Purpose of this test is not to verify process_answer functionality,
 *       but simply if the requesting/receiving works, so mirror is okay. */
static int reset(knot_layer_t *ctx) { return KNOT_NS_PROC_FULL; }
static int begin(knot_layer_t *ctx, void *module_param) { return reset(ctx); }
static int finish(knot_layer_t *ctx) { return KNOT_NS_PROC_NOOP; }
static int in(knot_layer_t *ctx, knot_pkt_t *pkt) { return KNOT_NS_PROC_DONE; }
static int out(knot_layer_t *ctx, knot_pkt_t *pkt) { return KNOT_NS_PROC_MORE; }

/*! \brief Dummy answer processing module. */
const knot_layer_api_t dummy_module = {
        &begin, &reset, &finish,
        &in, &out, &knot_layer_noop
};

static void* responder_thread(void *arg)
{
	int fd = *((int *)arg);
	uint8_t buf[KNOT_WIRE_MAX_PKTSIZE];
	while(true) {
		int client = accept(fd, NULL, NULL);
		if (client < 0) {
			break;
		}
		int len = tcp_recv_msg(client, buf, sizeof(buf), NULL);
		if (len < KNOT_WIRE_HEADER_SIZE) {
			close(client);
			break;
		}
		knot_wire_set_qr(buf);
		tcp_send_msg(client, buf, len);
		close(client);
	}
	return NULL;
}

/* Test implementations. */

#define DISCONNECTED_TESTS 2
#define CONNECTED_TESTS    4
#define TESTS_COUNT DISCONNECTED_TESTS + CONNECTED_TESTS

static struct knot_request *make_query(struct knot_requestor *requestor,  conf_iface_t *remote)
{
	knot_pkt_t *pkt = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, requestor->mm);
	assert(pkt);
	knot_pkt_put_question(pkt, ROOT_DNAME, KNOT_CLASS_IN, KNOT_RRTYPE_SOA);

	const struct sockaddr *dst = (const struct sockaddr *)&remote->addr;
	const struct sockaddr *src = (const struct sockaddr *)&remote->via;
	return knot_request_make(requestor->mm, dst, src, pkt, 0);
}

static void test_disconnected(struct knot_requestor *requestor, conf_iface_t *remote)
{
	/* Enqueue packet. */
	int ret = knot_requestor_enqueue(requestor, make_query(requestor, remote));
	is_int(KNOT_ECONN, ret, "requestor: disconnected/enqueue");

	/* Wait for completion. */
	struct timeval tv = { 5, 0 };
	ret = knot_requestor_exec(requestor, &tv);
	is_int(KNOT_ENOENT, ret, "requestor: disconnected/wait");
}

static void test_connected(struct knot_requestor *requestor, conf_iface_t *remote)
{
	/* Enqueue packet. */
	int ret = knot_requestor_enqueue(requestor, make_query(requestor, remote));
	is_int(KNOT_EOK, ret, "requestor: connected/enqueue");

	/* Wait for completion. */
	struct timeval tv = { 5, 0 };
	ret = knot_requestor_exec(requestor, &tv);
	is_int(KNOT_EOK, ret, "requestor: connected/wait");

	/* Enqueue multiple queries. */
	ret = KNOT_EOK;
	for (unsigned i = 0; i < 10; ++i) {
		ret |= knot_requestor_enqueue(requestor, make_query(requestor, remote));
	}
	is_int(KNOT_EOK, ret, "requestor: multiple enqueue");

	/* Wait for multiple queries. */
	ret = KNOT_EOK;
	for (unsigned i = 0; i < 10; ++i) {
		struct timeval tv = { 5, 0 };
		ret |= knot_requestor_exec(requestor, &tv);
	}
	is_int(KNOT_EOK, ret, "requestor: multiple wait");
}

int main(int argc, char *argv[])
{
	plan(TESTS_COUNT + 1);

	mm_ctx_t mm;
	mm_ctx_mempool(&mm, MM_DEFAULT_BLKSIZE);

	conf_iface_t remote;
	memset(&remote, 0, sizeof(conf_iface_t));
	sockaddr_set(&remote.addr, AF_INET, "127.0.0.1", 0);
	sockaddr_set(&remote.via, AF_INET, "127.0.0.1", 0);

	/* Create fake server environment. */
	server_t server;
	int ret = create_fake_server(&server, &mm);
	ok(ret == KNOT_EOK, "requestor: initialize fake server");

	/* Initialize requestor. */
	struct knot_requestor requestor;
	knot_requestor_init(&requestor, &mm);
	knot_requestor_overlay(&requestor, &dummy_module, NULL);

	/* Test requestor in disconnected environment. */
	test_disconnected(&requestor, &remote);

	/* Bind to random port. */
	int origin_fd = net_bound_socket(SOCK_STREAM, &remote.addr);
	assert(origin_fd > 0);
	socklen_t addr_len = sockaddr_len((struct sockaddr *)&remote.addr);
	getsockname(origin_fd, (struct sockaddr *)&remote.addr, &addr_len);
	ret = listen(origin_fd, 10);
	assert(ret == 0);

	/* Responder thread. */
	pthread_t thread;
	pthread_create(&thread, 0, responder_thread, &origin_fd);

	/* Test requestor in connected environment. */
	test_connected(&requestor, &remote);

	/*! \todo #243 TSIG secured requests test should be implemented. */

	/* Terminate responder. */
	int responder = net_connected_socket(SOCK_STREAM, &remote.addr, NULL, 0);
	assert(responder > 0);
	tcp_send_msg(responder, (const uint8_t *)"", 1);
	(void) pthread_join(thread, 0);
	close(responder);

	/* Close requestor. */
	knot_requestor_clear(&requestor);
	close(origin_fd);

	/* Cleanup. */
	mp_delete((struct mempool *)mm.ctx);
	server_deinit(&server);

	return 0;
}
