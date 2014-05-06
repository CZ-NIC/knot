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

#include <config.h>
#include <tap/basic.h>
#include <string.h>
#include <stdlib.h>

#include "common/mempool.h"
#include "libknot/processing/process.h"
#include "knot/nameserver/requestor.h"
#include "knot/server/tcp-handler.h"
#include "fake_server.h"

/* @note Purpose of this test is not to verify process_answer functionality,
 *       but simply if the requesting/receiving works, so mirror is okay. */
static int begin(knot_process_t *ctx, void *module_param) { return NS_PROC_MORE; }
static int answer(knot_pkt_t *pkt, knot_process_t *ctx) { return NS_PROC_DONE; }
static int reset(knot_process_t *ctx) { return NS_PROC_NOOP; }
static int noop(knot_pkt_t *pkt, knot_process_t *ctx) { return NS_PROC_NOOP; }

/*! \brief Dummy answer processing module. */
const knot_process_module_t dummy_module = {
        &begin, &reset, &reset, &answer, &noop, &noop
};

static void* responder_thread(void *arg)
{
	int fd = *((int *)arg);
	uint8_t buf[KNOT_WIRE_MAX_PKTSIZE];
	while(true) {
		int client = tcp_accept(fd);
		if (client < 0) {
			break;
		}
		int len = tcp_recv(client, buf, sizeof(buf), NULL);
		if (len < KNOT_WIRE_HEADER_SIZE) {
			close(client);
			break;
		}
		knot_wire_set_qr(buf);
		tcp_send(client, buf, len);
		close(client);
	}
	return NULL;
}

/* Test implementations. */

#define DISCONNECTED_TESTS 2
#define CONNECTED_TESTS    4
#define TESTS_COUNT DISCONNECTED_TESTS + CONNECTED_TESTS

static struct request *make_query(struct requestor *requestor, struct sockaddr_storage *remote)
{
	knot_pkt_t *pkt = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, requestor->mm);
	assert(pkt);
	knot_pkt_put_question(pkt, ROOT_DNAME, KNOT_CLASS_IN, KNOT_RRTYPE_SOA);

	conf_iface_t iface;
	memset(&iface, 0, sizeof(conf_iface_t));
	memcpy(&iface.addr, remote, sizeof(struct sockaddr_storage));
	sockaddr_set(&iface.via, AF_UNSPEC, "", 0);

	return requestor_make(requestor, &iface, pkt);
}

static void test_disconnected(struct requestor *requestor, struct sockaddr_storage *remote)
{
	/* Enqueue packet. */
	int ret = requestor_enqueue(requestor, make_query(requestor, remote), NULL);
	is_int(KNOT_EOK, ret, "requestor: disconnected/enqueue");

	/* Wait for completion. */
	struct timeval tv = { 5, 0 };
	ret = requestor_exec(requestor, &tv);
	is_int(KNOT_ECONNREFUSED, ret, "requestor: disconnected/wait");
}

static void test_connected(struct requestor *requestor, struct sockaddr_storage *remote)
{
	/* Enqueue packet. */
	int ret = requestor_enqueue(requestor, make_query(requestor, remote), NULL);;
	is_int(KNOT_EOK, ret, "requestor: connected/enqueue");

	/* Wait for completion. */
	struct timeval tv = { 5, 0 };
	ret = requestor_exec(requestor, &tv);
	is_int(KNOT_EOK, ret, "requestor: connected/wait");

	/* Enqueue multiple queries. */
	ret = KNOT_EOK;
	for (unsigned i = 0; i < 10; ++i) {
		ret |= requestor_enqueue(requestor, make_query(requestor, remote), NULL);;
	}
	is_int(KNOT_EOK, ret, "requestor: multiple enqueue");

	/* Wait for multiple queries. */
	ret = KNOT_EOK;
	for (unsigned i = 0; i < 10; ++i) {
		struct timeval tv = { 5, 0 };
		ret |= requestor_exec(requestor, &tv);
	}
	is_int(KNOT_EOK, ret, "requestor: multiple wait");
}

int main(int argc, char *argv[])
{
	plan(TESTS_COUNT);

	mm_ctx_t mm;
	mm_ctx_mempool(&mm, 4096);
	struct sockaddr_storage remote, origin;
	sockaddr_set(&remote, AF_INET, "127.0.0.1", 0);
	sockaddr_set(&origin, AF_INET, "127.0.0.1", 0);

	/* Create fake server environment. */
	server_t server;
	create_fake_server(&server, &mm);

	/* Initialize requestor. */
	struct requestor requestor;
	requestor_init(&requestor, &dummy_module, &mm);

	/* Test requestor in disconnected environment. */
	test_disconnected(&requestor, &remote);

	/* Bind to random port. */
	int origin_fd = net_bound_socket(SOCK_STREAM, &remote);
	assert(origin_fd > 0);
	socklen_t addr_len = sockaddr_len(&remote);
	getsockname(origin_fd, (struct sockaddr *)&remote, &addr_len);
	int ret = listen(origin_fd, 10);
	assert(ret == 0);

	/* Responder thread. */
	pthread_t thread;
	pthread_create(&thread, 0, responder_thread, &origin_fd);

	/* Test requestor in connected environment. */
	test_connected(&requestor, &remote);

	/* TSIG secured. */
#warning TODO: when ported sign_packet/verify_packet

	/* Terminate responder. */
	int responder = net_connected_socket(SOCK_STREAM, &remote, NULL, 0);
	assert(responder > 0);
	tcp_send(responder, (const uint8_t *)"", 1);
	(void) pthread_join(thread, 0);
	close(responder);

	/* Close requestor. */
	requestor_clear(&requestor);
	close(origin_fd);

	/* Cleanup. */
	mp_delete((struct mempool *)mm.ctx);
	server_deinit(&server);

	return 0;
}
