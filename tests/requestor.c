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

#include <assert.h>
#include <tap/basic.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#include "knot/conf/conf.h"
#include "libknot/processing/layer.h"
#include "libknot/processing/requestor.h"
#include "contrib/net.h"
#include "contrib/sockaddr.h"
#include "contrib/ucw/mempool.h"

/* @note Purpose of this test is not to verify process_answer functionality,
 *       but simply if the requesting/receiving works, so mirror is okay. */
static int reset(knot_layer_t *ctx) { return KNOT_STATE_PRODUCE; }
static int begin(knot_layer_t *ctx, void *module_param) { return reset(ctx); }
static int finish(knot_layer_t *ctx) { return KNOT_STATE_NOOP; }
static int in(knot_layer_t *ctx, knot_pkt_t *pkt) { return KNOT_STATE_DONE; }
static int out(knot_layer_t *ctx, knot_pkt_t *pkt) { return KNOT_STATE_CONSUME; }

static const struct timeval TIMEOUT = { 2, 0 };

/*! \brief Dummy answer processing module. */
const knot_layer_api_t dummy_module = {
        &begin, &reset, &finish,
        &in, &out, NULL
};

static void set_blocking_mode(int sock)
{
	int flags = fcntl(sock, F_GETFL);
	flags &= ~O_NONBLOCK;
	fcntl(sock, F_SETFL, flags);
}

static void* responder_thread(void *arg)
{
	int fd = *((int *)arg);
	set_blocking_mode(fd);
	uint8_t buf[KNOT_WIRE_MAX_PKTSIZE];
	while (true) {
		int client = accept(fd, NULL, NULL);
		if (client < 0) {
			break;
		}
		int len = net_dns_tcp_recv(client, buf, sizeof(buf), NULL);
		if (len < KNOT_WIRE_HEADER_SIZE) {
			close(client);
			break;
		}
		knot_wire_set_qr(buf);
		net_dns_tcp_send(client, buf, len, NULL);
		close(client);
	}
	return NULL;
}

/* Test implementations. */

static struct knot_request *make_query(struct knot_requestor *requestor, conf_remote_t *remote)
{
	knot_pkt_t *pkt = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, requestor->mm);
	assert(pkt);
	static const knot_dname_t *root = (uint8_t *)"";
	knot_pkt_put_question(pkt, root, KNOT_CLASS_IN, KNOT_RRTYPE_SOA);

	const struct sockaddr *dst = (const struct sockaddr *)&remote->addr;
	const struct sockaddr *src = (const struct sockaddr *)&remote->via;
	return knot_request_make(requestor->mm, dst, src, pkt, 0);
}

static void test_disconnected(struct knot_requestor *requestor, conf_remote_t *remote)
{
	/* Enqueue packet. */
	int ret = knot_requestor_enqueue(requestor, make_query(requestor, remote));
	is_int(KNOT_EOK, ret, "requestor: disconnected/enqueue");

	/* Wait for completion. */
	struct timeval tv = TIMEOUT;
	ret = knot_requestor_exec(requestor, &tv);
	is_int(KNOT_ECONN, ret, "requestor: disconnected/wait");
}

static void test_connected(struct knot_requestor *requestor, conf_remote_t *remote)
{
	/* Enqueue packet. */
	int ret = knot_requestor_enqueue(requestor, make_query(requestor, remote));
	is_int(KNOT_EOK, ret, "requestor: connected/enqueue");

	/* Wait for completion. */
	struct timeval tv = TIMEOUT;
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
		struct timeval tv = TIMEOUT;
		ret |= knot_requestor_exec(requestor, &tv);
	}
	is_int(KNOT_EOK, ret, "requestor: multiple wait");
}

int main(int argc, char *argv[])
{
	plan_lazy();

	mm_ctx_t mm;
	mm_ctx_mempool(&mm, MM_DEFAULT_BLKSIZE);

	conf_remote_t remote;
	memset(&remote, 0, sizeof(conf_remote_t));
	sockaddr_set(&remote.addr, AF_INET, "127.0.0.1", 0);
	sockaddr_set(&remote.via, AF_INET, "127.0.0.1", 0);

	/* Initialize requestor. */
	struct knot_requestor requestor;
	knot_requestor_init(&requestor, &mm);
	knot_requestor_overlay(&requestor, &dummy_module, NULL);

	/* Test requestor in disconnected environment. */
	test_disconnected(&requestor, &remote);

	/* Bind to random port. */
	int origin_fd = net_bound_socket(SOCK_STREAM, &remote.addr, 0);
	assert(origin_fd > 0);
	socklen_t addr_len = sockaddr_len((struct sockaddr *)&remote.addr);
	getsockname(origin_fd, (struct sockaddr *)&remote.addr, &addr_len);
	int ret = listen(origin_fd, 10);
	assert(ret == 0);

	/* Responder thread. */
	pthread_t thread;
	pthread_create(&thread, 0, responder_thread, &origin_fd);

	/* Test requestor in connected environment. */
	test_connected(&requestor, &remote);

	/*! \todo #243 TSIG secured requests test should be implemented. */

	/* Terminate responder. */
	struct timeval tv = TIMEOUT;
	int responder = net_connected_socket(SOCK_STREAM, &remote.addr, NULL);
	assert(responder > 0);
	net_dns_tcp_send(responder, (const uint8_t *)"", 1, &tv);
	(void) pthread_join(thread, 0);
	close(responder);

	/* Close requestor. */
	knot_requestor_clear(&requestor);
	close(origin_fd);

	/* Cleanup. */
	mp_delete((struct mempool *)mm.ctx);
	conf_free(conf(), false);

	return 0;
}
