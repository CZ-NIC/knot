/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <tap/basic.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#include "libknot/descriptor.h"
#include "libknot/errcode.h"
#include "knot/query/layer.h"
#include "knot/query/requestor.h"
#include "contrib/mempattern.h"
#include "contrib/net.h"
#include "contrib/sockaddr.h"
#include "contrib/ucw/mempool.h"

bool TFO = false;

/* @note Purpose of this test is not to verify process_answer functionality,
 *       but simply if the requesting/receiving works, so mirror is okay. */
static int reset(knot_layer_t *ctx) { return KNOT_STATE_PRODUCE; }
static int begin(knot_layer_t *ctx, void *module_param) { return reset(ctx); }
static int finish(knot_layer_t *ctx) { return reset(ctx); }
static int in(knot_layer_t *ctx, knot_pkt_t *pkt) { return KNOT_STATE_DONE; }
static int out(knot_layer_t *ctx, knot_pkt_t *pkt) { return KNOT_STATE_CONSUME; }

static const int TIMEOUT = 2000;

/*! \brief Dummy answer processing module. */
const knot_layer_api_t dummy_module = {
        &begin, &reset, &finish, &in, &out
};

static void set_blocking_mode(int sock)
{
	int flags = fcntl(sock, F_GETFL);
	flags &= ~O_NONBLOCK;
	fcntl(sock, F_SETFL, flags);
}

static void *responder_thread(void *arg)
{
	int fd = *(int *)arg;

	set_blocking_mode(fd);
	uint8_t buf[KNOT_WIRE_MAX_PKTSIZE] = { 0 };
	while (true) {
		int client = accept(fd, NULL, NULL);
		if (client < 0) {
			break;
		}
		int len = net_dns_tcp_recv(client, buf, sizeof(buf), -1);
		if (len < KNOT_WIRE_HEADER_SIZE) {
			close(client);
			break;
		}
		knot_wire_set_qr(buf);
		net_dns_tcp_send(client, buf, len, -1, NULL);
		close(client);
	}

	return NULL;
}

/* Test implementations. */

static knot_request_t *make_query(knot_requestor_t *requestor,
                                  const struct sockaddr_storage *dst,
                                  const struct sockaddr_storage *src)
{
	knot_pkt_t *pkt = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, requestor->mm);
	assert(pkt);
	static const knot_dname_t *root = (uint8_t *)"";
	knot_pkt_put_question(pkt, root, KNOT_CLASS_IN, KNOT_RRTYPE_SOA);

	knot_request_flag_t flags = TFO ? KNOT_REQUEST_TFO: KNOT_REQUEST_NONE;

	return knot_request_make(requestor->mm, dst, src, pkt, NULL, flags);
}

static void test_disconnected(knot_requestor_t *requestor,
                              const struct sockaddr_storage *dst,
                              const struct sockaddr_storage *src)
{
	knot_request_t *req = make_query(requestor, dst, src);
	int ret = knot_requestor_exec(requestor, req, TIMEOUT);
	/* ECONNREFUSED on FreeBSD, ETIMEOUT on NetBSD/OpenBSD/macOS. */
	ret = (ret == KNOT_ECONNREFUSED || ret == KNOT_ETIMEOUT) ? KNOT_ECONN : ret;
	is_int(KNOT_ECONN, ret, "requestor: disconnected/exec");
	knot_request_free(req, requestor->mm);

}

static void test_connected(knot_requestor_t *requestor,
                           const struct sockaddr_storage *dst,
                           const struct sockaddr_storage *src)
{
	/* Enqueue packet. */
	knot_request_t *req = make_query(requestor, dst, src);
	int ret = knot_requestor_exec(requestor, req, TIMEOUT);
	is_int(KNOT_EOK, ret, "requestor: connected/exec");
	knot_request_free(req, requestor->mm);
}

int main(int argc, char *argv[])
{
#if defined(__linux__)
	FILE *fd = fopen("/proc/sys/net/ipv4/tcp_fastopen", "r");
	if (fd != NULL) {
		int val = fgetc(fd);
		fclose(fd);
		// 0 - disabled, 1 - server TFO (client fallbacks),
		// 2 - client TFO, 3 - both
		if (val == '1' || val == '3') {
			TFO = true;
		}
	}
#endif
	plan_lazy();

	knot_mm_t mm;
	mm_ctx_mempool(&mm, MM_DEFAULT_BLKSIZE);

	/* Initialize requestor. */
	knot_requestor_t requestor;
	knot_requestor_init(&requestor, &dummy_module, NULL, &mm);

	/* Define endpoints. */
	struct sockaddr_storage client = { 0 };
	sockaddr_set(&client, AF_INET, "127.0.0.1", 0);
	struct sockaddr_storage server = { 0 };
	sockaddr_set(&server, AF_INET, "127.0.0.1", 0);

	/* Bind to random port. */
	int responder_fd = net_bound_socket(SOCK_STREAM, &server, 0);
	assert(responder_fd >= 0);
	socklen_t addr_len = sockaddr_len(&server);
	int ret = getsockname(responder_fd, (struct sockaddr *)&server, &addr_len);
	ok(ret == 0, "check getsockname return");

	/* Test requestor in disconnected environment. */
	test_disconnected(&requestor, &server, &client);

	/* Start responder. */
	ret = listen(responder_fd, 10);
	ok(ret == 0, "check listen return");

	if (TFO) {
		ret = net_bound_tfo(responder_fd, 10);
		ok(ret == KNOT_EOK, "check bound TFO return");
	}

	pthread_t thread;
	pthread_create(&thread, 0, responder_thread, &responder_fd);

	/* Test requestor in connected environment. */
	test_connected(&requestor, &server, &client);

	/* Terminate responder. */
	int conn = net_connected_socket(SOCK_STREAM, &server, NULL, false);
	assert(conn > 0);
	conn = net_dns_tcp_send(conn, (uint8_t *)"", 1, TIMEOUT, NULL);
	assert(conn > 0);
	pthread_join(thread, NULL);
	close(responder_fd);

	/* Cleanup. */
	mp_delete((struct mempool *)mm.ctx);

	return 0;
}
