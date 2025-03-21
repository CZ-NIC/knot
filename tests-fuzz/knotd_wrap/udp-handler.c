/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <signal.h>

#include "knot/server/udp-handler.c"
#include "knot/common/log.h"

typedef struct {
	struct iovec iov[NBUFS];
	uint8_t buf[NBUFS][KNOT_WIRE_MAX_PKTSIZE];
	sockaddr_t addr;
	bool afl_persistent;
} udp_stdin_t;

static inline void next(udp_stdin_t *rq)
{
	if (rq->afl_persistent) {
		raise(SIGSTOP);
	} else {
		exit(0);
	}
}

static void *udp_stdin_init(_unused_ udp_context_t *ctx, _unused_ void *xdp_sock)
{
	udp_stdin_t *rq = calloc(1, sizeof(*rq));
	if (rq == NULL) {
		return NULL;
	}

	for (unsigned i = 0; i < NBUFS; ++i) {
		rq->iov[i].iov_base = rq->buf[i];
		rq->iov[i].iov_len = sizeof(rq->buf[i]);
	}

	rq->addr.ip4.sin_family = AF_INET;
	rq->addr.ip4.sin_addr.s_addr = IN_LOOPBACKNET;
	rq->addr.ip4.sin_port = 42;

	rq->afl_persistent = getenv("AFL_PERSISTENT") != NULL;

	return rq;
}

static void udp_stdin_deinit(void *d)
{
	free(d);
}

static int udp_stdin_recv(_unused_ int fd, void *d)
{
	udp_stdin_t *rq = (udp_stdin_t *)d;
	rq->iov[RX].iov_len = fread(rq->iov[RX].iov_base, 1,
	                            sizeof(rq->buf[RX]), stdin);
	if (rq->iov[RX].iov_len == 0) {
		next(rq);
	}

	return rq->iov[RX].iov_len;
}

static void udp_stdin_handle(udp_context_t *ctx, _unused_ const iface_t *iface, void *d)
{
	udp_stdin_t *rq = (udp_stdin_t *)d;
	knotd_qdata_params_t params = params_init(KNOTD_QUERY_PROTO_UDP, &rq->addr,
	                                          &iface->addr, STDIN_FILENO, NULL, 0);
	udp_handler(ctx, &params, &rq->iov[RX], &rq->iov[TX]);
}

static void udp_stdin_send(void *d)
{
	udp_stdin_t *rq = (udp_stdin_t *)d;
	next(rq);
}

static udp_api_t stdin_api = {
	udp_stdin_init,
	udp_stdin_deinit,
	udp_stdin_recv,
	udp_stdin_handle,
	udp_stdin_send
};

void udp_master_init_stdio(server_t *server) {

	log_info("AFL, UDP handler listening on stdin");

	// Register dummy interface to server.
	iface_t *ifc = calloc(1, sizeof(*ifc));
	assert(ifc);
	ifc->fd_udp = calloc(1, sizeof(*ifc->fd_udp));
	assert(ifc->fd_udp);
	ifc->fd_udp[0] = STDIN_FILENO;
	ifc->fd_udp_count = 1;

	server->n_ifaces = 1;
	server->ifaces = ifc;

	udp_msg_api = stdin_api;
#ifdef ENABLE_RECVMMSG
	udp_mmsg_api = stdin_api;
#endif
}
