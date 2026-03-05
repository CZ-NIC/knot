/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <signal.h>

#include "knot/server/udp-handler.c"
#include "knot/common/log.h"

typedef struct {
	network_dns_request_manager_t *req_mgr;
	network_dns_request_t *req;
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

static void *udp_stdin_init(udp_context_t *ctx, _unused_ void *xdp_sock)
{
	udp_stdin_t *rq = ctx->req_mgr->allocate_mem_func(ctx->req_mgr, sizeof(*rq));
	if (rq == NULL) {
		return NULL;
	}
	memset(rq, 0, sizeof(*rq));
	rq->req_mgr = ctx->req_mgr;

	network_dns_request_t *req = ctx->req_mgr->allocate_network_request_func(ctx->req_mgr);
	if (req == NULL) {
		rq->req_mgr->free_mem_func(rq->req_mgr, rq);
		return NULL;
	}

	if (sockaddr_set(&req->dns_req.req_data.source_addr, AF_INET, "127.0.0.0", 42) != KNOT_EOK) {
		rq->req_mgr->free_network_request_func(rq->req_mgr, req);
		rq->req_mgr->free_mem_func(rq->req_mgr, rq);
		return NULL;
	}

	rq->afl_persistent = getenv("AFL_PERSISTENT") != NULL;

	return rq;
}

static void udp_stdin_deinit(void *d)
{
	udp_stdin_t *rq = d;
	rq->req_mgr->free_network_request_func(rq->req_mgr, rq->req);
	rq->req_mgr->free_mem_func(rq->req_mgr, rq);
}

static int udp_stdin_recv(_unused_ int fd, void *d)
{
	udp_stdin_t *rq = d;

	rq->req->iov[RX].iov_len = fread(rq->req->iov[RX].iov_base, 1,
	                                 rq->req->iov[RX].iov_len, stdin);
	if (rq->req->iov[RX].iov_len == 0) {
		next(rq);
	}

	return rq->req->iov[RX].iov_len;
}

static void udp_stdin_handle(udp_context_t *ctx, _unused_ const iface_t *iface, void *d)
{
	udp_stdin_t *rq = d;

	init_dns_request(&ctx->dns_handler, &rq->req->dns_req, STDIN_FILENO, KNOTD_QUERY_PROTO_UDP);

	udp_handler(ctx, rq->req);
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
