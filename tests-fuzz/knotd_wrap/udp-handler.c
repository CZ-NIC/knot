/*  Copyright (C) 2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <signal.h>

#include "knot/server/udp-handler.c"
#include "knot/common/log.h"

typedef struct {
	struct iovec iov[NBUFS];
	uint8_t buf[NBUFS][KNOT_WIRE_MAX_PKTSIZE];
	struct sockaddr_storage addr;
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
	udp_stdin_t *rq = calloc(1, sizeof(udp_stdin_t));
	if (rq == NULL) {
		return NULL;
	}

	for (unsigned i = 0; i < NBUFS; ++i) {
		rq->iov[i].iov_base = rq->buf[i];
		rq->iov[i].iov_len = KNOT_WIRE_MAX_PKTSIZE;
	}

	struct sockaddr_in *a = (struct sockaddr_in *)&rq->addr;
	a->sin_family = AF_INET;
	a->sin_addr.s_addr = IN_LOOPBACKNET;
	a->sin_port = 42;

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
	                            KNOT_WIRE_MAX_PKTSIZE, stdin);
	if (rq->iov[RX].iov_len == 0) {
		next(rq);
	}

	return rq->iov[RX].iov_len;
}

static void udp_stdin_handle(udp_context_t *ctx, void *d)
{
	udp_stdin_t *rq = (udp_stdin_t *)d;
	udp_handle(ctx, STDIN_FILENO, &rq->addr, &rq->iov[RX], &rq->iov[TX], false);
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

	udp_recvfrom_api = stdin_api;
#ifdef ENABLE_RECVMMSG
	udp_recvmmsg_api = stdin_api;
#endif
}
