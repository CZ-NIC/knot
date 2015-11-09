/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

/*
 * Udp handler listen on stdin and send to stdout.
 * To use this handler initialize it with udp_master_init_stdin.
 */

#include <stdbool.h>

#include "knot/server/udp-handler.c"
#include "knot/common/log.h"

struct udp_stdin {
	struct iovec iov[NBUFS];
	uint8_t buf[NBUFS][KNOT_WIRE_MAX_PKTSIZE];
	struct sockaddr_storage addr;
	bool afl_persistent;
};

static inline void next(struct udp_stdin *rq)
{
	if (rq->afl_persistent) {
		raise(SIGSTOP);
	} else {
		exit(0);
	}
}

static void *udp_stdin_init(void)
{
	struct udp_stdin *rq = malloc(sizeof(struct udp_stdin));
	memset(rq, 0, sizeof(struct udp_stdin));
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

static int udp_stdin_deinit(void *d)
{
	free(d);
	return 0;
}

static int udp_stdin_recv(int fd, void *d)
{
	struct udp_stdin *rq = (struct udp_stdin *)d;
	rq->iov[RX].iov_len = fread(rq->iov[RX].iov_base,
	                            1, KNOT_WIRE_MAX_PKTSIZE, stdin);

	if (rq->iov[RX].iov_len == 0) {
		next(rq);
	}

	return rq->iov[RX].iov_len;
}

static int udp_stdin_handle(udp_context_t *ctx, void *d)
{
	struct udp_stdin *rq = (struct udp_stdin *)d;
	udp_handle(ctx, STDIN_FILENO, &rq->addr, &rq->iov[RX], &rq->iov[TX]);
	return 0;
}

static int udp_stdin_send(void *d)
{
	struct udp_stdin *rq = (struct udp_stdin *)d;
	next(rq);
	return 0;
}

/*!
 * \brief Initialize udp_handler with stdio
 */
void udp_master_init_stdio(server_t *server) {

	log_info("AFL, UDP handler listen on stdin");

	// register our dummy interface to server
	iface_t *ifc = calloc(1, sizeof(iface_t));
	assert(ifc);
	ifc->fd_udp = calloc(1, sizeof(int));
	assert(ifc->fd_udp);
	ifc->fd_udp[0] = STDIN_FILENO;
	ifc->fd_udp_count = 1;

	add_tail(&server->ifaces->l, (node_t *)ifc);

	_udp_init = udp_stdin_init;
	_udp_recv = udp_stdin_recv;
	_udp_handle = udp_stdin_handle;
	_udp_send = udp_stdin_send;
	_udp_deinit = udp_stdin_deinit;
}
