
#include "knot/server/udp-handler.c"
#include "knot/common/debug.h"

/*
 * Udp handler listen on stdin and send to stdout.
 * To use this handler initialize it with udp_master_init_stdin.
 */

struct udp_stdin {
	struct iovec iov[NBUFS];
	uint8_t buf[NBUFS][KNOT_WIRE_MAX_PKTSIZE];
	struct sockaddr_storage addr;
};

static void *udp_stdin_init(void)
{
	struct udp_stdin *rq = malloc(sizeof(struct udp_stdin));
	memset(rq, 0, sizeof(struct udp_stdin));
	for (unsigned i = 0; i < NBUFS; ++i) {
		rq->iov[i].iov_base = rq->buf[i];
		rq->iov[i].iov_len = KNOT_WIRE_MAX_PKTSIZE;
	}
	return rq;
}

static int udp_stdin_deinit(void *d)
{
	free(d);
	return 0;
}

static int udp_stdin_recv(int fd, void *d)
{
	struct udp_stdin *rq = (struct udp_stdin *) d;
	rq->iov[RX].iov_len = fread(rq->iov[RX].iov_base,
	                            1, rq->iov[RX].iov_len, stdin);
	return rq->iov[RX].iov_len;
}

static int udp_stdin_handle(udp_context_t *ctx, void *d)
{
	struct udp_stdin *rq = (struct udp_stdin *) d;
	udp_handle(ctx, STDIN_FILENO, &rq->addr, &rq->iov[RX], &rq->iov[TX]);
	return 0;
}

static int udp_stdin_send(void *d)
{
	struct udp_stdin *rq = (struct udp_stdin *) d;
	fwrite(rq->iov[TX].iov_base, 1, rq->iov[TX].iov_len, stdout);
	if (getenv("AFL_PERSISTENT")) {
		raise(SIGSTOP);
	} else {
		exit(0);
	}
	return 0;
}

/*!
 * \brief Initialize udp_handler with stdio
 */
void udp_master_init_stdio(server_t *server) {

	log_info("AFL, UDP handler listen on stdin");

	// register our dummy interface to server
	iface_t * ifc = malloc(sizeof(iface_t));
	ifc->fd[RX] = STDIN_FILENO;
	ifc->fd[TX] = STDOUT_FILENO;
	add_tail(&server->ifaces->l, (node_t *)ifc);

	_udp_init = udp_stdin_init;
	_udp_recv = udp_stdin_recv;
	_udp_handle = udp_stdin_handle;
	_udp_send = udp_stdin_send;
	_udp_deinit = udp_stdin_deinit;
}
