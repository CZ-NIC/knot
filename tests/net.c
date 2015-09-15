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

#include <tap/basic.h>

#include <pthread.h>
#include <stdbool.h>
#include <string.h>

#include "libknot/errcode.h"
#include "libknot/internal/net.h"

const struct timeval TIMEOUT = { 2, 0 };
const struct timeval TIMEOUT_SHORT = { 0, 100000 };

#define MIN_MESSAGE_SIZE 1
#define LISTEN_BACKLOG 5
#define MAX(a, b) ((a) > (b) ? (a) : (b))

/*!
 * \brief Echo server context.
 */
struct echo_server_ctx {
	int udp_sock;
	int tcp_sock;
};

/*!
 * \brief Perform non-blocking read and write on a socket.
 */
static bool receive_and_reply(int sock)
{
	struct sockaddr_storage remote = { 0 };

	uint8_t buffer[128] = { 0 };
	struct iovec io = {
		.iov_base = buffer,
		.iov_len = sizeof(buffer)
	};

	struct msghdr msg = {
		.msg_name = &remote, .msg_namelen = sizeof(remote),
		.msg_iov = &io, .msg_iovlen = 1,
	};

	ssize_t in = recvmsg(sock, &msg, MSG_DONTWAIT);
	if (in <= MIN_MESSAGE_SIZE) {
		return false;
	}

	io.iov_len = in;

	ssize_t out = sendmsg(sock, &msg, 0);
	return (in == out);
}

/*!
 * \brief Simple TCP and UDP echo server.
 *
 * Terminated by sending a one byte message to the UDP socket.
 */
static void *echo_server_main(void *data)
{
	struct echo_server_ctx *ctx = data;

	fd_set fds;
	FD_ZERO(&fds);
	FD_SET(ctx->udp_sock, &fds);
	FD_SET(ctx->tcp_sock, &fds);
	int fd_max = MAX(ctx->tcp_sock, ctx->udp_sock);

	for (;;) {
		fd_set rfds = fds;
		struct timeval tv = TIMEOUT;
		int r = select(fd_max + 1, &rfds, NULL, NULL, &tv);
		if (r == -1) {
			break;
		} else if (r == 0) {
			continue;
		}

		// UDP echo

		if (FD_ISSET(ctx->udp_sock, &rfds)) {
			if (!receive_and_reply(ctx->udp_sock)) {
				break;
			}
		}

		// TCP echo

		if (FD_ISSET(ctx->tcp_sock, &rfds)) {
			int client = accept(ctx->tcp_sock, NULL, NULL);
			if (client < 0) {
				break;
			}

			fd_set tcp;
			FD_ZERO(&tcp);
			FD_SET(client, &tcp);
			tv = TIMEOUT;
			r = select(client + 1, &tcp, NULL, NULL, &tv);
			if (r != 1) {
				close(client);
				continue;
			}

			receive_and_reply(client);

			close(client);
		}
	}

	return NULL;
}

/*!
 * \brief Get loopback socket address with unset port.
 */
static struct sockaddr_storage addr_local(void)
{
	struct sockaddr_storage addr = { 0 };
	struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&addr;

	addr6->sin6_family = AF_INET6;
	addr6->sin6_addr = in6addr_loopback;

	return addr;
}

/*!
 * \brief Get address of a socket.
 */
static struct sockaddr_storage addr_from_socket(int sock)
{
	struct sockaddr_storage addr = { 0 };
	socklen_t len = sizeof(addr);
	getsockname(sock, (struct sockaddr *)&addr, &len);

	return addr;
}

static void test_connected(void)
{
	int r;

	struct echo_server_ctx ctx = { 0 };

	// create bound sockets

	struct sockaddr_storage udp_addr, tcp_addr;
	udp_addr = tcp_addr = addr_local();

	ctx.udp_sock = net_bound_socket(SOCK_DGRAM, &udp_addr, 0);
	ctx.tcp_sock = net_bound_socket(SOCK_STREAM, &udp_addr, 0);

	ok(ctx.udp_sock >= 0, "UDP: server, create bound socket");
	ok(ctx.tcp_sock >= 0, "TCP: server, create bound socket");

	udp_addr = addr_from_socket(ctx.udp_sock);
	tcp_addr = addr_from_socket(ctx.tcp_sock);

	r = listen(ctx.tcp_sock, LISTEN_BACKLOG);
	ok(r == 0, "TCP: server, starting listening");

	// start echo server

	pthread_t echo_server_thr;
	pthread_create(&echo_server_thr, NULL, echo_server_main, &ctx);

	// send test messages and receive answers

	const uint8_t out[] = "test message";
	const size_t out_len = sizeof(out);

	int sock;
	struct timeval tv;
	uint8_t in[128] = { 0 };

	sock = net_connected_socket(SOCK_DGRAM, &udp_addr, NULL);
	ok(sock >= 0, "UDP: client, create connected socket");

	r = net_is_connected(sock);
	ok(r, "UDP: client, is connected");

	r = udp_send_msg(sock, out, out_len, NULL);
	ok(r == out_len, "UDP: client, send message");

	memset(in, 0, sizeof(in));
	tv = TIMEOUT;
	r = udp_recv_msg(sock, in, sizeof(in), &tv);
	ok(r == out_len && memcmp(out, in, out_len) == 0,
	   "UDP: client, receive message");

	close(sock);

	sock = net_connected_socket(SOCK_STREAM, &tcp_addr, NULL);
	ok(sock >= 0, "TCP: client, create connected socket");

	ok(net_is_connected(sock), "TCP: client, is connected");

	tv = TIMEOUT;
	r = tcp_send_msg(sock, out, out_len, &tv);
	ok(r == out_len, "TCP client, send message");

	memset(in, 0, sizeof(in));
	tv = TIMEOUT;
	r = tcp_recv_msg(sock, in, sizeof(in), &tv);
	ok(r == out_len && memcmp(out, in, out_len) == 0,
	   "TCP client, receive message");

	close(sock);

	// terminate the echo server

	struct sockaddr_storage addr = addr_local();
	sock = net_unbound_socket(SOCK_DGRAM, &addr);
	ok(sock >= 0, "UDP: client, create unbound socket");

	ok(!net_is_connected(sock), "UDP: client, is not connected");

	r = udp_send_msg(sock, (uint8_t *)"", 1, (struct sockaddr *)&udp_addr);
	ok(r == 1, "UDP: client, send server termination request");

	close(sock);

	// cleanup

	pthread_join(echo_server_thr, NULL);
	if (ctx.udp_sock >= 0) {
		close(ctx.udp_sock);
	}
	if (ctx.udp_sock >= 0) {
		close(ctx.udp_sock);
	}
}

static void test_unconnected(void)
{
	int r = 0;
	int sock = -1;
	struct sockaddr_storage addr = addr_local();
	struct timeval tv = { 0 };

	uint8_t buffer[1] = { 0 };

	// UDP

	sock = net_unbound_socket(SOCK_DGRAM, &addr);
	ok(sock >= 0, "UDP, create unbound socket");

	r = net_is_connected(sock);
	ok(!r, "UDP, is not connected");

	r = udp_send_msg(sock, (uint8_t *)"", 1, NULL);
	ok(r == KNOT_ECONN, "UDP, send failure on unconnected socket");

	tv = TIMEOUT_SHORT;
	r = udp_recv_msg(sock, buffer, sizeof(buffer), &tv);
	ok(r == KNOT_ETIMEOUT, "UDP, receive timeout on unconnected socket");

	// TCP

	sock = net_unbound_socket(SOCK_STREAM, &addr);
	ok(sock >= 0, "TCP, create unbound socket");

	r = net_is_connected(sock);
	ok(!r, "TCP, is not connected");

//	tv = TIMEOUT_SHORT;
//	r = tcp_send_msg(sock, (uint8_t *)"", 1, &tv);
//	ok(r == KNOT_ECONN, "TCP, send failure on unconnected socket");
	skip("TCP, send failure on unconnected socket");

//	tv = TIMEOUT;
//	r = tcp_recv_msg(sock, buffer, sizeof(buffer), &tv);
//	ok(r == KNOT_ETIMEOUT, "TCP, receive timeout on unconnected socket");
	skip("TCP, receive timeout on unconnected socket");

	close(sock);
}

static void test_refused(void)
{
	skip("TODO");
}

int main(int argc, char *argv[])
{
	plan_lazy();

	diag("connected sockets");
	test_connected();
	diag("unconnected sockets");
	test_unconnected();
	diag("refused connections");
	test_refused();

	return 0;
}
