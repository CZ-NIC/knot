/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <assert.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <string.h>

#include "libknot/errcode.h"
#include "contrib/net.h"
#include "contrib/sockaddr.h"

#undef ENABLE_NET_UNREACHABLE_TEST
//#define ENABLE_NET_UNREACHABLE_TEST

const int TIMEOUT = 5000;
const int TIMEOUT_SHORT = 500;

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

#ifdef ENABLE_NET_UNREACHABLE_TEST
/*!
 * \brief Get unreachable IPv6 address.
 *
 * Allocated from 100::/64 (Discard-Only Address Block).
 */
static struct sockaddr_storage addr_unreachable(void)
{
	struct sockaddr_storage addr = { 0 };
	sockaddr_set(&addr, AF_INET6, "100::b1ac:h01e", 42);

	return addr;
}
#endif

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

static const char *socktype_name(int type)
{
	switch (type) {
	case SOCK_STREAM: return "TCP";
	case SOCK_DGRAM:  return "UDP";
	default:          return "unknown";
	}
}

static bool socktype_is_stream(int type)
{
	return type == SOCK_STREAM;
}

/* -- mock server ---------------------------------------------------------- */

#define LISTEN_BACKLOG 5

struct server_ctx;
typedef struct server_ctx server_ctx_t;

typedef void (*server_cb)(int sock, void *data);

/*!
 * \brief Server context.
 */
struct server_ctx {
	int sock;
	int type;
	bool terminate;
	server_cb handler;
	void *handler_data;

	pthread_t thr;
	pthread_mutex_t mx;
};

static int poll_read(int sock)
{
	struct pollfd pfd = { .fd = sock, .events = POLLIN };
	return poll(&pfd, 1, TIMEOUT);
}

static void server_handle(server_ctx_t *ctx)
{
	int remote = ctx->sock;

	assert(ctx->type == SOCK_STREAM || ctx->type == SOCK_DGRAM);

	if (socktype_is_stream(ctx->type)) {
		remote = accept(ctx->sock, 0, 0);
		if (remote < 0) {
			return;
		}
	}

	pthread_mutex_lock(&ctx->mx);
	server_cb handler = ctx->handler;
	pthread_mutex_unlock(&ctx->mx);
	handler(remote, ctx->handler_data);

	if (socktype_is_stream(ctx->type)) {
		close(remote);
	}
}

/*!
 * \brief Simple server.
 *
 * Terminated when a one-byte message is delivered.
 */
static void *server_main(void *_ctx)
{
	server_ctx_t *ctx = _ctx;

	for (;;) {
		pthread_mutex_lock(&ctx->mx);
		bool terminate = ctx->terminate;
		pthread_mutex_unlock(&ctx->mx);
		if (terminate) {
			break;
		}

		int r = poll_read(ctx->sock);
		if (r == -1) {
			if (errno == EINTR) {
				continue;
			} else {
				break;
			}
		} else if (r == 0) {
			continue;
		}

		assert(r == 1);
		server_handle(ctx);
	}

	return NULL;
}

static bool server_start(server_ctx_t *ctx, int sock, int type,
                         server_cb handler, void *handler_data)
{
	memset(ctx, 0, sizeof(*ctx));

	ctx->sock = sock;
	ctx->type = type;
	ctx->handler = handler;
	ctx->handler_data = handler_data;

	ctx->terminate = false;

	pthread_mutex_init(&ctx->mx, NULL);
	return (pthread_create(&ctx->thr, NULL, server_main, ctx) == 0);
}

static void server_stop(server_ctx_t *ctx)
{
	pthread_mutex_lock(&ctx->mx);
	ctx->terminate = true;
	pthread_mutex_unlock(&ctx->mx);

	pthread_kill(ctx->thr, SIGUSR1);
	pthread_join(ctx->thr, NULL);
}

/* -- tests ---------------------------------------------------------------- */

static void handler_echo(int sock, void *_server)
{
	server_ctx_t *server = _server;
	uint8_t buffer[16] = { 0 };

	struct sockaddr_storage remote = { 0 };
	struct sockaddr_storage *addr = NULL;
	if (!socktype_is_stream(server->type)) {
		addr = &remote;
	}

	int in = net_base_recv(sock, buffer, sizeof(buffer), addr, TIMEOUT);
	if (in <= 0) {
		return;
	}

	net_base_send(sock, buffer, in, (struct sockaddr *)addr, TIMEOUT);
}

static void test_connected_one(const struct sockaddr_storage *server_addr,
                               const struct sockaddr_storage *source_addr,
                               int type, const char *name, const char *addr_name)
{
	int r;

	int client = net_connected_socket(type, (struct sockaddr *)server_addr, NULL);
	ok(client >= 0, "%s, %s: client, create connected socket", name, addr_name);

	const uint8_t out[] = "test message";
	const size_t out_len = sizeof(out);
	if (socktype_is_stream(type)) {
		r = net_stream_send(client, out, out_len, TIMEOUT);
	} else {
		r = net_dgram_send(client, out, out_len, NULL);
	}
	ok(r == out_len, "%s, %s: client, send message", name, addr_name);

	r = net_is_connected(client);
	ok(r, "%s, %s: client, is connected", name, addr_name);

	uint8_t in[128] = { 0 };
	if (socktype_is_stream(type)) {
		r = net_stream_recv(client, in, sizeof(in), TIMEOUT);
	} else {
		r = net_dgram_recv(client, in, sizeof(in), TIMEOUT);
	}
	ok(r == out_len && memcmp(out, in, out_len) == 0,
	   "%s, %s: client, receive message", name, addr_name);

	close(client);
}

static void test_connected(int type)
{
	const char *name = socktype_name(type);
	const struct sockaddr_storage empty_addr = { 0 };
	const struct sockaddr_storage local_addr = addr_local();

	int r;

	// setup server

	int server = net_bound_socket(type, (struct sockaddr *)&local_addr, 0);
	ok(server >= 0, "%s: server, create bound socket", name);

	if (socktype_is_stream(type)) {
		r = listen(server, LISTEN_BACKLOG);
		ok(r == 0, "%s: server, start listening", name);
	}

	server_ctx_t server_ctx = { 0 };
	r = server_start(&server_ctx, server, type, handler_echo, &server_ctx);
	ok(r, "%s: server, start", name);

	const struct sockaddr_storage server_addr = addr_from_socket(server);

	// connected socket, send and receive

	test_connected_one(&server_addr, NULL, type, name, "NULL source");
	test_connected_one(&server_addr, &empty_addr, type, name, "zero source");
	test_connected_one(&server_addr, &local_addr, type, name, "valid source");

	// cleanup

	server_stop(&server_ctx);
	close(server);
}

static void handler_noop(int sock, void *data)
{
}

static void test_unconnected(void)
{
	int r = 0;
	int sock = -1;
	const struct sockaddr_storage local = addr_local();

	uint8_t buffer[] = { 'k', 'n', 'o', 't' };
	ssize_t buffer_len = sizeof(buffer);

	// server

	int server = net_bound_socket(SOCK_DGRAM, (struct sockaddr *)&local, 0);
	ok(server >= 0, "UDP, create server socket");

	server_ctx_t server_ctx = { 0 };
	r = server_start(&server_ctx, server, SOCK_DGRAM, handler_noop, NULL);
	ok(r, "UDP, start server");

	// UDP

	sock = net_unbound_socket(SOCK_DGRAM, (struct sockaddr *)&local);
	ok(sock >= 0, "UDP, create unbound socket");

	ok(!net_is_connected(sock), "UDP, is not connected");

	r = net_dgram_send(sock, buffer, buffer_len, NULL);
	ok(r == KNOT_ECONN, "UDP, send failure on unconnected socket");

	r = net_dgram_recv(sock, buffer, buffer_len, TIMEOUT_SHORT);
	ok(r == KNOT_ETIMEOUT, "UDP, receive timeout on unconnected socket");

	struct sockaddr_storage server_addr = addr_from_socket(server);
	r = net_dgram_send(sock, buffer, buffer_len, (struct sockaddr *)&server_addr);
	ok(r == buffer_len, "UDP, send on defined address");

	close(sock);

	// TCP

	sock = net_unbound_socket(SOCK_STREAM, (struct sockaddr *)&local);
	ok(sock >= 0, "TCP, create unbound socket");

	ok(!net_is_connected(sock), "TCP, is not connected");

#ifdef __linux__
	const int expected = KNOT_ECONN;
	const char *expected_msg = "failure";
	const int expected_timeout = TIMEOUT;
#else
	const int expected = KNOT_ETIMEOUT;
	const char *expected_msg = "timeout";
	const int expected_timeout = TIMEOUT_SHORT;
#endif

	r = net_stream_send(sock, buffer, buffer_len, expected_timeout);
	ok(r == expected, "TCP, send %s on unconnected socket", expected_msg);

	r = net_stream_recv(sock, buffer, sizeof(buffer), expected_timeout);
	ok(r == expected, "TCP, receive %s on unconnected socket", expected_msg);

	close(sock);

	// server termination

	server_stop(&server_ctx);
	close(server);
}

static void test_refused(void)
{
	int r = -1;

	struct sockaddr_storage addr = { 0 };
	uint8_t buffer[1] = { 0 };
	int server, client;

	// unreachable remote

#ifdef ENABLE_NET_UNREACHABLE_TEST
	addr = addr_unreachable();

	client = net_connected_socket(SOCK_STREAM, &addr, NULL);
	ok(client >= 0, "client, connected");

	tv = TIMEOUT_SHORT;
	r = net_stream_send(client, (uint8_t *)"", 1, &tv);
	ok(r == KNOT_ETIMEOUT, "client, timeout on write");
	close(client);

	client = net_connected_socket(SOCK_STREAM, &addr, NULL);
	ok(client >= 0, "client, connected");

	tv = TIMEOUT_SHORT;
	r = net_stream_recv(client, buffer, sizeof(buffer), &tv);
	ok(r == KNOT_ETIMEOUT, "client, timeout on read");
	close(client);
#else
	skip("unreachable tests disabled");
#endif

	// listening, not accepting

	addr = addr_local();
	server = net_bound_socket(SOCK_STREAM, (struct sockaddr *)&addr, 0);
	ok(server >= 0, "server, create server");
	addr = addr_from_socket(server);

	r = listen(server, LISTEN_BACKLOG);
	ok(r == 0, "server, start listening");

	client = net_connected_socket(SOCK_STREAM, (struct sockaddr *)&addr, NULL);
	ok(client >= 0, "client, connect");

	r = net_stream_send(client, (uint8_t *)"", 1, TIMEOUT);
	ok(r == 1, "client, successful write");

	r = net_stream_recv(client, buffer, sizeof(buffer), TIMEOUT_SHORT);
	ok(r == KNOT_ETIMEOUT, "client, timeout on read");

	close(client);

	// listening, closed immediately

	client = net_connected_socket(SOCK_STREAM, (struct sockaddr *)&addr, NULL);
	ok(client >= 0, "client, connect");

	r = close(server);
	ok(r == 0, "server, close socket");

	r = net_stream_send(client, (uint8_t *)"", 1, TIMEOUT);
	ok(r == KNOT_ECONN, "client, refused on write");

	close(client);
}

struct dns_handler_ctx {
	const uint8_t *expected;
	int len;
	bool raw;
	bool success;
};

static void _sync(int remote, int send)
{
	uint8_t buf[1] = { 0 };
	int r;
	if (send) {
		r = net_stream_send(remote, buf, sizeof(buf), TIMEOUT);
	} else {
		r = net_stream_recv(remote, buf, sizeof(buf), TIMEOUT);

	}
	assert(r == sizeof(buf));
	(void)r;
}

static void sync_signal(int remote)
{
	_sync(remote, true);
}

static void sync_wait(int remote)
{
	_sync(remote, false);
}

static void handler_dns(int sock, void *_ctx)
{
	struct dns_handler_ctx *ctx = _ctx;

	uint8_t in[16] = { 0 };
	int in_len = 0;

	sync_signal(sock);

	if (ctx->raw) {
		in_len = net_stream_recv(sock, in, sizeof(in), TIMEOUT);
	} else {
		in_len = net_dns_tcp_recv(sock, in, sizeof(in), TIMEOUT);
	}

	ctx->success = in_len == ctx->len &&
	               (ctx->len < 0 || memcmp(in, ctx->expected, in_len) == 0);
}

static void dns_send_hello(int sock)
{
	net_dns_tcp_send(sock, (uint8_t *)"wimbgunts", 9, TIMEOUT);
}

static void dns_send_fragmented(int sock)
{
	struct fragment { const uint8_t *data; size_t len; };

	const struct fragment fragments[] = {
		{ (uint8_t *)"\x00",     1 },
		{ (uint8_t *)"\x08""qu", 3 },
		{ (uint8_t *)"oopisk",   6 },
		{ NULL }
	};

	for (const struct fragment *f = fragments; f->len > 0; f++) {
		net_stream_send(sock, f->data, f->len, TIMEOUT);
	}
}

static void dns_send_incomplete(int sock)
{
	net_stream_send(sock, (uint8_t *)"\x00\x08""korm", 6, TIMEOUT);
}

static void dns_send_trailing(int sock)
{
	net_stream_send(sock, (uint8_t *)"\x00\x05""bloitxx", 9, TIMEOUT);
}

static void test_dns_tcp(void)
{
	struct testcase {
		const char *name;
		const uint8_t *expected;
		size_t expected_len;
		bool expected_raw;
		void (*send_callback)(int sock);
	};

	const struct testcase testcases[] = {
		{ "single DNS",       (uint8_t *)"wimbgunts", 9, false, dns_send_hello },
		{ "single RAW",       (uint8_t *)"\x00\x09""wimbgunts", 11, true, dns_send_hello },
		{ "fragmented",       (uint8_t *)"quoopisk", 8, false, dns_send_fragmented },
		{ "incomplete",       NULL, KNOT_ECONN, false, dns_send_incomplete },
		{ "trailing garbage", (uint8_t *)"bloit", 5, false, dns_send_trailing },
		{ NULL }
	};

	for (const struct testcase *t = testcases; t->name != NULL; t++) {
		struct dns_handler_ctx handler_ctx = {
			.expected = t->expected,
			.len      = t->expected_len,
			.raw      = t->expected_raw,
			.success  = false
		};

		struct sockaddr_storage addr = addr_local();
		int server = net_bound_socket(SOCK_STREAM, (struct sockaddr *)&addr, 0);
		ok(server >= 0, "%s, server, create socket", t->name);

		int r = listen(server, LISTEN_BACKLOG);
		ok(r == 0, "%s, server, start listening", t->name);

		server_ctx_t server_ctx = { 0 };
		r = server_start(&server_ctx, server, SOCK_STREAM, handler_dns, &handler_ctx);
		ok(r, "%s, server, start handler", t->name);

		addr = addr_from_socket(server);
		int client = net_connected_socket(SOCK_STREAM, (struct sockaddr *)&addr, NULL);
		ok(client >= 0, "%s, client, create connected socket", t->name);

		sync_wait(client);
		t->send_callback(client);

		close(client);
		server_stop(&server_ctx);
		close(server);

		ok(handler_ctx.success, "%s, expected result", t->name);
	}
}

static bool socket_is_blocking(int sock)
{
	return fcntl(sock, F_GETFL, O_NONBLOCK) == 0;
}

static void test_nonblocking_mode(int type)
{
	const char *name = socktype_name(type);
	const struct sockaddr_storage addr = addr_local();

	int client = net_unbound_socket(type, (struct sockaddr *)&addr);
	ok(client >= 0, "%s: unbound, create", name);
	ok(!socket_is_blocking(client), "%s: unbound, nonblocking mode", name);
	close(client);

	int server = net_bound_socket(type, (struct sockaddr *)&addr, 0);
	ok(server >= 0, "%s: bound, create", name);
	ok(!socket_is_blocking(server), "%s: bound, nonblocking mode", name);

	if (socktype_is_stream(type)) {
		int r = listen(server, LISTEN_BACKLOG);
		ok(r == 0, "%s: bound, start listening", name);
	}

	struct sockaddr_storage server_addr = addr_from_socket(server);
	client = net_connected_socket(type, (struct sockaddr *)&server_addr, NULL);
	ok(client >= 0, "%s: connected, create", name);
	ok(!socket_is_blocking(client), "%s: connected, nonblocking mode", name);

	close(client);
	close(server);
}

static void test_nonblocking_accept(void)
{
	int r;

	// create server

	struct sockaddr_storage addr_server = addr_local();

	int server = net_bound_socket(SOCK_STREAM, (struct sockaddr *)&addr_server, 0);
	ok(server >= 0, "server, create socket");

	r = listen(server, LISTEN_BACKLOG);
	ok(r == 0, "server, start listening");

	addr_server = addr_from_socket(server);

	// create client

	int client = net_connected_socket(SOCK_STREAM, (struct sockaddr *)&addr_server, NULL);
	ok(client >= 0, "client, create connected socket");

	struct sockaddr_storage addr_client = addr_from_socket(client);

	// accept connection

	r = poll_read(server);
	ok(r == 1, "server, pending connection");

	struct sockaddr_storage addr_accepted = { 0 };
	int accepted = net_accept(server, &addr_accepted);
	ok(accepted >= 0, "server, accept connection");

	ok(!socket_is_blocking(accepted), "accepted, nonblocking mode");

	ok(sockaddr_cmp((struct sockaddr *)&addr_client,
	                (struct sockaddr *)&addr_accepted) == 0,
	   "accepted, correct address");

	close(client);

	// client reconnect

	close(client);
	client = net_connected_socket(SOCK_STREAM, (struct sockaddr *)&addr_server, NULL);
	ok(client >= 0, "client, reconnect");

	r = poll_read(server);
	ok(r == 1, "server, pending connection");

	accepted = net_accept(server, NULL);
	ok(accepted >= 0, "server, accept connection (no remote address)");

	ok(!socket_is_blocking(accepted), "accepted, nonblocking mode");

	// cleanup

	close(client);
	close(server);
}

static void test_socket_types(void)
{
	struct sockaddr_storage addr = addr_local();

	struct testcase {
		const char *name;
		int type;
		bool is_stream;
	};

	const struct testcase testcases[] = {
		{ "UDP", SOCK_DGRAM, false },
		{ "TCP", SOCK_STREAM, true },
		{ NULL }
	};

	for (const struct testcase *t = testcases; t->name != NULL; t++) {
		int sock = net_unbound_socket(t->type, (struct sockaddr *)&addr);
		ok(sock >= 0, "%s, create socket", t->name);

		is_int(t->type, net_socktype(sock), "%s, socket type", t->name);

		ok(net_is_stream(sock) == t->is_stream, "%s, is stream", t->name);

		close(sock);
	}

	is_int(AF_UNSPEC, net_socktype(-1), "invalid, socket type");
	ok(!net_is_stream(-1), "invalid, is stream");
}

static void test_bind_multiple(void)
{
	const struct sockaddr_storage addr = addr_local();

	// bind first socket

	int sock_one = net_bound_socket(SOCK_DGRAM, (struct sockaddr *)&addr, NET_BIND_MULTIPLE);
	if (sock_one == KNOT_ENOTSUP) {
		skip("not supported on this system");
		return;
	}
	ok(sock_one >= 0, "bind first socket");

	// bind second socket to the same address

	const struct sockaddr_storage addr_one = addr_from_socket(sock_one);
	int sock_two = net_bound_socket(SOCK_DGRAM, (struct sockaddr *)&addr_one, NET_BIND_MULTIPLE);
	ok(sock_two >= 0, "bind second socket");

	// compare sockets

	ok(sock_one != sock_two, "descriptors are different");

	const struct sockaddr_storage addr_two = addr_from_socket(sock_two);
	ok(sockaddr_cmp((struct sockaddr *)&addr_one,
	                (struct sockaddr *)&addr_two) == 0,
	   "addresses are the same");

	close(sock_one);
	close(sock_two);
}

static void signal_noop(int sig)
{
}

int main(int argc, char *argv[])
{
	plan_lazy();

	signal(SIGUSR1, signal_noop);

	diag("nonblocking mode");
	test_nonblocking_mode(SOCK_DGRAM);
	test_nonblocking_mode(SOCK_STREAM);
	test_nonblocking_accept();

	diag("socket types");
	test_socket_types();

	diag("connected sockets");
	test_connected(SOCK_DGRAM);
	test_connected(SOCK_STREAM);

	diag("unconnected sockets");
	test_unconnected();

	diag("refused connections");
	test_refused();

	diag("DNS messages over TCP");
	test_dns_tcp();

	diag("flag NET_BIND_MULTIPLE");
	test_bind_multiple();

	return 0;
}
