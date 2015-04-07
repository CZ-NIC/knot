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

#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "knot/server/net.h"
#include "knot/server/tcp-handler.h"

const struct timeval TIMEOUT = { .tv_sec = 1 };

static struct sockaddr_storage localhost(void)
{
	struct sockaddr_storage addr = { 0 };

	struct addrinfo *res = NULL;
	if (getaddrinfo(NULL, "0", NULL, &res) == 0) {
		memcpy(&addr, res->ai_addr, res->ai_addrlen);
		freeaddrinfo(res);
	}

	return addr;
}


struct data {
	int fd;
	struct timeval timeout;
	uint8_t *buffer;
	size_t size;
	int result;
};

static void *thr_receive(void *data)
{
	struct data *d = data;
	d->result = tcp_recv_msg(d->fd, d->buffer, d->size, &d->timeout);
	return NULL;
}

int main(int argc, char *argv[])
{
	plan_lazy();

	int r;

	// create TCP server
	struct sockaddr_storage addr = localhost();
	int server = net_bound_socket(SOCK_STREAM, &addr);
	ok(server >= 0, "server: bind socket");

	r = listen(server, 0);
	ok(r == 0, "server: start listening");

	struct sockaddr *sa = (struct sockaddr *)&addr;
	socklen_t salen = sockaddr_len(&addr);
	r = getsockname(server, sa, &salen);
	ok(r == 0, "server: get bound address");

	r = fcntl(server, F_SETFL, O_NONBLOCK);
	ok(r == 0, "server: set non-blocking mode");

	// create TCP client

	int client = net_connected_socket(SOCK_STREAM, &addr, NULL, 0);
	ok(client >= 0, "client: connect to server");

	r = fcntl(client, F_SETFL, O_NONBLOCK);
	ok(r == 0, "client: set non-blocking mode");

	int optval = 8192;
	socklen_t optlen = sizeof(optval);
	r = setsockopt(client, SOL_SOCKET, SO_SNDBUF, &optval, optlen);
	ok(r == 0, "client: configure small send buffer");

	// accept TCP connection

	int accepted = accept(server, NULL, NULL);
	ok(accepted >= 0, "server: accepted connection");

	r = fcntl(accepted, F_SETFL, O_NONBLOCK);
	ok(r == 0, "accepted: set non-blocking mode");

	uint8_t recvbuf[UINT16_MAX] = { 0 };
	struct data recv_data = {
		.fd = accepted,
		.timeout = TIMEOUT,
		.buffer = recvbuf,
		.size = sizeof(recvbuf)
	};

	pthread_t thr;
	r = pthread_create(&thr, NULL, thr_receive, &recv_data);
	ok(r == 0, "server: start receiver thread");

	// send message (should handle partial-write correctly)

	uint8_t sndbuf[UINT16_MAX];
	for (size_t i = 0; i < sizeof(sndbuf); i++) {
		sndbuf[i] = i;
	}
	struct timeval timeout = TIMEOUT;
	r = tcp_send_msg(client, sndbuf, sizeof(sndbuf), &timeout);
	ok(r == sizeof(sndbuf), "client: tcp_send_msg() with short-write");

	// receive message

	r = pthread_join(thr, NULL);
	ok(r == 0, "server: wait for reciever thread to terminate");

	ok(recv_data.result == sizeof(recvbuf) &&
	   memcmp(sndbuf, recvbuf, sizeof(recvbuf)) == 0,
	   "server: tcp_recv_msg() complete and valid data");

	// clean up

	if (accepted >= 0) {
		close(accepted);
	}

	if (server >= 0) {
		close(server);
	}

	if (client >= 0) {
		close(client);
	}

	return 0;
}
