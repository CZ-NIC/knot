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

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>

#include <stdio.h>

#include "libknot/errcode.h"
#include "libknot/internal/net.h"

int main(int argc, char *argv[])
{
	plan_lazy();

	int r;

	// create TCP server

	struct sockaddr_storage addr = { 0 };
	addr.ss_family = AF_INET;
	int server = net_bound_socket(SOCK_STREAM, &addr, 0);
	ok(server >= 0, "server: bind socket");

	r = listen(server, 0);
	ok(r == 0, "server: start listening");

	struct sockaddr *sa = (struct sockaddr *)&addr;
	socklen_t salen = sockaddr_len(sa);
	r = getsockname(server, sa, &salen);
	ok(r == 0, "server: get bound address");

	r = fcntl(server, F_SETFL, O_NONBLOCK);
	ok(r == 0, "server: set non-blocking mode");

	// create TCP client

	int client = net_connected_socket(SOCK_STREAM, &addr, NULL, 0);
	ok(client >= 0, "client: connect to server");

	r = fcntl(client, F_SETFL, O_NONBLOCK);
	ok(r == 0, "client: set non-blocking mode");

	int optval = 1;
	socklen_t optlen = sizeof(optval);
	r = setsockopt(client, SOL_SOCKET, SO_SNDBUF, &optval, optlen);
	ok(r == 0, "client: configure small send buffer");

	// send message (should handle partial-write correctly)

	uint8_t sndbuf[UINT16_MAX];
	for (size_t i = 0; i < sizeof(sndbuf); i++) {
		sndbuf[i] = i;
	}
	r = tcp_send_msg(client, sndbuf, sizeof(sndbuf));
	ok(r == sizeof(sndbuf), "client: tcp_send_msg() with short-write");

	// receive message

	int accepted = accept(server, NULL, NULL);
	ok(accepted >= 0, "server: accepted connection");

	uint8_t recvbuf[UINT16_MAX];
	memset(recvbuf, 0, sizeof(recvbuf));
	struct timeval timeout = { .tv_sec = 1 };
	r = tcp_recv_msg(accepted, recvbuf, sizeof(recvbuf), &timeout);
	ok(r == sizeof(recvbuf) && memcmp(sndbuf, recvbuf, sizeof(sndbuf)) == 0,
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
