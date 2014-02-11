/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <config.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <netdb.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif
#include <sys/stat.h>
#include <assert.h>

#include "knot/knot.h"
#include "knot/server/socket.h"

int socket_create(int family, int type, int proto)
{
	/* Create socket. */
	int ret = socket(family, type, proto);
	if (ret < 0) {
		return knot_map_errno(EACCES, EINVAL, ENOMEM);
	}

	return ret;
}

int socket_connect(int fd, int family, const char *addr, unsigned short port)
{
	struct sockaddr_storage ss;
	int ret = sockaddr_set(&ss, family, addr, port);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = connect(fd, (struct sockaddr *)&ss, sockaddr_len(&ss));
	if (ret < 0) {
		ret = knot_map_errno(EACCES, EADDRINUSE, EAGAIN,
		                     ECONNREFUSED, EISCONN);
	}

	return ret;
}

int socket_bind(int socket, int family, const char *addr, unsigned short port)
{
	/* Check address family. */
	int flag = 1;
	struct sockaddr_storage ss;
	int ret = sockaddr_set(&ss, family, addr, port);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Make the socket IPv6 only to allow 'any' for IPv4 and IPv6 at the same time. */
	if (family == AF_INET6) {
		/* Do not support mapping IPv4 in IPv6 sockets. */
		ret = setsockopt(socket, IPPROTO_IPV6, IPV6_V6ONLY,
		                 &flag, sizeof(flag));
		if (ret < 0) {
			return KNOT_EINVAL;
		}
	}

	/* Unlink UNIX socket if exists. */
	if (family == AF_UNIX) {
		unlink(addr);
	}

	/* Reuse old address if taken. */
	ret = setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));
	if (ret < 0) {
		return KNOT_EINVAL;
	}

	/* Bind to specified address. */
	ret = bind(socket, (struct sockaddr *)&ss, sockaddr_len(&ss));
	if (ret < 0) {
		ret = knot_map_errno(EADDRINUSE, EINVAL, EACCES, ENOMEM);
		log_server_error("Cannot bind to socket: %s\n", knot_strerror(ret));
	}

	return ret;
}

int socket_listen(int socket, int backlog_size)
{
	int ret = listen(socket, backlog_size);
	if (ret < 0) {
		return knot_map_errno(EADDRINUSE);
	}

	return KNOT_EOK;
}

int socket_close(int socket)
{
	if (close(socket) < 0) {
		return KNOT_ERROR;
	}

	return KNOT_EOK;
}
