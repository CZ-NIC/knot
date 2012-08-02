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
#include <sys/socket.h>
#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include "knot/other/error.h"
#include "knot/common.h"
#include "knot/server/socket.h"

int socket_create(int family, int type)
{
	/* Create socket. */
	int ret = socket(family, type, 0);
	if (ret < 0) {
		return knot_map_errno(EACCES, EINVAL, ENOMEM);
	}

	return ret;
}

int socket_connect(int fd, const char *addr, unsigned short port)
{
	/* NULL address => any */
	if (!addr) {
		addr = "0.0.0.0";
	}

	/* Resolve address. */
	int ret = KNOTD_EOK;
	struct addrinfo hints, *res;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if ((ret = getaddrinfo(addr, NULL, &hints, &res)) != 0) {
		return KNOTD_EINVAL;
	}

	/* Evaluate address type. */
	struct sockaddr *saddr = 0;
	socklen_t addrlen = 0;
#ifndef DISABLE_IPV6
	if (res->ai_family == AF_INET6) {
		struct sockaddr_in6 *ipv6 = (struct sockaddr_in6*)res->ai_addr;
		ipv6->sin6_port = htons(port);
		saddr = (struct sockaddr*)ipv6;
		addrlen = sizeof(struct sockaddr_in6);
	}
#endif
	if (res->ai_family == AF_INET) {
		struct sockaddr_in *ipv4 = (struct sockaddr_in*)res->ai_addr;
		ipv4->sin_port = htons(port);
		saddr = (struct sockaddr*)ipv4;
		addrlen = sizeof(struct sockaddr_in);
	}

	/* Connect. */
	ret = -1;
	ret = connect(fd, saddr, addrlen);
	if (ret < 0) {
		ret = knot_map_errno(EACCES, EADDRINUSE, EAGAIN,
		                     ECONNREFUSED, EISCONN);
	}



	/* Free addresses. */
	freeaddrinfo(res);

	return ret;
}

int socket_bind(int socket, int family, const char *addr, unsigned short port)
{
	/* Check address family. */
	int flag = 1;
	int ret = 0;
	struct sockaddr* paddr = 0;
	socklen_t addrlen = 0;
	struct sockaddr_in saddr;
#ifndef DISABLE_IPV6
	struct sockaddr_in6 saddr6;
#endif
	if (family == AF_INET) {

		/* Initialize socket address. */
		paddr = (struct sockaddr*)&saddr;
		addrlen = sizeof(saddr);
		if (getsockname(socket, paddr, &addrlen) < 0) {
			return KNOTD_EINVAL;
		}

		/* Set address and port. */
		saddr.sin_port = htons(port);
		if (inet_pton(family, addr, &saddr.sin_addr) < 0) {
			saddr.sin_addr.s_addr = INADDR_ANY;
			char buf[INET_ADDRSTRLEN];
			inet_ntop(family, &saddr.sin_addr, buf, sizeof(buf));
			log_server_error("Address '%s' is invalid, "
			                 "using '%s' instead.\n",
			                 addr, buf);

		}

	} else {

#ifdef DISABLE_IPV6
		log_server_error("ipv6 support disabled\n");
		return KNOTD_ENOIPV6;
#else
		/* Initialize socket address. */
		paddr = (struct sockaddr*)&saddr6;
		addrlen = sizeof(saddr6);
		if (getsockname(socket, paddr, &addrlen) < 0) {
			return KNOTD_EINVAL;
		}

		/* Set address and port. */
		saddr6.sin6_port = htons(port);
		if (inet_pton(family, addr, &saddr6.sin6_addr) < 0) {
			memcpy(&saddr6.sin6_addr, &in6addr_any, sizeof(in6addr_any));
			char buf[INET6_ADDRSTRLEN];
			inet_ntop(family, &saddr6.sin6_addr, buf, sizeof(buf));
			log_server_error("Address '%s' is invalid, "
			                 "using '%s' instead\n",
			                 addr, buf);

		}

		/* Make the socket IPv6 only to allow 'any' for IPv4 and IPv6 at the same time. */
#ifdef IPV6_V6ONLY
		if (family == AF_INET6) {
			/* Do not support mapping IPv4 in IPv6 sockets. */
			ret = setsockopt(socket, IPPROTO_IPV6, IPV6_V6ONLY,
			                 &flag, sizeof(flag));
			if (ret < 0) {
				return KNOTD_EINVAL;
			}
		}
#endif /* IPV6_V6ONLY */
#endif /* DISABLE_IPV6 */
	}

	/* Reuse old address if taken. */
	ret = setsockopt(socket, SOL_SOCKET, SO_REUSEADDR,
	                     &flag, sizeof(flag));
	if (ret < 0) {
		return KNOTD_EINVAL;
	}

	/* Bind to specified address. */
	int res = bind(socket, paddr, addrlen);
	if (res < 0) {
		log_server_error("Cannot bind to socket (errno %d).\n",
		                 errno);
		return knot_map_errno(EADDRINUSE, EINVAL, EACCES, ENOMEM);
	}

	return KNOTD_EOK;
}

int socket_listen(int socket, int backlog_size)
{
	int ret = listen(socket, backlog_size);
	if (ret < 0) {
		return knot_map_errno(EADDRINUSE);
	}

	return KNOTD_EOK;
}

int socket_close(int socket)
{
	if (close(socket) < 0) {
		return KNOTD_EINVAL;
	}

	return KNOTD_EOK;
}

