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

#include "knot/server/net.h"
#include "knot/knot.h"

static int socket_create(int family, int type, int proto)
{
	/* Create socket. */
	int ret = socket(family, type, proto);
	if (ret < 0) {
		return knot_map_errno(EACCES, EINVAL, ENOMEM);
	}

	return ret;
}

int net_unbound_socket(int type, const struct sockaddr_storage *ss)
{
	if (ss == NULL) {
		return KNOT_EINVAL;
	}

	/* Convert to string address format. */
	char addr_str[SOCKADDR_STRLEN] = {0};
	sockaddr_tostr(ss, addr_str, sizeof(addr_str));

	/* Create socket. */
	int socket = socket_create(ss->ss_family, type, 0);
	if (socket < 0) {
		log_error("failed to create socket '%s' (%s)",
		          addr_str, knot_strerror(socket));
		return socket;
	}

	return socket;
}

int net_bound_socket(int type, const struct sockaddr_storage *ss)
{
	/* Create socket. */
	int socket = net_unbound_socket(type, ss);
	if (socket < 0) {
		return socket;
	}

	/* Convert to string address format. */
	char addr_str[SOCKADDR_STRLEN] = {0};
	sockaddr_tostr(ss, addr_str, sizeof(addr_str));

	/* Reuse old address if taken. */
	int flag = 1;
	(void) setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));

	/* Unlink UNIX socket if exists. */
	if (ss->ss_family == AF_UNIX) {
		unlink(addr_str);
	}

	/* Make the socket IPv6 only to allow 'any' for IPv4 and IPv6 at the same time. */
	if (ss->ss_family == AF_INET6) {
		(void) setsockopt(socket, IPPROTO_IPV6, IPV6_V6ONLY,
		                  &flag, sizeof(flag));
	}

	/* Bind to specified address. */
	int ret = bind(socket, (const struct sockaddr *)ss, sockaddr_len(ss));
	if (ret < 0) {
		ret = knot_map_errno(EADDRINUSE, EINVAL, EACCES, ENOMEM);
		log_error("cannot bind address '%s' (%s)",
		          addr_str, knot_strerror(ret));
		close(socket);
		return ret;
	}

	return socket;
}

int net_connected_socket(int type, const struct sockaddr_storage *dst_addr,
                         const struct sockaddr_storage *src_addr, unsigned flags)
{
	if (dst_addr == NULL) {
		return KNOT_EINVAL;
	}

	int socket = -1;

	/* Check port. */
	if (sockaddr_port(dst_addr) == 0) {
		return KNOT_ECONN;
	}

	/* Bind to specific source address - if set. */
	if (src_addr != NULL && src_addr->ss_family != AF_UNSPEC) {
		socket = net_bound_socket(type, src_addr);
	} else {
		socket = net_unbound_socket(type, dst_addr);
	}
	if (socket < 0) {
		return socket;
	}

	/* Set socket flags. */
	if (fcntl(socket, F_SETFL, flags) < 0)
		;

	/* Connect to destination. */
	int ret = connect(socket, (const struct sockaddr *)dst_addr,
	                  sockaddr_len(dst_addr));
	if (ret != 0 && errno != EINPROGRESS) {
		close(socket);
		return knot_map_errno(EACCES, EADDRINUSE, EAGAIN,
		                      ECONNREFUSED, EISCONN);
	}

	return socket;
}

int net_is_connected(int fd)
{
	struct sockaddr_storage ss;
	socklen_t len = sizeof(ss);
	return getpeername(fd, (struct sockaddr *)&ss, &len) == 0;
}
