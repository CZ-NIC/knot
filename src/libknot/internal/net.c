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
#include <sys/uio.h>
#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif
#include <netinet/in.h>
#include <sys/stat.h>
#include <assert.h>

#include "libknot/internal/net.h"
#include "libknot/errcode.h"

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

	/* Create socket. */
	return socket_create(ss->ss_family, type, 0);
}

static void allow_freebind(int socket, int family)
{
#if defined(IP_FREEBIND) || defined(IP_BINDANY) || defined(IPV6_BINDANY)
	int flag = 1;
#endif

#ifdef IP_FREEBIND
	(void) setsockopt(socket, IPPROTO_IP, IP_FREEBIND, &flag, sizeof(flag));
#endif

#ifdef IP_BINDANY
	if (family == AF_INET) {
		(void) setsockopt(socket, IPPROTO_IP, IP_BINDANY, &flag, sizeof(flag));
	}
#endif
#ifdef IPV6_BINDANY
	if (family == AF_INET6) {
		(void) setsockopt(socket, IPPROTO_IPV6, IPV6_BINDANY, &flag, sizeof(flag));
	}
#endif
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
	sockaddr_tostr(addr_str, sizeof(addr_str), ss);

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

	/* Allow bind to non-local address. */
	allow_freebind(socket, ss->ss_family);

	/* Bind to specified address. */
	const struct sockaddr *sa = (const struct sockaddr *)ss;
	int ret = bind(socket, sa, sockaddr_len(sa));
	if (ret < 0) {
		ret = knot_map_errno(EADDRINUSE, EINVAL, EACCES, ENOMEM);
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
	const struct sockaddr *sa = (const struct sockaddr *)dst_addr;
	int ret = connect(socket, sa, sockaddr_len(sa));
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

/*! \brief Wait for data and return true if data arrived. */
static int tcp_wait_for_data(int fd, struct timeval *timeout)
{
	fd_set set;
	FD_ZERO(&set);
	FD_SET(fd, &set);
	return select(fd + 1, &set, NULL, NULL, timeout);
}

/* \brief Receive a block of data from TCP socket with wait. */
static int tcp_recv_data(int fd, uint8_t *buf, int len, struct timeval *timeout)
{
	int ret = 0;
	int rcvd = 0;
	int flags = 0;

#ifdef MSG_NOSIGNAL
	flags |= MSG_NOSIGNAL;
#endif

	while (rcvd < len) {
		/* Receive data. */
		ret = recv(fd, buf + rcvd, len - rcvd, flags);
		if (ret > 0) {
			rcvd += ret;
			continue;
		}
		/* Check for disconnected socket. */
		if (ret == 0) {
			return KNOT_ECONNREFUSED;
		}

		/* Check for no data available. */
		if (errno == EAGAIN || errno == EINTR) {
			/* Continue only if timeout didn't expire. */
			ret = tcp_wait_for_data(fd, timeout);
			if (ret) {
				continue;
			} else {
				return KNOT_ETIMEOUT;
			}
		} else {
			return KNOT_ECONN;
		}
	}

	return rcvd;
}

int udp_send_msg(int fd, const uint8_t *msg, size_t msglen,
                 const struct sockaddr *addr)
{
	socklen_t addr_len = sockaddr_len(addr);
	int ret = sendto(fd, msg, msglen, 0, addr, addr_len);
	if (ret != msglen) {
		return KNOT_ECONN;
	}

	return ret;
}

int udp_recv_msg(int fd, uint8_t *buf, size_t len, struct sockaddr *addr)
{
	socklen_t addr_len = sizeof(struct sockaddr_storage);
	int ret = recvfrom(fd, buf, len, 0, addr, &addr_len);
	if (ret < 0) {
		return KNOT_ECONN;
	}

	return ret;
}

int tcp_send_msg(int fd, const uint8_t *msg, size_t msglen)
{
	/* Create iovec for gathered write. */
	struct iovec iov[2];
	uint16_t pktsize = htons(msglen);
	iov[0].iov_base = &pktsize;
	iov[0].iov_len = sizeof(uint16_t);
	iov[1].iov_base = (void *)msg;
	iov[1].iov_len = msglen;

	/* Send. */
	int total_len = iov[0].iov_len + iov[1].iov_len;
	int sent = writev(fd, iov, 2);
	if (sent != total_len) {
		return KNOT_ECONN;
	}

	return msglen; /* Do not count the size prefix. */
}

int tcp_recv_msg(int fd, uint8_t *buf, size_t len, struct timeval *timeout)
{
	if (buf == NULL || fd < 0) {
		return KNOT_EINVAL;
	}

	/* Receive size. */
	unsigned short pktsize = 0;
	int ret = tcp_recv_data(fd, (uint8_t *)&pktsize, sizeof(pktsize), timeout);
	if (ret != sizeof(pktsize)) {
		return ret;
	}

	pktsize = ntohs(pktsize);

	// Check packet size
	if (len < pktsize) {
		return KNOT_ENOMEM;
	}

	/* Receive payload. */
	ret = tcp_recv_data(fd, buf, pktsize, timeout);
	if (ret != pktsize) {
		return ret;
	}

	return ret;
}
