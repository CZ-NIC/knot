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
#include <stdbool.h>
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

#include "libknot/internal/macros.h"
#include "libknot/internal/net.h"
#include "libknot/internal/errcode.h"

// MSG_NOSIGNAL not available on OS X
#ifndef MSG_NOSIGNAL
  #define MSG_NOSIGNAL 0
#endif

/*!
 * \brief Enable socket option.
 */
static bool sockopt_enable(int sock, int level, int optname)
{
	const int enable = 1;
	return (setsockopt(sock, level, optname, &enable, sizeof(enable)) == 0);
}

/*!
 * \brief Create a non-blocking socket.
 *
 * Prefer SOCK_NONBLOCK if available to save one fcntl() syscall.
 *
 */
static int socket_create(int family, int type, int proto)
{
#ifdef SOCK_NONBLOCK
	type |= SOCK_NONBLOCK;
#endif
	int sock = socket(family, type, proto);
	if (sock < 0) {
		return knot_map_errno();
	}

#ifndef SOCK_NONBLOCK
	if (fcntl(sock, F_SETFL, O_NONBLOCK) != 0) {
		int ret = knot_map_errno();
		close(sock);
		return ret;
	}
#endif

	return sock;
}

int net_unbound_socket(int type, const struct sockaddr_storage *ss)
{
	if (ss == NULL) {
		return KNOT_EINVAL;
	}

	/* Create socket. */
	return socket_create(ss->ss_family, type, 0);
}

struct option {
	int level;
	int name;
};

/*!
 * \brief Get setsock option for binding non-local address.
 */
static const struct option *nonlocal_option(int family)
{
	static const struct option ipv4 = {
		#if defined(IP_FREEBIND)
			IPPROTO_IP, IP_FREEBIND
		#elif defined(IP_BINDANY)
			IPPROTO_IP, IP_BINDANY
		#else
			0, 0
		#endif
	};

	static const struct option ipv6 = {
		#if defined(IP_FREEBIND)
			IPPROTO_IP, IP_FREEBIND
		#elif defined(IPV6_BINDANY)
			IPPROTO_IPV6, IPV6_BINDANY
		#else
			0, 0
		#endif

	};

	switch (family) {
	case AF_INET:  return &ipv4;
	case AF_INET6: return &ipv6;
	default:
		return NULL;
	}
}

static bool enable_nonlocal(int socket, int family)
{
	const struct option *opt = nonlocal_option(family);
	if (opt == NULL || opt->name == 0) {
		return false;
	}

	return sockopt_enable(socket, opt->level, opt->name);
}

static void unlink_unix_socket(const struct sockaddr_storage *addr)
{
	char path[SOCKADDR_STRLEN] = {0};
	sockaddr_tostr(path, sizeof(path), addr);
	unlink(path);
}

int net_bound_socket(int type, const struct sockaddr_storage *ss, enum net_flags flags)
{
	/* Create socket. */
	int sock = net_unbound_socket(type, ss);
	if (sock < 0) {
		return sock;
	}

	/* Unlink UNIX sock if exists. */
	if (ss->ss_family == AF_UNIX) {
		unlink_unix_socket(ss);
	}

	/* Reuse old address if taken. */
	sockopt_enable(sock, SOL_SOCKET, SO_REUSEADDR);

	/* Don't bind IPv4 for IPv6 any address. */
	if (ss->ss_family == AF_INET6) {
		sockopt_enable(sock, IPPROTO_IPV6, IPV6_V6ONLY);
	}

	/* Allow bind to non-local address. */
	if (flags & NET_BIND_NONLOCAL) {
		enable_nonlocal(sock, ss->ss_family);
	}

	/* Allow to bind the same address by multiple threads. */
	if (flags & NET_BIND_MULTIPLE) {
#ifdef ENABLE_REUSEPORT
		if (!sockopt_enable(sock, SOL_SOCKET, SO_REUSEPORT)) {
			int ret = knot_map_errno();
			close(sock);
			return ret;
		}
#else
		close(sock);
		return KNOT_ENOTSUP;
#endif
	}

	/* Bind to specified address. */
	const struct sockaddr *sa = (const struct sockaddr *)ss;
	int ret = bind(sock, sa, sockaddr_len(sa));
	if (ret < 0) {
		ret = knot_map_errno();
		close(sock);
		return ret;
	}

	return sock;
}

int net_connected_socket(int type, const struct sockaddr_storage *dst_addr,
                         const struct sockaddr_storage *src_addr)
{
	if (dst_addr == NULL) {
		return KNOT_EINVAL;
	}

	/* Check port. */
	if (sockaddr_port(dst_addr) == 0) {
		return KNOT_NET_EADDR;
	}

	/* Bind to specific source address - if set. */
	int sock = -1;
	if (src_addr) {
		sock = net_bound_socket(type, src_addr, 0);
	} else {
		sock = net_unbound_socket(type, dst_addr);
	}
	if (sock < 0) {
		return sock;
	}

	/* Connect to destination. */
	const struct sockaddr *sa = (const struct sockaddr *)dst_addr;
	int ret = connect(sock, sa, sockaddr_len(sa));
	if (ret != 0 && errno != EINPROGRESS) {
		ret = knot_map_errno();
		close(sock);
		return ret;
	}

	return sock;
}

bool net_is_connected(int sock)
{
	struct sockaddr_storage ss;
	socklen_t len = sizeof(ss);
	return (getpeername(sock, (struct sockaddr *)&ss, &len) == 0);
}

static int select_read(int fd, struct timeval *timeout)
{
	fd_set set;
	FD_ZERO(&set);
	FD_SET(fd, &set);
	return select(fd + 1, &set, NULL, NULL, timeout);
}

static int select_write(int fd, struct timeval *timeout)
{
	fd_set set;
	FD_ZERO(&set);
	FD_SET(fd, &set);

	return select(fd + 1, NULL, &set, NULL, timeout);
}

/*!
 * \brief Check if we should wait for I/O readiness.
 *
 * \param error  'errno' set by the failed send() or recv().
 */
static bool io_should_wait(int error)
{
	switch (error) {
	case EAGAIN:       // connection in progress (Linux) or data not ready
#if EAGAIN != EWOULDBLOCK
	case EWOULDBLOCK:
#endif
	case ENOTCONN:     // connection in progress (BSD)
		return true;
	default:
		return false;
	}
}

/* \brief Receive a block of data from TCP socket with wait. */
static int recv_data(int fd, uint8_t *buf, int len, bool oneshot, struct timeval *timeout)
{
	int ret = 0;
	int rcvd = 0;
	int flags = MSG_DONTWAIT | MSG_NOSIGNAL;

	while (rcvd < len) {
		/* Receive data. */
		ret = recv(fd, buf + rcvd, len - rcvd, flags);
		if (ret > 0) {
			rcvd += ret;
			/* One-shot recv() */
			if (oneshot) {
				return ret;
			} else {
				continue;
			}
		}

		/* Check for disconnected socket. */
		if (ret == 0) {
			return KNOT_ECONNREFUSED;
		}

		/* Handle error. */
		assert(ret == -1);
		if (errno == EINTR) {
			continue;
		} else if (io_should_wait(errno)) {
			ret = select_read(fd, timeout);
			if (ret > 0) {
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

int udp_send_msg(int fd, const uint8_t *msg, size_t msglen, const struct sockaddr *addr)
{
	socklen_t addr_len = sockaddr_len(addr);
	int ret = sendto(fd, msg, msglen, MSG_NOSIGNAL, addr, addr_len);
	if (ret != msglen) {
		return KNOT_ECONN;
	}

	return ret;
}

int udp_recv_msg(int fd, uint8_t *buf, size_t len, struct timeval *timeout)
{
	return recv_data(fd, buf, len, true, timeout);
}

/*!
 * \brief Shift processed data out of iovec structure.
 */
static void iovec_shift(struct iovec **iov_ptr, int *iovcnt_ptr, size_t done)
{
	struct iovec *iov = *iov_ptr;
	int iovcnt = *iovcnt_ptr;

	for (int i = 0; i < iovcnt && done > 0; i++) {
		if (iov[i].iov_len > done) {
			iov[i].iov_base += done;
			iov[i].iov_len -= done;
			done = 0;
		} else {
			done -= iov[i].iov_len;
			*iov_ptr += 1;
			*iovcnt_ptr -= 1;
		}
	}

	assert(done == 0);
}

/*!
 * \brief Send out TCP data with timeout in case the output buffer is full.
 */
static int send_data(int fd, struct iovec iov[], int iovcnt, struct timeval *timeout)
{
	size_t total = 0;
	for (int i = 0; i < iovcnt; i++) {
		total += iov[i].iov_len;
	}

	for (size_t avail = total; avail > 0; /* nop */) {
		ssize_t sent = writev(fd, iov, iovcnt);
		if (sent == avail) {
			break;
		}

		/* Short write. */
		if (sent > 0) {
			avail -= sent;
			iovec_shift(&iov, &iovcnt, sent);
			continue;
		}

		/* Handle error. */
		assert(sent == -1);
		if (errno == EINTR) {
			continue;
		} else if (io_should_wait(errno)) {
			int ret = select_write(fd, timeout);
			if (ret > 0) {
				continue;
			} else if (ret == 0) {
				return KNOT_ETIMEOUT;
			}
		} else {
			return KNOT_ECONN;
		}
	}

	return total;
}

int tcp_send_msg(int fd, const uint8_t *msg, size_t msglen, struct timeval *timeout)
{
	if (msglen > UINT16_MAX) {
		return KNOT_EINVAL;
	}

	/* Create iovec for gathered write. */
	struct iovec iov[2];
	uint16_t pktsize = htons(msglen);
	iov[0].iov_base = &pktsize;
	iov[0].iov_len = sizeof(uint16_t);
	iov[1].iov_base = (void *)msg;
	iov[1].iov_len = msglen;

	/* Send. */
	ssize_t ret = send_data(fd, iov, 2, timeout);
	if (ret < 0) {
		return ret;
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
	int ret = recv_data(fd, (uint8_t *)&pktsize, sizeof(pktsize), false, timeout);
	if (ret != sizeof(pktsize)) {
		return ret;
	}

	pktsize = ntohs(pktsize);

	// Check packet size
	if (len < pktsize) {
		return KNOT_ENOMEM;
	}

	/* Receive payload. */
	return recv_data(fd, buf, pktsize, false, timeout);
}
