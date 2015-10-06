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

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <unistd.h>

#include "libknot/internal/net.h"
#include "libknot/internal/errcode.h"

/*
 * OS X doesn't support MSG_NOSIGNAL. Use SO_NOSIGPIPE socket option instead.
 */
#if defined(__APPLE__) && !defined(MSG_NOSIGNAL)
#  define MSG_NOSIGNAL 0
#  define osx_block_sigpipe(sock) sockopt_enable(sock, SOL_SOCKET, SO_NOSIGPIPE)
#else
#  define osx_block_sigpipe(sock) /* no-op */
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

	osx_block_sigpipe(sock);

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

/* -- I/O interface handling partial  -------------------------------------- */

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
	/* non-blocking operation */
	if (error == EAGAIN || error == EWOULDBLOCK) {
		return true;
	}

#ifndef __linux__
	/* FreeBSD: connection in progress */
	if (error == ENOTCONN) {
		return true;
	}
#endif

	return false;
}

/*!
 * \brief Shift processed data out of message IO vectors.
 */
static void msg_iov_shift(struct msghdr *msg, size_t done)
{
	struct iovec *iov = msg->msg_iov;
	int iovlen = msg->msg_iovlen;

	for (int i = 0; i < iovlen && done > 0; i++) {
		if (iov[i].iov_len > done) {
			iov[i].iov_base += done;
			iov[i].iov_len -= done;
			done = 0;
		} else {
			done -= iov[i].iov_len;
			msg->msg_iov += 1;
			msg->msg_iovlen -= 1;
		}
	}

	assert(done == 0);
}

/*!
 * \brief Get total size of I/O vector in a message.
 */
static size_t msg_iov_len(const struct msghdr *msg)
{
	size_t total = 0;

	for (int i = 0; i < msg->msg_iovlen; i++) {
		total += msg->msg_iov[i].iov_len;
	}

	return total;
}

/*!
 * \brief Receive a message from a socket with waiting.
 *
 * \param oneshot  If set, doesn't wait until the buffer is full.
 *
 */
static int recv_data(int fd, struct msghdr *msg, bool oneshot, struct timeval *timeout)
{
	int flags = MSG_DONTWAIT | MSG_NOSIGNAL;

	size_t rcvd = 0;
	size_t total = msg_iov_len(msg);

	while (rcvd < total) {
		/* Receive data. */
		ssize_t ret = recvmsg(fd, msg, flags);
		if (ret > 0) {
			rcvd += ret;
			/* One-shot recv() */
			if (oneshot) {
				return ret;
			} else {
				msg_iov_shift(msg, ret);
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

/*!
 * \brief Send a message on a socket with timeout.
 */
static int send_data(int sock, struct msghdr *msg, struct timeval *timeout)
{
	size_t total = msg_iov_len(msg);

	for (size_t avail = total; avail > 0; /* nop */) {
		ssize_t sent = sendmsg(sock, msg, MSG_NOSIGNAL);
		if (sent == avail) {
			break;
		}

		/* Short write. */
		if (sent > 0) {
			avail -= sent;
			msg_iov_shift(msg, sent);
			continue;
		}

		/* Handle error. */
		assert(sent == -1);
		if (errno == EINTR) {
			continue;
		} else if (io_should_wait(errno)) {
			int ret = select_write(sock, timeout);
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

/* -- generic stream and datagram I/O -------------------------------------- */

int net_send(int sock, const uint8_t *buffer, size_t size,
             const struct sockaddr_storage *addr, struct timeval *timeout)
{
	if (sock < 0 || buffer == NULL) {
		return KNOT_EINVAL;
	}

	struct iovec iov = { 0 };
	iov.iov_base = (void*)buffer;
	iov.iov_len = size;

	struct msghdr msg = { 0 };
	msg.msg_name = (void *)addr;
	msg.msg_namelen = sockaddr_len((struct sockaddr *)addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	int ret = send_data(sock, &msg, timeout);
	if (ret < 0) {
		return ret;
	} else if (ret != size) {
		return KNOT_ECONN;
	}

	return ret;
}

int net_recv(int sock, uint8_t *buffer, size_t size,
             struct sockaddr_storage *addr, struct timeval *timeout)
{
	if (sock < 0 || buffer == NULL) {
		return KNOT_EINVAL;
	}

	struct iovec iov = { 0 };
	iov.iov_base = (void*)buffer;
	iov.iov_len = size;

	struct msghdr msg = { 0 };
	msg.msg_name = (void *)addr;
	msg.msg_namelen = sizeof(*addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	return recv_data(sock, &msg, true, timeout);
}

int net_dgram_send(int sock, const uint8_t *buffer, size_t size,
                   const struct sockaddr_storage *addr)
{
	return net_send(sock, buffer, size, addr, NULL);
}

int net_dgram_recv(int sock, uint8_t *buffer, size_t size, struct timeval *timeout)
{
	return net_recv(sock, buffer, size, NULL, timeout);
}

int net_stream_send(int sock, const uint8_t *buffer, size_t size, struct timeval *timeout)
{
	return net_send(sock, buffer, size, NULL, timeout);
}

int net_stream_recv(int sock, uint8_t *buffer, size_t size, struct timeval *timeout)
{
	return net_recv(sock, buffer, size, NULL, timeout);
}

/* -- DNS specific I/O ----------------------------------------------------- */

int net_dns_tcp_send(int fd, const uint8_t *buffer, size_t size, struct timeval *timeout)
{
	if (fd < 0 || buffer == NULL || size > UINT16_MAX) {
		return KNOT_EINVAL;
	}

	struct iovec iov[2];
	uint16_t pktsize = htons(size);
	iov[0].iov_base = &pktsize;
	iov[0].iov_len = sizeof(uint16_t);
	iov[1].iov_base = (void *)buffer;
	iov[1].iov_len = size;

	struct msghdr msg = { 0 };
	msg.msg_iov = iov;
	msg.msg_iovlen = 2;

	ssize_t ret = send_data(fd, &msg, timeout);
	if (ret < 0) {
		return ret;
	}

	return size; /* Do not count the size prefix. */
}

int net_dns_tcp_recv(int fd, uint8_t *buffer, size_t size, struct timeval *timeout)
{
	if (fd < 0 || buffer == NULL) {
		return KNOT_EINVAL;
	}

	struct iovec iov = { 0 };
	struct msghdr msg = { 0 };
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	/* Receive size. */
	uint16_t pktsize = 0;
	iov.iov_base = &pktsize;
	iov.iov_len = sizeof(pktsize);
	int ret = recv_data(fd, &msg, false, timeout);
	if (ret != sizeof(pktsize)) {
		return ret;
	}

	pktsize = ntohs(pktsize);

	/* Check packet size */
	if (size < pktsize) {
		return KNOT_ENOMEM;
	}

	/* Receive payload. */
	iov.iov_base = buffer;
	iov.iov_len = size;
	return recv_data(fd, &msg, false, timeout);
}
